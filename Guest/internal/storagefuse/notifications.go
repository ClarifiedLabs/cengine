package storagefuse

import (
	"context"
	"errors"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type kernelNotifier interface {
	InodeNotify(uint64, int64, int64) fuse.Status
	EntryNotify(uint64, string) fuse.Status
}

// Called only by storageclient's separate, serial, bounded event worker. It must
// not enqueue onto an RPC callback worker (that can deadlock kernel writeback).
// Terminal ownership must abort the exact device to unblock a notification write;
// go-fuse's notification API has no context-aware write. Never call Client.Close
// from here. IDs are already recipient-local, not event object IDs or wire nodes.
func invalidate(ctx context.Context, k kernelNotifier, n c.Notification) error {
	if err := n.Event.Validate(); err != nil {
		return err
	}
	send := func(node uint64, off, length int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		s := k.InodeNotify(node, off, length)
		if s != 0 && s != fuse.ENOENT {
			return errors.New("storagefuse: inode notification failed")
		}
		return nil
	}
	switch n.Event.Kind {
	case w.InvalidateAttr:
		for _, id := range n.Nodes {
			if err := send(uint64(id), -1, 0); err != nil {
				return err
			}
		}
	case w.InvalidateData:
		for _, id := range n.Nodes {
			if err := send(uint64(id), int64(n.Event.Offset), int64(n.Event.Length)); err != nil {
				return err
			}
		}
	case w.InvalidateEntry:
		for _, id := range n.Parents {
			if err := ctx.Err(); err != nil {
				return err
			}
			s := k.EntryNotify(uint64(id), string(n.Event.Name))
			if s != 0 && s != fuse.ENOENT {
				return errors.New("storagefuse: entry notification failed")
			}
		}
	default:
		return errTranslation
	}
	return ctx.Err()
}

// The native owner starts exactly one watcher before INIT, after pinning the
// exact connection's abort file. No generic/global unmount is used.
func (f *rawFS) watchTerminal(terminal <-chan struct{}, reason func() error) {
	<-terminal
	f.stop(reason())
}

// Target of the controlled fork's synchronous delivery hook, including discarded
// live node/FH grants. Never issue synthetic RELEASE/FORGET or reuse IDs here.
func (f *rawFS) deliveryFailed(_ uint64, err error) { f.stop(err) }
