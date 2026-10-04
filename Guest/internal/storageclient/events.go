package storageclient

import (
	"bytes"
	"fmt"
	"math"

	w "dev.cengine/guest/internal/storagewire"
)

// One bounded queue cell may cover multiple consecutive inode invalidations.
// count retains every accepted event until the covering kernel callback returns.
// No event may merge with a callback that has started, or across another object,
// namespace event, or different data range. No grants or RPCs are coalesced.
type eventWork struct {
	event w.Event
	count int
}

// Inode data invalidation also invalidates attributes (FUSE_NOTIFY_INVAL_INODE).
// This only combines already-validated events for the exact same object/range;
// it never turns a namespace notification into an inode notification.
func coalesceEvent(earlier, later w.Event) (w.Event, bool) {
	inode := func(k w.EventKind) bool { return k == w.InvalidateAttr || k == w.InvalidateData }
	if !inode(earlier.Kind) || !inode(later.Kind) || earlier.Volume != later.Volume || earlier.Object != later.Object ||
		earlier.Parent != later.Parent || !bytes.Equal(earlier.Name, later.Name) ||
		(earlier.Kind == w.InvalidateData && later.Kind == w.InvalidateData && (earlier.Offset != later.Offset || earlier.Length != later.Length)) {
		return w.Event{}, false
	}
	if earlier.Kind == w.InvalidateData {
		earlier.EventSequence = later.EventSequence
		return earlier, true
	}
	return later, true
}

// Called under mu after stream validation and before shutdown can commit. Keep
// the reader nonblocking: kernel invalidation may itself need a later RPC reply.
func (c *Client) enqueueEvent(event w.Event) error {
	if c.pendingEvents == math.MaxInt {
		return fmt.Errorf("%w: invalidation count", ErrCapacity)
	}
	if tail := c.eventTail; tail != nil {
		if merged, ok := coalesceEvent(tail.event, event); ok {
			tail.event = merged
			tail.count++ // count <= pendingEvents < MaxInt
			c.pendingEvents++
			return nil
		}
	}
	cell := &eventWork{event: event, count: 1}
	select {
	case c.events <- cell:
		c.eventTail = cell
		c.pendingEvents++
		return nil
	default:
		return fmt.Errorf("%w: invalidation queue", ErrCapacity)
	}
}
