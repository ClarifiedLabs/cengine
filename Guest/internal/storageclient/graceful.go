package storageclient

import (
	"context"
	"errors"
	"fmt"
)

// CloseGracefully seals local admission and joins accepted work. It may ONLY be
// called after successful native syncfs, normal kernel unmount, and the complete
// FUSE Serve/callback join. There can be no future kernel callbacks, including
// credential captures. It never synthesizes RELEASE/FORGET, credentials, or a
// remote drain request.
//
// Nil means positively completed local RPCs (including cleanup acknowledgements),
// reply application and admitted invalidations, with no remaining handles.
// Residual lookup references/grants may remain inert after kernel quiescence:
// normal fuse.managed-v3 (not fuseblk) does not emit DESTROY, and final inode
// teardown does not promise FORGET delivery before disconnect. Their nodes, refs,
// owned counts and pins remain untouched; nil does NOT release remote grants.
// Already queued FORGETs must still receive and apply their acknowledgements.
// Completed negatives LOOKUP/ENOENT and GETXATTR/ENODATA permit nil. Xattr
// ERANGE requires a successful data retry of the same probe and caller. Other
// completed errno and failed credential captures prevent nil, without changing
// Do's normal errno delivery. This is NOT remote authority drain proof.
//
// Context cancellation aborts the transport and joins the cancellation-aware
// workers. Invalidate must honor cancellation and must not call either close
// method. Native Capture ioctls cannot be canceled; the caller's callback-join
// prerequisite ensures none remain. Repeated graceful closes share the result;
// concurrent Close or Abort always records failure, never intentional success.
func (c *Client) CloseGracefully(ctx context.Context) error {
	c.mu.Lock()
	c.sealed = true
	c.broadcastLocked()
	for c.err == nil && !c.stopping {
		if err := ctx.Err(); err != nil {
			c.failLocked(err)
			break
		}
		if len(c.queue) == 0 && !c.processing && !c.replyPending && c.outstanding == nil && c.pendingEvents == 0 && c.captures == 0 {
			if err := c.completionError(); err != nil {
				c.failLocked(err)
			} else if len(c.handles) != 0 || len(c.wireHandles) != 0 {
				c.failLocked(fmt.Errorf("%w: live handles", ErrIncomplete))
			} else {
				c.stopping = true
				c.cancel()
				c.broadcastLocked()
			}
			break
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		c.mu.Lock()
	}
	c.mu.Unlock()
	select {
	case <-c.joined:
	case <-ctx.Done():
		c.fail(ctx.Err())
		<-c.joined
	}
	// A concurrent Abort/Close or an unexpected read failure during the join
	// wins over the intentional-close marker.
	return c.Err()
}

func (c *Client) admissionLocked() error {
	if c.err != nil {
		return c.err
	}
	if c.sealed {
		return ErrClosed
	}
	return nil
}

func (c *Client) broadcastLocked() {
	if c.changed != nil {
		close(c.changed)
	}
	c.changed = make(chan struct{})
}

func (c *Client) capture(query credentialQuery, fd int, unique uint64) (s Snapshot, err error) {
	c.mu.Lock()
	if err := c.admissionLocked(); err != nil {
		c.mu.Unlock()
		return Snapshot{}, err
	}
	select {
	case c.credentialSlots <- struct{}{}:
		c.captures++
	default:
		c.mu.Unlock()
		return Snapshot{}, ErrCapacity
	}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		<-c.credentialSlots
		c.captures--
		if err != nil {
			if c.completionErr == nil {
				c.completionErr = errors.Join(ErrIncomplete, err)
			}
			if c.err != nil {
				c.failLocked(err)
			}
		}
		c.broadcastLocked()
		c.mu.Unlock()
	}()
	s, err = capture(query, fd, unique, c.supportedCaps)
	if err == nil {
		s.owner = c
	}
	return s, err
}
