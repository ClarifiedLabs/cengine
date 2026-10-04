package storageclient

import (
	"context"
	"errors"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// OriginalConsumerPositiveRoot is an exclusive-profile, fixed root metadata RPC.
// It uses the already-issued root grant, not caller/PID credentials or a second
// connection. The private metadata-only snapshot cannot escape this fixed call;
// it does not pretend to be a captured kernel request or authorize mutation.
func (c *Client) OriginalConsumerPositiveRoot(ctx context.Context, expected a.DataHello) error {
	return c.originalConsumerPositiveRoot(ctx, expected, nil)
}

// OriginalConsumerRootRequest identifies this client's actual serialized fixed
// request. It is not server admission evidence: callers must independently match
// the sequence and node to the passive service recorder's real Admit result.
type OriginalConsumerRootRequest struct {
	Node            w.NodeID
	RequestSequence uint64
}

// OriginalConsumerRootAttempt uses the still-live original client and its root
// grant. A transport failure is returned unchanged, never labeled blocked. In
// particular, local close, cancellation and timeout cannot certify retirement.
func (c *Client) OriginalConsumerRootAttempt(ctx context.Context, expected a.DataHello) (OriginalConsumerRootRequest, error) {
	return c.originalConsumerRoot(ctx, expected, nil)
}

// beforeValidation is a package-private test seam after the actual RPC. The
// public operation never accepts a callback or caller-selected request/authority.
func (c *Client) originalConsumerPositiveRoot(ctx context.Context, expected a.DataHello, beforeValidation func()) error {
	_, err := c.originalConsumerRoot(ctx, expected, beforeValidation)
	return err
}

func (c *Client) originalConsumerRoot(ctx context.Context, expected a.DataHello, beforeValidation func()) (OriginalConsumerRootRequest, error) {
	var request OriginalConsumerRootRequest
	if ctx == nil || c == nil || preparecompat.CurrentProfile() != preparecompat.FullProfile || c.authority != expected || expected.Binding.Role != a.RuntimeRole || c.Err() != nil || c.root.Node == 0 {
		return request, ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return request, err
	}
	request.Node = c.root.Node
	// Do cannot cancel an admitted request. On observation expiry, fail this
	// exact client through its ordinary terminal path and join its workers.
	// No detached RPC, successful drain, or timeout-as-evidence is produced.
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.fail(ctx.Err()); close(canceled) })
	result, err := c.do(Snapshot{owner: c, valid: true}, w.NodeMetadataAuth, w.GetAttrRequest{Node: c.root.Node}, &request.RequestSequence)
	if beforeValidation != nil {
		beforeValidation()
	}
	if err == nil {
		attr, ok := result.Reply.Body.(w.GetAttrReply)
		if !ok || result.Reply.Sequence == 0 || result.Reply.Op != w.OpGetAttr || result.Reply.Errno != 0 || attr.Attr.Mode&0170000 != 0040000 || attr.Attr.Ino != c.root.Attr.Ino || c.Err() != nil {
			err = ErrProtocol
		}
	}
	// Keep cancellation armed through validation. A successful stop is the
	// operation's linearization point; cancellation after it cannot invalidate
	// this completed observation. If cancellation won, always join the callback
	// and exact client workers, even when Do already returned a successful reply.
	if !stop() {
		<-canceled
		<-c.joined
		return OriginalConsumerRootRequest{}, ctx.Err()
	}
	return request, err
}

// OriginalConsumerClosedRoot observes only this exact, already-terminal client.
// It cannot close, reconnect, manufacture credentials or enqueue an active RPC.
// ErrClosed means a real Do was locally rejected after all transport workers
// joined; it is NOT remote authentication/admission denial or a drain receipt.
func (c *Client) OriginalConsumerClosedRoot(ctx context.Context, expected a.DataHello) error {
	if c == nil || preparecompat.CurrentProfile() != preparecompat.FullProfile || c.authority != expected || !errors.Is(c.Err(), ErrClosed) {
		return ErrProtocol
	}
	select {
	case <-c.joined:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// No valid credential snapshot is fabricated. Terminal admission is sticky
	// and precedes credentials in Do; a future change that admits this request
	// must fail this observation rather than gaining any authority.
	result, err := c.Do(Snapshot{}, w.NodeMetadataAuth, w.GetAttrRequest{Node: c.root.Node})
	if !errors.Is(err, ErrClosed) || result.Reply.Sequence != 0 || result.Reply.Body != nil || result.Node != 0 || result.Handle != 0 {
		return ErrProtocol
	}
	return ErrClosed
}
