package storageclient

import (
	"context"
	"crypto/tls"
	w "dev.cengine/guest/internal/storagewire"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"dev.cengine/guest/internal/preparecompat"
)

func TestOriginalConsumerClosedRootRejectsUnjoinedAndInert(t *testing.T) {
	c := fixture(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.OriginalConsumerClosedRoot(ctx, c.Authority()); !errors.Is(err, ErrProtocol) {
		t.Fatal("live client accepted", err)
	}
	_ = c.Close()
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		if err := c.OriginalConsumerClosedRoot(context.Background(), c.Authority()); err != ErrProtocol {
			t.Fatal("inert profile produced original observation", err)
		}
		return
	}
	if err := c.OriginalConsumerClosedRoot(ctx, c.Authority()); err != context.Canceled {
		t.Fatal("canceled call accepted", err)
	}
	if err := c.OriginalConsumerClosedRoot(context.Background(), c.Authority()); err != ErrClosed {
		t.Fatal("joined original client not rejected", err)
	}
	// Terminal notification alone is insufficient: no synthetic Do result is
	// emitted while the native owner still has transport callbacks to join.
	unjoined := &Client{authority: c.authority, err: ErrClosed, joined: make(chan struct{})}
	if err := unjoined.OriginalConsumerClosedRoot(ctx, c.Authority()); err != context.Canceled {
		t.Fatal("unjoined client yielded evidence", err)
	}
}

func TestOriginalConsumerPositiveRootActualRPC(t *testing.T) {
	var calls atomic.Uint32
	c := fixture(t, nil, func(conn *tls.Conn) {
		rpcServer(conn, func(req w.Request) w.Reply {
			body, ok := req.Body.(w.GetAttrRequest)
			if !ok || body.Node != 99 || body.Handle != nil || req.Auth.Kind != w.NodeMetadataAuth || req.Auth.Caller != nil {
				t.Error("not fixed granted-root metadata operation")
			}
			calls.Add(1)
			return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
		})
	})
	ctx := context.Background()
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		if err := c.OriginalConsumerPositiveRoot(ctx, c.Authority()); err != ErrProtocol || calls.Load() != 0 {
			t.Fatal("inert positive", err)
		}
		return
	}
	bad := c.Authority()
	bad.Binding.Volume = testID('8')
	if err := c.OriginalConsumerPositiveRoot(ctx, bad); err != ErrProtocol || calls.Load() != 0 {
		t.Fatal("wrong scope admitted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.OriginalConsumerPositiveRoot(canceled, c.Authority()); err != context.Canceled || calls.Load() != 0 {
		t.Fatal("canceled positive", err)
	}
	request, err := c.OriginalConsumerRootAttempt(ctx, c.Authority())
	if err != nil || calls.Load() != 1 || request.Node != 99 || request.RequestSequence != 1 {
		t.Fatal("no actual positive RPC and serializer sequence", request, err)
	}
	_ = c.Close()
	if err := c.OriginalConsumerClosedRoot(ctx, c.Authority()); err != ErrClosed || calls.Load() != 1 {
		t.Fatal("negative replaced original client", err)
	}
	if err := c.OriginalConsumerPositiveRoot(ctx, c.Authority()); err != ErrProtocol {
		t.Fatal("closed positive", err)
	}
}
func TestOriginalConsumerRootAttemptTransportLossDoesNotClaimDenial(t *testing.T) {
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		t.Skip("exclusive full profile")
	}
	c := fixture(t, nil, func(conn *tls.Conn) {
		var req w.Request
		if err := w.ReadFrame(conn, &req); err != nil {
			t.Error(err)
		}
		// No authority exists in this client fixture. EOF cannot certify blocked.
		_ = conn.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := c.OriginalConsumerRootAttempt(ctx, c.Authority())
	if err == nil || ctx.Err() != nil || request.Node != 99 || request.RequestSequence != 1 {
		t.Fatal("missing actual failed attempt", request, err)
	}
	if request, err = c.OriginalConsumerRootAttempt(ctx, c.Authority()); request != (OriginalConsumerRootRequest{}) || err != ErrProtocol {
		t.Fatal("local preclosed client yielded request", request, err)
	}
}

func TestOriginalConsumerRootAttemptCancellationDiscardsRequest(t *testing.T) {
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		t.Skip("exclusive full profile")
	}
	c := fixture(t, nil, func(conn *tls.Conn) {
		rpcServer(conn, func(req w.Request) w.Reply {
			return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := c.originalConsumerRoot(ctx, c.Authority(), cancel)
	if request != (OriginalConsumerRootRequest{}) || err != context.Canceled {
		t.Fatal("cancellation retained request evidence", request, err)
	}
	select {
	case <-c.joined:
	default:
		t.Fatal("cancellation did not join exact workers")
	}
}

func TestOriginalConsumerPositiveRootRefusesRemoteErrno(t *testing.T) {
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		t.Skip("exclusive full profile")
	}
	c := fixture(t, nil, func(conn *tls.Conn) { rpcServer(conn, func(req w.Request) w.Reply { return w.Reply{Errno: 13} }) })
	if err := c.OriginalConsumerPositiveRoot(context.Background(), c.Authority()); err == nil {
		t.Fatal("errno accepted as positive")
	}
}

func TestOriginalConsumerPositiveRootCancellationAfterReplyBeforeValidationJoins(t *testing.T) {
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		t.Skip("exclusive full profile")
	}
	var calls atomic.Uint32
	c := fixture(t, nil, func(conn *tls.Conn) {
		rpcServer(conn, func(req w.Request) w.Reply {
			body, ok := req.Body.(w.GetAttrRequest)
			if !ok || body.Node != 99 || body.Handle != nil || req.Auth.Kind != w.NodeMetadataAuth {
				t.Error("not original granted-root GETATTR")
			}
			calls.Add(1)
			return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed, validate := make(chan struct{}), make(chan struct{})
	defer close(validate)
	result := make(chan error, 1)
	go func() {
		result <- c.originalConsumerPositiveRoot(ctx, c.Authority(), func() {
			close(completed) // Do has received and applied the actual peer reply.
			<-validate
		})
	}()
	select {
	case <-completed:
	case <-time.After(3 * time.Second):
		t.Fatal("GETATTR did not complete before validation")
	}
	if calls.Load() != 1 || c.Err() != nil {
		t.Fatal("not one successful live original DATA RPC")
	}
	cancel() // Deterministically after Do, while validation is still pending.
	validate <- struct{}{}
	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatal("post-reply cancellation published positive/other result", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("post-reply cancellation did not return")
	}
	if !errors.Is(c.Err(), context.Canceled) {
		t.Fatal("post-reply cancellation did not fail original client", c.Err())
	}
	select {
	case <-c.joined:
	default:
		t.Fatal("post-reply cancellation returned without worker join")
	}
}

func TestOriginalConsumerPositiveRootCancellationAfterDispatchJoins(t *testing.T) {
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		t.Skip("exclusive full profile")
	}
	received := make(chan struct{})
	c := fixture(t, func(cfg *Config) { cfg.Timeout = 30 * time.Second }, func(conn *tls.Conn) {
		var req w.Request
		if err := w.ReadFrame(conn, &req); err != nil {
			t.Error(err)
			return
		}
		if req.Body.Operation() != w.OpGetAttr {
			t.Error("not GETATTR")
		}
		close(received)
		var next w.Request
		if err := w.ReadFrame(conn, &next); err == nil {
			t.Error("canceled RPC admitted more work")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.OriginalConsumerPositiveRoot(ctx, c.Authority()) }()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("request not dispatched")
	}
	cancel()
	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatal("cancellation became evidence", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waited for transport timeout")
	}
	select {
	case <-c.joined:
	default:
		t.Fatal("returned before actual worker join")
	}
}
