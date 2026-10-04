package storagecontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

func TestLifecycleTLSSuccessorReservedAdmission(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	s, err := NewLifecycleServer(f.authority, f.sc)
	must(t, err)
	current, currentWorker, currentRaw, cancelCurrent := connectObservedLifecycle(t, f, s)
	if !nextControlDeadline(t, currentRaw).IsZero() {
		t.Fatal("idle deadline")
	}
	// A second authenticated current owner must not retain the reserved slot.
	raw, rejected := lifecycleServe(t, s)
	if client, err := NewLifecycleClient(context.Background(), raw, f.cc); err == nil {
		client.Close()
		t.Fatal("current owner consumed successor reservation")
	}
	if err := rejected.wait(t); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	lifecycleIdleMemory(t, s, 1)
	if len(s.currentSlots) != 1 {
		t.Fatal("current quota changed on rejection")
	}

	nextFixture := *f
	nextFixture.cc = f.successor()
	next, nextWorker, nextRaw, cancelNext := connectObservedLifecycle(t, &nextFixture, s)
	if !nextControlDeadline(t, nextRaw).IsZero() {
		t.Fatal("successor idle deadline")
	}
	// The reservation is inside, not in addition to, the two-slot total cap.
	raw, rejected = lifecycleServe(t, s)
	if client, err := NewLifecycleClient(context.Background(), raw, nextFixture.cc); err == nil {
		client.Close()
		t.Fatal("total connection cap exceeded")
	}
	if err := rejected.wait(t); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	_, err = next.Takeover(context.Background(), f.takeover)
	must(t, err)
	_, err = next.Result(context.Background(), f.takeover.Grant, make([]byte, 32))
	must(t, err)
	_, err = current.Result(context.Background(), f.initial.Grant, make([]byte, 32))
	remote(t, err, Unauthorized)
	cancelCurrent()
	currentWorker.wait(t)
	if len(s.currentSlots) != 0 {
		t.Fatal("cancellation retained current quota")
	}
	// The old key is now refused at Hello, not merely on its first operation.
	raw, rejected = lifecycleServe(t, s)
	if client, err := NewLifecycleClient(context.Background(), raw, f.cc); err == nil {
		client.Close()
		t.Fatal("stale current Hello accepted")
	}
	if err := rejected.wait(t); !errors.Is(err, a.ErrUnauthorized) {
		t.Fatal(err)
	}
	if len(s.currentSlots) != 0 {
		t.Fatal("stale Hello leaked current quota")
	}
	cancelNext()
	nextWorker.wait(t)
	lifecycleIdleMemory(t, s, 0)
	// Exact promoted successor is admitted through lifecycle-result auth.
	promoted := lifecycleConnect(t, s, nextFixture.cc)
	_, err = promoted.Result(context.Background(), f.takeover.Grant, make([]byte, 32))
	must(t, err)
}

func TestLifecycleTLSStaleSuccessorCannotFallBackToPending(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	original, err := NewLifecycleServer(f.authority, f.sc)
	must(t, err)
	next := lifecycleConnect(t, original, f.successor())
	_, err = next.Takeover(context.Background(), f.takeover)
	must(t, err)
	next.Close()

	// Another explicitly reconciled server advances the actual same authority.
	// The original server's now-stale successor must not regain pending status.
	thirdKey, err := p.NewControllerKey()
	must(t, err)
	thirdGrant := lifecycleSign(t, f.bootstrap, a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: f.initial.Grant.Identity, Serial: f.takeover.Grant.Serial + 1, ExpectedEpoch: 2, NewKey: a.Fingerprint(pkiPin(t, thirdKey).String())})
	cfg := f.sc
	cfg.CurrentGrant, cfg.ControllerKey = f.takeover.Grant, f.sc.SuccessorKey
	cfg.SuccessorGrant, cfg.SuccessorKey = thirdGrant.Grant, pkiPin(t, thirdKey)
	cfg.RetireGrant = a.LifecycleGrant{}
	reconciled, err := NewLifecycleServer(f.authority, cfg)
	must(t, err)
	thirdConfig := f.cc
	thirdConfig.Hello.ControllerEpoch = 3
	binding, err := p.NewControllerBinding(p.StoreID(thirdConfig.Hello.Identity.Store), 3)
	must(t, err)
	thirdConfig.Identity = f.issue(thirdKey, binding)
	third := lifecycleConnect(t, reconciled, thirdConfig)
	_, err = third.Takeover(context.Background(), thirdGrant)
	must(t, err)

	raw, rejected := lifecycleServe(t, original)
	if stale, err := NewLifecycleClient(context.Background(), raw, f.successor()); err == nil {
		stale.Close()
		t.Fatal("stale successor fell back to possession-only pending admission")
	}
	if err := rejected.wait(t); !errors.Is(err, a.ErrUnauthorized) {
		t.Fatal(err)
	}
}

// Cancels only once the test TLS server is sending its final Hello reply.
// Buffered ciphertext may still decode successfully even after raw is closed;
// publication must nevertheless lose when handshake cancellation has started.
type lifecycleCancelOnReplyConn struct {
	net.Conn
	armed  atomic.Bool
	cancel context.CancelFunc
}

func (c *lifecycleCancelOnReplyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.armed.CompareAndSwap(true, false) {
		c.cancel()
	}
	return n, err
}

func TestLifecycleTLSClientHandshakeCancellationHandoff(t *testing.T) {
	t.Run("final-reply-canceled", func(t *testing.T) {
		f := newLifecycleTLSFixture(t)
		left, right := tcpPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		raw := &lifecycleCancelOnReplyConn{Conn: right, cancel: cancel}
		worker := &testWorker{done: make(chan struct{})}
		go func() {
			defer close(worker.done)
			defer left.Close()
			cfg, err := p.ServerTLSConfig(f.sc.Identity, f.sc.ClientRoot)
			if err != nil {
				worker.err = err
				return
			}
			conn := tls.Server(left, cfg)
			if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				worker.err = err
				return
			}
			if err = conn.HandshakeContext(context.Background()); err != nil {
				worker.err = err
				return
			}
			var hello LifecycleHello
			if err = readFrame(conn, &hello, 4096, &budget{}); err != nil {
				worker.err = err
				return
			}
			var frame bytes.Buffer
			if err = writeFrame(&frame, hello, 4096, &budget{}); err != nil {
				worker.err = err
				return
			}
			raw.armed.Store(true)
			worker.err = writeFull(conn, frame.Bytes())
		}()
		t.Cleanup(func() { raw.Close(); worker.wait(t) })
		client, err := NewLifecycleClient(ctx, raw, f.cc)
		if err == nil || client != nil {
			if client != nil {
				client.Close()
			}
			t.Fatal("constructor published a client after final-reply cancellation", err)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("final-reply cancellation was not exercised")
		}
		worker.wait(t)
	})
	t.Run("successful-handoff-stops-callback", func(t *testing.T) {
		f := newLifecycleTLSFixture(t)
		s, err := NewLifecycleServer(f.authority, f.sc)
		must(t, err)
		raw, _ := lifecycleServe(t, s)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client, err := NewLifecycleClient(ctx, raw, f.cc)
		must(t, err)
		defer client.Close()
		cancel()
		_, err = client.Result(context.Background(), f.initial.Grant, make([]byte, 32))
		must(t, err)
		select {
		case <-client.closed:
			t.Fatal("completed handshake retained its cancellation callback")
		default:
		}
	})
}
