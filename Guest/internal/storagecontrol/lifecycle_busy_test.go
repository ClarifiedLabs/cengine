package storagecontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

// Exercise real DATA admission and durability, not a synthetic authority BUSY.
func lifecycleDataGuard(t *testing.T, f *fixture, mutates bool) *a.Guard {
	t.Helper()
	c := f.client()
	defer c.Close()
	v := id(t)
	call(t, c, Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: v, Name: "busy-data"}})
	b, k := f.binding(v, "")
	call(t, c, Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: b}})
	g, err := f.authority.Admit(f.data(k, b), v, mutates)
	must(t, err)
	t.Cleanup(g.Release)
	return g
}

// The test-only observer runs the production TLS policy and operation dispatcher.
// Observing a response provides a deterministic rendezvous without adding a hook
// to either the client or authority. Every attempt must retain the exact grant.
func lifecycleObservedClient(t *testing.T, f *lifecycleFixture, timeout time.Duration, observe func(lifecycleResponse) bool) (*LifecycleClient, *atomic.Int32) {
	t.Helper()
	s, err := NewLifecycleServer(f.authority, f.sc)
	must(t, err)
	left, right := tcpPair(t)
	worker := &testWorker{done: make(chan struct{})}
	attempts := &atomic.Int32{}
	go func() {
		defer close(worker.done)
		defer left.Close()
		worker.err = func() error {
			conn := tls.Server(left, s.tls)
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return err
			}
			if err := conn.HandshakeContext(context.Background()); err != nil {
				return err
			}
			var h LifecycleHello
			if err := readFrame(conn, &h, 4096, &budget{}); err != nil {
				return err
			}
			if err := s.verify(conn, h); err != nil {
				return err
			}
			if err := s.authenticateHello(context.Background(), conn, h); err != nil {
				return err
			}
			if err := writeFrame(conn, h, 4096, &budget{}); err != nil {
				return err
			}
			for id := uint64(1); ; id++ {
				var q lifecycleRequest
				if err := readFrame(conn, &q, lifecycleFrameBytes, &budget{}); err != nil {
					return err
				}
				if !q.valid() || q.ID != id {
					return ErrProtocol
				}
				if q.Takeover != nil {
					if q.Takeover.Grant != f.takeover.Grant || !bytes.Equal(q.Takeover.Signature, f.takeover.Signature) {
						return ErrProtocol
					}
					attempts.Add(1)
				}
				r, err := s.operation(context.Background(), conn, h, q)
				if err != nil {
					r = lifecycleResponse{ID: q.ID, Error: errorCode(err)}
				}
				if err := writeFrame(conn, r, lifecycleFrameBytes, &budget{}); err != nil {
					return err
				}
				if observe != nil && !observe(r) {
					return nil
				}
			}
		}()
	}()
	t.Cleanup(func() { right.Close(); worker.wait(t) })
	cc := f.successor()
	cc.Limits, err = lifecycleLimits(Limits{})
	must(t, err)
	cc.Limits.OperationTimeout = timeout
	client, err := NewLifecycleClient(context.Background(), right, cc)
	must(t, err)
	t.Cleanup(func() { client.Close() })
	return client, attempts
}

func awaitLifecycleBusy(t *testing.T, busy <-chan struct{}) {
	t.Helper()
	select {
	case <-busy:
	case <-time.After(2 * time.Second):
		t.Fatal("no authenticated BUSY response")
	}
}

func busyObserver(busy chan<- struct{}) func(lifecycleResponse) bool {
	return func(r lifecycleResponse) bool {
		if r.Error == Busy {
			select {
			case busy <- struct{}{}:
			default:
			}
		}
		return true
	}
}

func TestLifecycleTakeoverTLSBusyDurabilitySameGrant(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	g := lifecycleDataGuard(t, f, true)
	d, err := g.BeginDurability(1)
	must(t, err)
	before := workloadStoreCensus(t, f.rootPath)
	busy := make(chan struct{}, 1)
	c, attempts := lifecycleObservedClient(t, f.lifecycleFixture, 2*time.Second, busyObserver(busy))
	done := make(chan error, 1)
	go func() { _, err := c.Takeover(context.Background(), f.takeover); done <- err }()
	awaitLifecycleBusy(t, busy)
	// A waiting takeover neither holds the session gate nor fabricates an
	// applied grant. Result is a fresh authenticated operation on that session.
	_, err = c.Result(context.Background(), f.takeover.Grant, make([]byte, 32))
	remote(t, err, Unauthorized)
	if !reflect.DeepEqual(before, workloadStoreCensus(t, f.rootPath)) {
		t.Fatal("BUSY mutated durable state")
	}
	must(t, d.Complete(nil)) // Must progress while Takeover is still retrying.
	g.Release()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("takeover did not finish")
	}
	if attempts.Load() < 2 {
		t.Fatal("takeover did not retry")
	}
	r, err := c.Result(context.Background(), f.takeover.Grant, make([]byte, 32))
	must(t, err)
	if r.Grant != f.takeover.Grant {
		t.Fatal("different grant applied")
	}
}

func TestLifecycleTakeoverTLSReadOnlyAndPoisoned(t *testing.T) {
	for _, poison := range []bool{false, true} {
		t.Run(map[bool]string{false: "read-only", true: "poisoned"}[poison], func(t *testing.T) {
			f := fixtureFor(t, Limits{}, nil)
			g := lifecycleDataGuard(t, f, poison)
			c, attempts := lifecycleObservedClient(t, f.lifecycleFixture, time.Second, nil)
			if poison {
				d, err := g.BeginDurability(1)
				must(t, err)
				if err := d.Complete(syscall.EIO); err == nil {
					t.Fatal("failed DATA did not poison")
				}
			}
			before := workloadStoreCensus(t, f.rootPath)
			controller, err := c.Takeover(context.Background(), f.takeover)
			if poison {
				remote(t, err, Blocked)
				if controller != (a.Controller{}) || !reflect.DeepEqual(before, workloadStoreCensus(t, f.rootPath)) {
					t.Fatal("poison fabricated application")
				}
			} else {
				must(t, err)
			}
			if attempts.Load() != 1 {
				t.Fatal("unexpected retry", attempts.Load())
			}
		})
	}
}

func TestLifecycleTakeoverTLSBusyBudgetAndCancellation(t *testing.T) {
	for _, kind := range []string{"configured", "deadline", "cancel", "transport"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureFor(t, Limits{}, nil)
			g := lifecycleDataGuard(t, f, true)
			d, err := g.BeginDurability(1)
			must(t, err)
			defer func() { must(t, d.Complete(nil)) }()
			before := workloadStoreCensus(t, f.rootPath)
			busy := make(chan struct{}, 1)
			observe := busyObserver(busy)
			if kind == "transport" {
				observe = func(r lifecycleResponse) bool { busyObserver(busy)(r); return false }
			}
			budget := time.Second
			if kind == "configured" {
				budget = 120 * time.Millisecond
			}
			c, attempts := lifecycleObservedClient(t, f.lifecycleFixture, budget, observe)
			ctx, cancel := context.WithCancel(context.Background())
			if kind == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 120*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				controller, err := c.Takeover(ctx, f.takeover)
				if controller != (a.Controller{}) {
					done <- errors.New("fabricated controller")
					return
				}
				done <- err
			}()
			awaitLifecycleBusy(t, busy)
			if kind == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if kind == "cancel" {
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				} else if kind == "transport" {
					if err == nil {
						t.Fatal("transport loss accepted")
					}
				} else if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-time.After(700 * time.Millisecond):
				t.Fatal("retry renewed operation budget")
			}
			if (kind == "configured" || kind == "deadline") && attempts.Load() < 2 {
				t.Fatal("no retries")
			}
			if kind == "transport" && attempts.Load() != 1 {
				t.Fatal("retried lost transport")
			}
			if !reflect.DeepEqual(before, workloadStoreCensus(t, f.rootPath)) {
				t.Fatal("failed takeover mutated store")
			}
		})
	}
}

func TestLifecycleTakeoverTLSGateWaitUsesOperationBudget(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	c, attempts := lifecycleObservedClient(t, f, 50*time.Millisecond, nil)
	c.gate <- struct{}{}
	_, err := c.Takeover(context.Background(), f.takeover)
	<-c.gate
	if !errors.Is(err, context.DeadlineExceeded) || attempts.Load() != 0 {
		t.Fatal("gate wait escaped operation budget", err, attempts.Load())
	}
	// Timing out before IO must not close the authenticated session. The
	// second call proves reuse, not disk latency: give its real durable commit
	// the normal test budget instead of the gate-only 50 ms budget.
	c.config.Limits.OperationTimeout = 2 * time.Second
	_, err = c.Takeover(context.Background(), f.takeover)
	must(t, err)
}

func TestLifecycleTakeoverTLSUnauthorizedNoRetry(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	// Exact configured grant/key but invalid ROOT signature: TLS remains valid.
	f.takeover.Signature = make([]byte, 64)
	c, attempts := lifecycleObservedClient(t, f, time.Second, nil)
	_, err := c.Takeover(context.Background(), f.takeover)
	remote(t, err, Unauthorized)
	if attempts.Load() != 1 {
		t.Fatal("unauthorized retried")
	}
}
