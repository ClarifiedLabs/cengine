package storageclient

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

// Real mutual TLS + public New/Do: kernel invalidation can wait for writeback,
// so a blocked notifier must not prevent DATA replies needed to finish it.
func TestRepeatedPendingInvalidationsKeepRepliesAndGracefulOwnership(t *testing.T) {
	for _, cancelClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "cancel"}[cancelClose], func(t *testing.T) { repeatedPendingInvalidations(t, cancelClose) })
	}
}

func repeatedPendingInvalidations(t *testing.T, cancelClose bool) {
	const writes = 1000
	first, releaseFirst := gate()
	last, releaseLast := gate()
	entered := make(chan uint64, writes)
	firstStarted := make(chan struct{})
	c := fixture(t, func(cfg *Config) {
		cfg.Timeout = 5 * time.Second
		cfg.Limits.Events = 1
		cfg.Invalidate = func(ctx context.Context, n Notification) error {
			entered <- n.Event.EventSequence
			if n.Event.EventSequence == 1 {
				close(firstStarted)
			}
			wait := first
			if n.Event.EventSequence != 1 {
				wait = last
			}
			select {
			case <-wait:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}, func(s *tls.Conn) {
		var sequence uint64
		for {
			var req w.Request
			if w.ReadFrame(s, &req) != nil {
				return
			}
			reply := w.Reply{Sequence: req.Sequence, Op: req.Body.Operation()}
			switch body := req.Body.(type) {
			case w.LookupRequest:
				reply.Body = w.LookupReply{Entry: testEntry(42, false)}
			case w.OpenRequest:
				reply.Body = w.OpenReply{Opened: w.Opened{Handle: 7}}
			case w.WriteRequest:
				reply.Body = w.WriteReply{Written: uint32(len(body.Data))}
			case w.GetAttrRequest:
				reply.Body = w.GetAttrReply{Attr: testEntry(99, true).Attr}
			case w.ReleaseRequest:
				reply.Body = w.ReleaseReply{}
			case w.ForgetRequest:
				reply.Body = w.ForgetReply{}
			default:
				t.Errorf("unexpected RPC %T", body)
				return
			}
			if w.WriteFrame(s, &reply) != nil {
				return
			}
			if req.Body.Operation() == w.OpWrite {
				// Match storagemanaged's WRITE: data followed by attributes.
				for _, kind := range []w.EventKind{w.InvalidateData, w.InvalidateAttr} {
					sequence++
					if w.WriteFrame(s, &w.Event{EventSequence: sequence, Volume: testID('2'), Object: testEntry(42, false).Object, Kind: kind, Name: []byte{}}) != nil {
						return
					}
					if sequence == 1 {
						// Prove the first event is running before sending any event
						// that the new implementation may legitimately coalesce.
						select {
						case <-firstStarted:
						case <-time.After(3 * time.Second):
							t.Error("first notification did not start")
							return
						}
					}
				}
			}
		}
	})
	t.Cleanup(releaseFirst)
	t.Cleanup(releaseLast)
	lookup, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("fsx-file")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Do(caller(c), 0, w.OpenRequest{Node: 42, Flags: w.OpenReadWrite}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < writes; i++ {
		result, err := c.Do(caller(c), 0, w.WriteRequest{Node: 42, Handle: 7, Offset: uint64(i), Data: []byte{byte(i)}})
		if err != nil || result.Reply.Errno != 0 {
			t.Fatalf("write %d: %v errno=%d", i, err, result.Reply.Errno)
		}
		if i == 0 {
			select {
			case seq := <-entered:
				if seq != 1 {
					t.Fatal(seq)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("first notification did not start")
			}
		}
	}
	// The FIFO RPC reply follows all preceding events on the actual wire.
	if _, err = c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	pending, cells, handles, pins := c.pendingEvents, len(c.events), len(c.handles), c.pins
	c.mu.Unlock()
	if pending != 2*writes || cells != 1 || handles != 1 || pins != 2 {
		t.Fatalf("lost obligations: pending=%d cells=%d handles=%d pins=%d", pending, cells, handles, pins)
	}
	if _, err = c.Do(none(c), w.LifecycleAuth, w.ReleaseRequest{Node: 42, Handle: 7}); err != nil {
		t.Fatal(err)
	}
	if err = c.Forget(lookup.Node, 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := gracefulStart(t, c, ctx)
	stillClosing(t, done)
	if cancelClose {
		cancel()
		if err := awaitError(t, done); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.pendingEvents != 2*writes-1 || len(c.events) != 1 || c.err == nil {
			t.Fatal("cancellation erased unrun events or claimed completion")
		}
		return
	}
	releaseFirst()
	select {
	case seq := <-entered:
		if seq != 2*writes {
			t.Fatalf("queued coverage ended at %d", seq)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued notification did not start")
	}
	c.mu.Lock()
	pending = c.pendingEvents
	c.mu.Unlock()
	if pending != 2*writes-1 {
		t.Fatalf("running aggregate lost counts: %d", pending)
	}
	stillClosing(t, done)
	releaseLast()
	if err = awaitError(t, done); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingEvents != 0 || c.pins != 1 || len(c.handles) != 0 || len(c.events) != 0 {
		t.Fatal("graceful join left counts or grants")
	}
}
