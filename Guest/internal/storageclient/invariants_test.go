package storageclient

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

func TestForgetDoesNotOvertakeInterveningRPC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, terminal: make(chan struct{}), wake: make(chan struct{}, 1), limits: DefaultLimits(), nodes: make(map[LocalNode]*nodeState), wireNodes: make(map[w.NodeID]*nodeState), nextNode: 1, pins: 1}
	id, err := c.onEntry(testEntry(42, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.onEntry(testEntry(42, false)); err != nil {
		t.Fatal(err)
	}
	if err = c.Forget(id, 1); err != nil {
		t.Fatal(err)
	}
	intervening := &work{req: w.Request{Sequence: 1, Auth: w.Auth{Kind: w.NodeMetadataAuth}, Body: w.GetAttrRequest{Node: 42}}}
	c.queue = append(c.queue, intervening)
	if err = c.Forget(id, 1); err != nil {
		t.Fatal(err)
	}
	if len(c.queue) != 3 || c.queue[1] != intervening {
		t.Fatal("cleanup reordered")
	}
	for _, i := range []int{0, 2} {
		if c.queue[i].req.Body.(w.ForgetRequest).Entries[0].Count != 1 {
			t.Fatal("later FORGET moved before RPC")
		}
	}
}
func TestAggregateLookupPinQuota(t *testing.T) {
	c := fixture(t, func(cfg *Config) { cfg.Limits.Nodes = 3 }, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply { return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}} })
	})
	for i := 0; i < 2; i++ {
		if _, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("same")}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("same")}); !errors.Is(err, ErrCapacity) {
		t.Fatal("unbounded repeated lookup refs", err)
	}
}
func TestGrantCorruptionAndInvalidRelease(t *testing.T) {
	for _, kind := range []string{"identity", "handle", "releaseflags", "releaseauth"} {
		t.Run(kind, func(t *testing.T) {
			lookups := 0
			c := fixture(t, nil, func(s *tls.Conn) {
				rpcServer(s, func(req w.Request) w.Reply {
					switch req.Body.(type) {
					case w.LookupRequest:
						lookups++
						e := testEntry(42, false)
						if kind == "identity" && lookups > 1 {
							e.Object[0]++
						}
						return w.Reply{Body: w.LookupReply{Entry: e}}
					case w.OpenRequest:
						return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 7}}}
					default:
						return w.Reply{Errno: 5}
					}
				})
			})
			if _, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")}); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "identity":
				_, err = c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
			case "handle":
				if _, err = c.Do(caller(c), 0, w.OpenRequest{Node: 42}); err != nil {
					t.Fatal(err)
				}
				_, err = c.Do(caller(c), 0, w.OpenRequest{Node: 42})
			case "releaseflags":
				_, err = c.Do(none(c), w.LifecycleAuth, w.ReleaseRequest{Node: 42, Handle: 7, ReleaseFlags: 128})
			case "releaseauth":
				_, err = c.Do(Snapshot{}, w.LifecycleAuth, w.ReleaseRequest{Node: 42, Handle: 7})
			}
			if err == nil {
				t.Fatal("corruption accepted")
			}
			waitTerminal(t, c)
		})
	}
}
func TestSequenceWrapTerminal(t *testing.T) {
	c := fixture(t, nil, nil)
	c.mu.Lock()
	c.sequence = math.MaxUint64
	c.mu.Unlock()
	if _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); err == nil {
		t.Fatal("wrapped sequence")
	}
	waitTerminal(t, c)
}
func TestQueuedCallsJoinOnFailure(t *testing.T) {
	active := make(chan struct{})
	c := fixture(t, nil, func(s *tls.Conn) {
		var req w.Request
		if w.ReadFrame(s, &req) == nil {
			close(active)
		}
	})
	const count = 8
	var wg sync.WaitGroup
	wg.Add(count)
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		go func() { defer wg.Done(); _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); results <- err }()
	}
	<-active
	// Wait for deterministic admission, without mutating transport ordering.
	deadline := time.After(time.Second)
	for {
		c.mu.Lock()
		admitted := c.requests
		c.mu.Unlock()
		if admitted == count {
			break
		}
		select {
		case <-deadline:
			t.Fatal("admission stalled")
		case <-time.After(time.Millisecond):
		}
	}
	c.Abort(errors.New("FUSE response delivery failed"))
	wg.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, ErrClosed) {
			t.Fatal("unjoined request", err)
		}
	}
}
func TestCloseJoinsInvalidation(t *testing.T) {
	entered := make(chan struct{})
	exit := make(chan struct{})
	c := fixture(t, func(cfg *Config) {
		cfg.Invalidate = func(ctx context.Context, _ Notification) error { close(entered); <-ctx.Done(); close(exit); return nil }
	}, func(s *tls.Conn) {
		_ = w.WriteFrame(s, &w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{99}, Kind: w.InvalidateAttr, Name: []byte{}})
	})
	<-entered
	c.Close()
	select {
	case <-exit:
	default:
		t.Fatal("callback not joined")
	}
}
