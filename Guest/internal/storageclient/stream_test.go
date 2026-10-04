package storageclient

import (
	"crypto/tls"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

func TestCleanupUsesReservedCapacity(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	order := make(chan w.Operation, 5)
	c := fixture(t, func(cfg *Config) { cfg.Limits.Requests = 1 }, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply {
			order <- req.Body.Operation()
			switch req.Body.(type) {
			case w.LookupRequest:
				return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
			case w.OpenRequest:
				return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 7}}}
			case w.GetAttrRequest:
				close(entered)
				<-proceed
				return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
			case w.ForgetRequest:
				return w.Reply{Body: w.ForgetReply{}}
			case w.ReleaseRequest:
				return w.Reply{Body: w.ReleaseReply{}}
			default:
				return w.Reply{Errno: 5}
			}
		})
	})
	result, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Do(caller(c), 0, w.OpenRequest{Node: 42}); err != nil {
		t.Fatal(err)
	}
	complete := make(chan error, 2)
	go func() { _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); complete <- err }()
	<-entered
	if err = c.Forget(result.Node, 1); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := c.Do(none(c), w.LifecycleAuth, w.ReleaseRequest{Node: 42, Handle: 7})
		complete <- err
	}()
	deadline := time.After(time.Second)
	for {
		c.mu.Lock()
		queued := len(c.queue)
		c.mu.Unlock()
		if queued == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cleanup could not use reserved capacity")
		case <-time.After(time.Millisecond):
		}
	}
	close(proceed)
	for i := 0; i < 2; i++ {
		if err = <-complete; err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range []w.Operation{w.OpLookup, w.OpOpen, w.OpGetAttr, w.OpForget, w.OpRelease} {
		if op := <-order; op != expected {
			t.Fatal(op, expected)
		}
	}
}
func TestAdjacentForgetCoalescingPreservesCounts(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	forgets := make(chan w.ForgetRequest, 2)
	c := fixture(t, func(cfg *Config) { cfg.Timeout = 5 * time.Second }, func(s *tls.Conn) {
		firstGetAttr := true
		rpcServer(s, func(req w.Request) w.Reply {
			switch body := req.Body.(type) {
			case w.LookupRequest:
				return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
			case w.GetAttrRequest:
				if firstGetAttr {
					firstGetAttr = false
					close(entered)
					<-proceed
				}
				return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
			case w.ForgetRequest:
				forgets <- body
				return w.Reply{Body: w.ForgetReply{}}
			default:
				return w.Reply{Errno: 5}
			}
		})
	})
	// Unblock the server even if an assertion fails before normal release.
	t.Cleanup(release)

	var id LocalNode
	for i := 0; i < 5; i++ {
		result, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("same")})
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && result.Node != id {
			t.Fatal("repeated lookup allocated a different local node")
		}
		id = result.Node
	}

	complete := make(chan error, 1)
	go func() { _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); complete <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("execution worker did not reach the blocking RPC")
	}
	// The execution worker cannot dequeue either callback until released, so the
	// second FORGET deterministically updates the first queued body's slice.
	if err := c.Forget(id, 2); err != nil {
		t.Fatal(err)
	}
	if err := c.Forget(id, 3); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	n := c.nodes[id]
	if n == nil || n.pending == nil {
		c.mu.Unlock()
		t.Fatal("unacknowledged lookup ownership was discarded")
	}
	queued := len(c.queue)
	queuedCount := n.pending.req.Body.(w.ForgetRequest).Entries[0].Count
	refs, owned, pins := n.refs, n.owned, c.pins
	c.mu.Unlock()
	if queued != 1 || queuedCount != 5 || refs != 0 || owned != 5 || pins != 6 {
		t.Fatalf("before ack: queued=%d count=%d refs=%d owned=%d pins=%d", queued, queuedCount, refs, owned, pins)
	}

	release()
	if err := <-complete; err != nil {
		t.Fatal(err)
	}
	// This FIFO barrier returns only after the preceding FORGET ack has been
	// applied, without timing sleeps or polling private accounting state.
	if _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); err != nil {
		t.Fatal(err)
	}
	select {
	case batch := <-forgets:
		if len(batch.Entries) != 1 || batch.Entries[0] != (w.ForgetEntry{Node: 42, Count: 5}) {
			t.Fatalf("wire FORGET lost the adjacent count sum: %+v", batch)
		}
	default:
		t.Fatal("no wire FORGET before the FIFO barrier")
	}
	select {
	case extra := <-forgets:
		t.Fatalf("adjacent callbacks were not coalesced: %+v", extra)
	default:
	}

	c.mu.Lock()
	refs, owned, pins = n.refs, n.owned, c.pins
	pending := n.pending
	_, localLive := c.nodes[id]
	_, wireLive := c.wireNodes[42]
	nodes, wireNodes := len(c.nodes), len(c.wireNodes)
	c.mu.Unlock()
	if refs != 0 || owned != 0 || pins != 1 || pending != nil || localLive || wireLive || nodes != 1 || wireNodes != 1 {
		t.Fatalf("after ack: refs=%d owned=%d pins=%d pending=%v local=%v wire=%v nodes=%d wireNodes=%d", refs, owned, pins, pending != nil, localLive, wireLive, nodes, wireNodes)
	}
}

func TestInvalidStreamTerminal(t *testing.T) {
	for _, kind := range []string{"unsolicited", "oversized", "malformed", "event-regression"} {
		t.Run(kind, func(t *testing.T) {
			c := fixture(t, nil, func(s *tls.Conn) {
				switch kind {
				case "unsolicited":
					_ = w.WriteFrame(s, &w.Reply{Sequence: 1, Op: w.OpFlush, Body: w.FlushReply{}})
				case "oversized":
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], w.MaxFrame+1)
					_, _ = s.Write(header[:])
				case "malformed":
					payload := []byte(`{"sequence":1,"sequence":1}`)
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
					_, _ = s.Write(append(header[:], payload...))
				case "event-regression":
					for i := 0; i < 2; i++ {
						_ = w.WriteFrame(s, &w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{99}, Kind: w.InvalidateAttr, Name: []byte{}})
					}
				}
			})
			waitTerminal(t, c)
		})
	}
}
