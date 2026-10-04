package storageclient

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

func TestGrantLifecycleAndCleanup(t *testing.T) {
	forgetSeen := make(chan w.ForgetRequest, 1)
	releaseSeen := make(chan struct{}, 1)
	c := fixture(t, nil, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply {
			switch v := req.Body.(type) {
			case w.LookupRequest:
				return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
			case w.OpenRequest:
				return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 100}}}
			case w.ReadRequest:
				return w.Reply{Body: w.ReadReply{Data: []byte("x")}}
			case w.ForgetRequest:
				forgetSeen <- v
				return w.Reply{Body: w.ForgetReply{}}
			case w.ReleaseRequest:
				releaseSeen <- struct{}{}
				return w.Reply{Body: w.ReleaseReply{}}
			default:
				return w.Reply{Errno: 5}
			}
		})
	})
	root, entry := c.Root()
	if root != 1 || entry.Node != 99 {
		t.Fatal(root, entry)
	}
	one, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
	if err != nil || one.Node != two.Node || one.Node == 42 {
		t.Fatal(one, two, err)
	}
	opened, err := c.Do(caller(c), 0, w.OpenRequest{Node: 42, Flags: w.OpenReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.Handle(opened.Handle)
	if err != nil || grant.Node != 42 || grant.Handle != 100 {
		t.Fatal(grant, err)
	}
	if _, err = c.Do(none(c), w.OpenGrantAuth, w.WriteRequest{Node: 42, Handle: 100, Data: []byte("x")}); !errors.Is(err, ErrGrant) {
		t.Fatal(err)
	}
	if _, err = c.Do(none(c), w.OpenGrantAuth, w.ReadRequest{Node: 99, Handle: 100, Size: 1}); !errors.Is(err, ErrGrant) {
		t.Fatal("cross-node grant", err)
	}
	if err = c.Forget(one.Node, 2); err != nil {
		t.Fatal(err)
	}
	select {
	case batch := <-forgetSeen:
		if len(batch.Entries) != 1 || batch.Entries[0].Count != 2 {
			t.Fatal(batch)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup lost")
	}
	if _, err = c.Do(none(c), w.OpenGrantAuth, w.ReadRequest{Node: 42, Handle: 100, Size: 1}); err != nil {
		t.Fatal("handle pin lost", err)
	}
	if _, err = c.Do(none(c), w.NodeMetadataAuth, w.GetAttrRequest{Node: 42}); !errors.Is(err, ErrGrant) {
		t.Fatal("forgotten metadata authorized", err)
	}
	if _, err = c.Do(none(c), w.LifecycleAuth, w.ReleaseRequest{Node: 42, Handle: 100}); err != nil {
		t.Fatal(err)
	}
	<-releaseSeen
	if _, err = c.Handle(opened.Handle); !errors.Is(err, ErrGrant) {
		t.Fatal("released handle retained", err)
	}
	if _, err = c.Node(one.Node); !errors.Is(err, ErrGrant) {
		t.Fatal("forgotten node retained", err)
	}
	if _, err = c.Node(root); err != nil {
		t.Fatal("root unpinned", err)
	}
}
func TestQuotaAndCleanupFailure(t *testing.T) {
	c := fixture(t, func(cfg *Config) { cfg.Limits.Nodes = 2; cfg.Limits.Handles = 1 }, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply {
			switch req.Body.(type) {
			case w.LookupRequest:
				return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
			case w.OpenRequest:
				return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 7}}}
			case w.ReleaseRequest:
				return w.Reply{Errno: 5}
			default:
				return w.Reply{Errno: 5}
			}
		})
	})
	if _, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("y")}); !errors.Is(err, ErrCapacity) {
		t.Fatal("node quota", err)
	}
	if _, err := c.Do(caller(c), 0, w.OpenRequest{Node: 42}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(caller(c), 0, w.OpenRequest{Node: 42}); !errors.Is(err, ErrCapacity) {
		t.Fatal("handle quota", err)
	}
	if _, err := c.Do(none(c), w.LifecycleAuth, w.ReleaseRequest{Node: 42, Handle: 7}); err == nil {
		t.Fatal("cleanup failure ignored")
	}
	waitTerminal(t, c)
}
func TestForgetUnderflowAndFailedAck(t *testing.T) {
	for _, underflow := range []bool{true, false} {
		t.Run(map[bool]string{true: "underflow", false: "ack"}[underflow], func(t *testing.T) {
			c := fixture(t, nil, func(s *tls.Conn) {
				rpcServer(s, func(req w.Request) w.Reply {
					if _, ok := req.Body.(w.LookupRequest); ok {
						return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
					}
					return w.Reply{Errno: 5}
				})
			})
			result, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
			if err != nil {
				t.Fatal(err)
			}
			count := uint64(1)
			if underflow {
				count = 2
			}
			err = c.Forget(result.Node, count)
			if underflow && err == nil {
				t.Fatal("underflow accepted")
			}
			waitTerminal(t, c)
		})
	}
}
func TestEventsMapAfterGrantAndAreSeparate(t *testing.T) {
	received := make(chan Notification, 1)
	unblock := make(chan struct{})
	var once sync.Once
	c := fixture(t, func(cfg *Config) {
		cfg.Invalidate = func(ctx context.Context, n Notification) error {
			once.Do(func() { received <- n })
			select {
			case <-unblock:
			case <-ctx.Done():
			}
			return nil
		}
	}, func(s *tls.Conn) {
		var req w.Request
		if w.ReadFrame(s, &req) != nil {
			return
		}
		_ = w.WriteFrame(s, &w.Reply{Sequence: req.Sequence, Op: w.OpLookup, Body: w.LookupReply{Entry: testEntry(42, false)}})
		_ = w.WriteFrame(s, &w.Event{EventSequence: 1, Volume: testID('2'), Object: testEntry(42, false).Object, Kind: w.InvalidateAttr, Name: []byte{}})
		rpcServer(s, func(req w.Request) w.Reply { return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}} })
	})
	result, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-received:
		if len(n.Nodes) != 1 || n.Nodes[0] != result.Node {
			t.Fatal("grant/event order", n)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	// A blocked callback does not own the execution stream.
	if _, err = c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); err != nil {
		t.Fatal(err)
	}
	close(unblock)
}
func TestEventOverflowAndCallbackFailure(t *testing.T) {
	for _, overflow := range []bool{true, false} {
		t.Run(map[bool]string{true: "overflow", false: "callback"}[overflow], func(t *testing.T) {
			entered := make(chan struct{})
			var once sync.Once
			c := fixture(t, func(cfg *Config) {
				cfg.Limits.Events = 1
				cfg.Invalidate = func(ctx context.Context, _ Notification) error {
					once.Do(func() { close(entered) })
					if overflow {
						<-ctx.Done()
						return nil
					}
					return ErrProtocol
				}
			}, func(s *tls.Conn) {
				for i := uint64(1); i <= 4; i++ {
					if w.WriteFrame(s, &w.Event{EventSequence: i, Volume: testID('2'), Object: w.ObjectID{byte(i)}, Kind: w.InvalidateAttr, Name: []byte{}}) != nil {
						return
					}
					if i == 1 {
						<-entered
					}
				}
			})
			waitTerminal(t, c)
		})
	}
}
