package storageclient

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"sync"
	"testing"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

// Observe lifecycle transitions, not sleeps/polling or channel queue lengths.
func awaitClient(t *testing.T, c *Client, predicate func() bool) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		c.mu.Lock()
		ready, changed := predicate(), c.changed
		c.mu.Unlock()
		if ready {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatal("client lifecycle transition stalled")
		}
	}
}
func awaitError(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not join")
		return nil
	}
}
func gracefulStart(t *testing.T, c *Client, ctx context.Context) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.CloseGracefully(ctx) }()
	awaitClient(t, c, func() bool { return c.sealed })
	return done
}
func stillClosing(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("closed before accepted work completed: %v", err)
	default:
	}
}
func gate() (<-chan struct{}, func()) {
	ch := make(chan struct{})
	return ch, sync.OnceFunc(func() { close(ch) })
}
func asyncGetAttr(c *Client) <-chan error {
	done := make(chan error, 1)
	go func() { _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); done <- err }()
	return done
}

func TestGracefulFIFOAndForgetAcknowledgement(t *testing.T) {
	first, releaseFirst := gate()
	forget, releaseForget := gate()
	last, releaseLast := gate()
	seen := make(chan w.Operation, 4)
	c := fixture(t, func(cfg *Config) { cfg.Timeout = 5 * time.Second }, func(s *tls.Conn) {
		getattrs := 0
		rpcServer(s, func(req w.Request) w.Reply {
			seen <- req.Body.Operation()
			switch req.Body.(type) {
			case w.LookupRequest:
				return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
			case w.ForgetRequest:
				<-forget
				return w.Reply{Body: w.ForgetReply{}}
			default:
				getattrs++
				if getattrs == 1 {
					<-first
				} else {
					<-last
				}
				return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
			}
		})
	})
	t.Cleanup(releaseFirst)
	t.Cleanup(releaseForget)
	t.Cleanup(releaseLast)
	result, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	<-seen
	// Leave one inert reference after the admitted FORGET completes. Relaxing
	// residual references must not relax the queued acknowledgement barrier.
	again, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
	if err != nil || again.Node != result.Node {
		t.Fatal(again, err)
	}
	<-seen
	one := asyncGetAttr(c)
	if op := <-seen; op != w.OpGetAttr {
		t.Fatal(op)
	}
	if err := c.Forget(result.Node, 1); err != nil {
		t.Fatal(err)
	}
	two := asyncGetAttr(c)
	awaitClient(t, c, func() bool { return len(c.queue) == 2 })
	done := gracefulStart(t, c, context.Background())
	if _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := c.Forget(result.Node, 1); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := c.Capture(-1, 0); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	stillClosing(t, done)
	releaseFirst()
	if err := awaitError(t, one); err != nil {
		t.Fatal(err)
	}
	if op := <-seen; op != w.OpForget {
		t.Fatal("FIFO", op)
	}
	stillClosing(t, done)
	c.mu.Lock()
	owned := c.nodes[result.Node].owned
	c.mu.Unlock()
	if owned != 2 {
		t.Fatal("FORGET ownership dropped before ack", owned)
	}
	releaseForget()
	if op := <-seen; op != w.OpGetAttr {
		t.Fatal("FIFO", op)
	}
	stillClosing(t, done)
	releaseLast()
	if err := awaitError(t, two); err != nil {
		t.Fatal(err)
	}
	if err := awaitError(t, done); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseGracefully(context.Background()); err != nil {
		t.Fatal("non-idempotent", err)
	}
	if c.Err() != nil {
		t.Fatal("intentional socket close became failure", c.Err())
	}
	c.mu.Lock()
	n := c.nodes[result.Node]
	retained := n != nil && n.refs == 1 && n.owned == 1 && c.pins == 2 && c.wireNodes[42] == n
	c.mu.Unlock()
	if !retained {
		t.Fatal("residual lookup ownership was cleared or FORGET ack was not applied")
	}
	select {
	case <-c.Terminal():
		t.Fatal("intentional close signaled abort")
	default:
	}
}

func TestGracefulJoinsQueuedAndRunningInvalidations(t *testing.T) {
	one, releaseOne := gate()
	two, releaseTwo := gate()
	entered := make(chan uint64, 2)
	firstStarted := make(chan struct{})
	c := fixture(t, func(cfg *Config) {
		cfg.Invalidate = func(ctx context.Context, n Notification) error {
			entered <- n.Event.EventSequence
			if n.Event.EventSequence == 1 {
				close(firstStarted)
			}
			wait := one
			if n.Event.EventSequence == 2 {
				wait = two
			}
			select {
			case <-wait:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}, func(s *tls.Conn) {
		for i := uint64(1); i <= 2; i++ {
			if err := w.WriteFrame(s, &w.Event{EventSequence: i, Volume: testID('2'), Object: w.ObjectID{99}, Kind: w.InvalidateAttr, Name: []byte{}}); err != nil {
				return
			}
			if i == 1 {
				<-firstStarted
			}
		}
	})
	t.Cleanup(releaseOne)
	t.Cleanup(releaseTwo)
	if seq := <-entered; seq != 1 {
		t.Fatal(seq)
	}
	awaitClient(t, c, func() bool { return c.pendingEvents == 2 })
	done := gracefulStart(t, c, context.Background())
	stillClosing(t, done)
	releaseOne()
	if seq := <-entered; seq != 2 {
		t.Fatal(seq)
	}
	stillClosing(t, done)
	releaseTwo()
	if err := awaitError(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestGracefulCompletedErrnoPolicy(t *testing.T) {
	for _, body := range []w.RequestBody{w.ReadRequest{Node: 42, Handle: 7, Size: 1}, w.WriteRequest{Node: 42, Handle: 7, Data: []byte("x")}, w.FlushRequest{Node: 42, Handle: 7}, w.FsyncRequest{Node: 42, Handle: 7}} {
		t.Run(string(body.Operation()), func(t *testing.T) {
			c := fixture(t, nil, func(s *tls.Conn) {
				rpcServer(s, func(req w.Request) w.Reply {
					switch req.Body.(type) {
					case w.LookupRequest:
						return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
					case w.OpenRequest:
						return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 7}}}
					case w.ReleaseRequest:
						return w.Reply{Body: w.ReleaseReply{}}
					case w.ForgetRequest:
						return w.Reply{Body: w.ForgetReply{}}
					default:
						return w.Reply{Errno: 5}
					}
				})
			})
			lookup, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Do(caller(c), 0, w.OpenRequest{Node: 42, Flags: w.OpenReadWrite}); err != nil {
				t.Fatal(err)
			}
			result, err := c.Do(caller(c), 0, body)
			if err != nil || result.Reply.Errno != 5 || c.Err() != nil {
				t.Fatalf("changed errno delivery: %+v %v %v", result, err, c.Err())
			}
			if _, err := c.Do(none(c), w.LifecycleAuth, w.ReleaseRequest{Node: 42, Handle: 7}); err != nil {
				t.Fatal(err)
			}
			if err := c.Forget(lookup.Node, 1); err != nil {
				t.Fatal(err)
			}
			if err := c.CloseGracefully(context.Background()); !errors.Is(err, ErrIncomplete) {
				t.Fatal("completed errno erased", err)
			}
		})
	}
	t.Run("negative-lookup-is-known", func(t *testing.T) {
		c := fixture(t, nil, func(s *tls.Conn) { rpcServer(s, func(w.Request) w.Reply { return w.Reply{Errno: 2} }) })
		result, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("missing")})
		if err != nil || result.Reply.Errno != 2 {
			t.Fatal(result, err)
		}
		if err := c.CloseGracefully(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestGracefulResidualLookupRefsAndLiveHandlePolicy(t *testing.T) {
	for _, handle := range []bool{false, true} {
		t.Run(map[bool]string{false: "lookup-ref-retained", true: "open-handle-rejected"}[handle], func(t *testing.T) {
			c := fixture(t, nil, func(s *tls.Conn) {
				rpcServer(s, func(req w.Request) w.Reply {
					switch req.Body.(type) {
					case w.LookupRequest:
						return w.Reply{Body: w.LookupReply{Entry: testEntry(42, false)}}
					case w.OpenRequest:
						return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 7}}}
					case w.ForgetRequest:
						if !handle {
							t.Error("synthetic FORGET for inert lookup reference")
						}
						return w.Reply{Body: w.ForgetReply{}}
					default:
						t.Error("synthetic cleanup RPC")
						return w.Reply{Errno: 5}
					}
				})
			})
			lookup, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("x")})
			if err != nil {
				t.Fatal(err)
			}
			if handle {
				if _, err := c.Do(caller(c), 0, w.OpenRequest{Node: 42}); err != nil {
					t.Fatal(err)
				}
				if err := c.Forget(lookup.Node, 1); err != nil {
					t.Fatal(err)
				}
			}
			c.mu.Lock()
			node := c.nodes[lookup.Node]
			refs, owned, pins := node.refs, node.owned, c.pins
			nodes, wireNodes := len(c.nodes), len(c.wireNodes)
			c.mu.Unlock()
			err = c.CloseGracefully(context.Background())
			if handle && !errors.Is(err, ErrIncomplete) || !handle && err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			retained := c.nodes[lookup.Node] == node && c.wireNodes[42] == node
			unchanged := node.refs == refs && node.owned == owned && c.pins == pins && len(c.nodes) == nodes && len(c.wireNodes) == wireNodes
			c.mu.Unlock()
			if !retained {
				t.Fatal("fabricated grant release")
			}
			if !handle && (refs == 0 || owned == 0 || !unchanged) {
				t.Fatal("inert lookup refs, grants, nodes, or pins changed during close")
			}
		})
	}
}

func TestGracefulUnknownAcceptedWork(t *testing.T) {
	for _, mode := range []string{"peer-EOF", "context", "RPC-timeout", "errno"} {
		t.Run(mode, func(t *testing.T) {
			proceed, release := gate()
			entered := make(chan struct{})
			c := fixture(t, func(cfg *Config) {
				cfg.Timeout = 5 * time.Second
				if mode == "RPC-timeout" {
					cfg.Timeout = 100 * time.Millisecond
				}
			}, func(s *tls.Conn) {
				var req w.Request
				if w.ReadFrame(s, &req) != nil {
					return
				}
				close(entered)
				<-proceed
				switch mode {
				case "peer-EOF":
					_ = s.NetConn().Close()
				case "errno":
					_ = w.WriteFrame(s, &w.Reply{Sequence: req.Sequence, Op: req.Body.Operation(), Errno: 5})
				}
			})
			t.Cleanup(release)
			one := asyncGetAttr(c)
			<-entered
			var two <-chan error
			if mode != "errno" {
				two = asyncGetAttr(c)
				awaitClient(t, c, func() bool { return len(c.queue) == 1 })
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := gracefulStart(t, c, ctx)
			if mode == "context" {
				cancel()
			}
			release()
			err := awaitError(t, done)
			if err == nil {
				t.Fatal("unknown or failed accepted work reported clean")
			}
			if mode == "peer-EOF" && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if mode == "context" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if mode == "errno" && !errors.Is(err, ErrIncomplete) {
				t.Fatal(err)
			}
			if err := awaitError(t, one); mode != "errno" && err == nil {
				t.Fatal("active RPC succeeded")
			}
			if two != nil && awaitError(t, two) == nil {
				t.Fatal("queued RPC succeeded")
			}
		})
	}
}

func TestGracefulAbortCloseAndCallbackFailurePreserved(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	proceed, release := gate()
	callbackErr, abortErr := errors.New("kernel notification failed"), errors.New("adapter reply failed")
	c := fixture(t, func(cfg *Config) {
		cfg.Invalidate = func(ctx context.Context, _ Notification) error {
			close(entered)
			<-ctx.Done()
			<-proceed
			close(exited)
			return callbackErr
		}
	}, func(s *tls.Conn) {
		_ = w.WriteFrame(s, &w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{99}, Kind: w.InvalidateAttr, Name: []byte{}})
	})
	t.Cleanup(release)
	<-entered
	done := gracefulStart(t, c, context.Background())
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	waitTerminal(t, c)
	c.Abort(abortErr)
	stillClosing(t, done)
	release()
	for _, ch := range []<-chan error{done, closed} {
		err := awaitError(t, ch)
		if !errors.Is(err, abortErr) || !errors.Is(err, callbackErr) || !errors.Is(err, ErrClosed) {
			t.Fatal("lost concurrent failure", err)
		}
	}
	select {
	case <-exited:
	default:
		t.Fatal("callback not joined")
	}
}

func TestGracefulDeadlineJoinsInvalidation(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	c := fixture(t, func(cfg *Config) {
		cfg.Invalidate = func(ctx context.Context, _ Notification) error {
			close(entered)
			<-ctx.Done()
			close(exited)
			return ctx.Err()
		}
	}, func(s *tls.Conn) {
		_ = w.WriteFrame(s, &w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{99}, Kind: w.InvalidateAttr, Name: []byte{}})
	})
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.CloseGracefully(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("callback not joined")
	}
}

func TestGracefulConcurrentClosersAndCaptureSeal(t *testing.T) {
	proceed, release := gate()
	entered := make(chan struct{})
	c := fixture(t, nil, nil)
	t.Cleanup(release)
	captured := make(chan error, 1)
	go func() {
		queries := 0
		_, err := c.capture(func(_ int, h *credentialHeader, _ []uint32) error {
			if queries == 0 {
				close(entered)
				<-proceed
			}
			queries++
			h.State = 0
			h.FSUID = math.MaxUint32
			h.FSGID = math.MaxUint32
			return nil
		}, 7, 1)
		captured <- err
	}()
	<-entered
	const count = 12
	closers := make([]<-chan error, count)
	for i := range closers {
		closers[i] = gracefulStart(t, c, context.Background())
	}
	for _, done := range closers {
		stillClosing(t, done)
	}
	if _, err := c.capture(func(int, *credentialHeader, []uint32) error { t.Error("query admitted after seal"); return nil }, 7, 2); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	release()
	if err := awaitError(t, captured); err != nil {
		t.Fatal(err)
	}
	for _, done := range closers {
		if err := awaitError(t, done); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGracefulPreservesPriorFailure(t *testing.T) {
	for _, failure := range []string{"abort", "capture", "completed-errno-then-close"} {
		t.Run(failure, func(t *testing.T) {
			c := fixture(t, nil, func(s *tls.Conn) {
				rpcServer(s, func(w.Request) w.Reply { return w.Reply{Errno: 5} })
			})
			want := errors.New("prior adapter failure")
			switch failure {
			case "abort":
				c.Abort(want)
			case "capture":
				want = ErrUnsupported
				if _, err := c.capture(func(int, *credentialHeader, []uint32) error { return want }, 7, 1); !errors.Is(err, want) {
					t.Fatal(err)
				}
			case "completed-errno-then-close":
				want = ErrIncomplete
				if err := awaitError(t, asyncGetAttr(c)); err != nil {
					t.Fatal(err)
				}
				if err := c.Close(); !errors.Is(err, want) {
					t.Fatal("Close lost completed error", err)
				}
			}
			if err := c.CloseGracefully(context.Background()); !errors.Is(err, want) {
				t.Fatal("graceful close erased prior failure", err)
			}
		})
	}
}

func TestGracefulWaitsExecuteAndReplyApplication(t *testing.T) {
	for _, field := range []string{"execute", "reply-applied"} {
		t.Run(field, func(t *testing.T) {
			c := fixture(t, nil, nil)
			// Model the narrow windows after dequeue / after reply validation. No
			// server RPC is active, so these owned flags cannot be changed by it.
			c.mu.Lock()
			if field == "execute" {
				c.processing = true
			} else {
				c.replyPending = true
			}
			c.mu.Unlock()
			done := gracefulStart(t, c, context.Background())
			stillClosing(t, done)
			c.mu.Lock()
			c.processing = false
			c.replyPending = false
			c.broadcastLocked()
			c.mu.Unlock()
			if err := awaitError(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
