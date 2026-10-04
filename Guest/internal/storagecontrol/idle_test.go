package storagecontrol

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// Observe the real TLS transport's deadline boundary, without changing IO or
// inserting a production hook. SetDeadline during authentication is untouched.
type controlDeadlineConn struct {
	net.Conn
	deadlines chan time.Time
}

func (c *controlDeadlineConn) SetReadDeadline(deadline time.Time) error {
	err := c.Conn.SetReadDeadline(deadline)
	if err == nil {
		c.deadlines <- deadline
	}
	return err
}

func nextControlDeadline(t *testing.T, c *controlDeadlineConn) time.Time {
	t.Helper()
	select {
	case deadline := <-c.deadlines:
		return deadline
	case <-time.After(3 * time.Second):
		t.Fatal("server did not reach request read boundary")
		return time.Time{}
	}
}

func connectObservedControl(t *testing.T, f *fixture, server *Server) (*Client, *testWorker, *controlDeadlineConn, context.CancelFunc) {
	t.Helper()
	left, right := tcpPair(t)
	raw := &controlDeadlineConn{Conn: left, deadlines: make(chan time.Time, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	worker := &testWorker{done: make(chan struct{})}
	go func() {
		defer close(worker.done)
		worker.err = server.Serve(ctx, raw)
	}()
	t.Cleanup(func() { cancel(); right.Close(); worker.wait(t) })
	// Only the server's frame budget is short; authentication/client/operation
	// deadlines retain normal values and cannot mask the server policy.
	client, err := NewPKILifecycleWorkloadClient(context.Background(), right, f.config())
	must(t, err)
	t.Cleanup(func() { client.Close() })
	return client, worker, raw, cancel
}

func controlFrameServer(t *testing.T, f *fixture, timeout time.Duration) *Server {
	t.Helper()
	l := f.l
	l.ReadTimeout = timeout
	server, err := NewPKILifecycleWorkloadServer(f.authority, f.serverPolicy(l))
	must(t, err)
	return server
}

func idleControlMemory(t *testing.T, server *Server, slots int) {
	t.Helper()
	server.memory.mu.Lock()
	used := server.memory.used
	server.memory.mu.Unlock()
	if used != 0 || len(server.slots) != slots || len(server.queries) != 0 {
		t.Fatalf("retained control resources: memory=%d slots=%d queries=%d, want slots=%d", used, len(server.slots), len(server.queries), slots)
	}
}

func TestAuthenticatedControlIdleSurvivesFrameBudget(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	server := controlFrameServer(t, f, 150*time.Millisecond)
	client, worker, raw, _ := connectObservedControl(t, f, server)
	// Exercise both the first request after Hello and a later request on the
	// SAME authenticated connection. There is no reconnect, heartbeat or replay.
	for id := uint64(1); id <= 2; id++ {
		nextControlDeadline(t, raw)
		<-time.After(2 * server.config.Limits.ReadTimeout)
		select {
		case <-worker.done:
			t.Fatalf("authenticated idle connection expired before request %d: %v", id, worker.err)
		default:
		}
		idleControlMemory(t, server, 1)
		response := call(t, client, Request{Query: &Empty{}})
		if response.ID != id || response.Snapshot.Store.ID != f.store || response.Snapshot.Epoch != f.authority.Epoch() {
			t.Fatal("idle query changed correlation or authority identity")
		}
		if nextControlDeadline(t, raw).IsZero() {
			t.Fatal("first request byte did not arm frame deadline")
		}
	}
	client.Close()
	worker.wait(t)
	idleControlMemory(t, server, 0)
}

func TestAuthenticatedControlPartialFramesRemainBounded(t *testing.T) {
	var frame bytes.Buffer
	must(t, writeFrame(&frame, Request{ID: 1, Query: &Empty{}}, 1024, &budget{}))
	for _, size := range []int{1, 2, 3, 4, 5, frame.Len() - 1} {
		t.Run(string(rune('a'+size)), func(t *testing.T) {
			f := fixtureFor(t, Limits{}, nil)
			server := controlFrameServer(t, f, 150*time.Millisecond)
			client, worker, raw, _ := connectObservedControl(t, f, server)
			if !nextControlDeadline(t, raw).IsZero() {
				t.Fatal("authenticated idle read has a deadline")
			}
			must(t, writeFull(client.conn, frame.Bytes()[:1]))
			deadline := nextControlDeadline(t, raw)
			if deadline.IsZero() {
				t.Fatal("partial frame has no deadline")
			}
			if size > 1 {
				must(t, writeFull(client.conn, frame.Bytes()[1:size]))
			}
			err := worker.wait(t)
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() || time.Now().Before(deadline) {
				t.Fatalf("partial frame did not hit its real read deadline: %v", err)
			}
			select {
			case extra := <-raw.deadlines:
				t.Fatalf("partial frame extended its absolute deadline: %v", extra)
			default:
			}
			idleControlMemory(t, server, 0)
		})
	}
}

func TestAuthenticatedControlCancellationJoinsIdleAndPartialFrames(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "partial-body"}[partial], func(t *testing.T) {
			f := fixtureFor(t, Limits{}, nil)
			server := controlFrameServer(t, f, time.Minute)
			client, worker, raw, cancel := connectObservedControl(t, f, server)
			if !nextControlDeadline(t, raw).IsZero() {
				t.Fatal("idle deadline")
			}
			if partial {
				must(t, writeFull(client.conn, []byte{0, 0, 0, 20, '{'}))
				if nextControlDeadline(t, raw).IsZero() {
					t.Fatal("missing partial-body deadline")
				}
			}
			cancel()
			if err := worker.wait(t); err == nil {
				t.Fatal("canceled incomplete input succeeded")
			}
			idleControlMemory(t, server, 0)
		})
	}
}

func TestAuthenticatedControlIdleRetainsBoundedConnectionSlots(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	server := controlFrameServer(t, f, 100*time.Millisecond)
	first, firstWorker, firstRaw, _ := connectObservedControl(t, f, server)
	_, secondWorker, secondRaw, cancelSecond := connectObservedControl(t, f, server)
	nextControlDeadline(t, firstRaw)
	nextControlDeadline(t, secondRaw)
	<-time.After(2 * server.config.Limits.ReadTimeout)
	idleControlMemory(t, server, 2)
	_, refused, err := f.connectWorker(server, f.config())
	if err == nil || !errors.Is(refused.wait(t), ErrLimit) {
		t.Fatal("idle connections exceeded exact admission bound")
	}
	first.Close()
	firstWorker.wait(t)
	idleControlMemory(t, server, 1)
	replacement, replacementWorker, _, cancelReplacement := connectObservedControl(t, f, server)
	call(t, replacement, Request{Query: &Empty{}})
	cancelSecond()
	cancelReplacement()
	secondWorker.wait(t)
	replacementWorker.wait(t)
	idleControlMemory(t, server, 0)
}
