package storagecontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestLifecycleTLSMoreThan4096ResultsAndCounterExhaustion(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	server, err := NewLifecycleServer(f.authority, f.sc)
	must(t, err)
	client := lifecycleConnect(t, server, f.cc)
	var nonce [32]byte
	for id := uint64(1); id <= 4100; id++ {
		binary.BigEndian.PutUint64(nonce[:8], id)
		receipt, err := client.Result(context.Background(), f.initial.Grant, nonce[:])
		must(t, err)
		if client.id != id || receipt.Grant != f.initial.Grant || !bytes.Equal(receipt.Nonce, nonce[:]) {
			t.Fatalf("wrong result/counter on same client at request %d", id)
		}
	}
	t.Log("4100 fresh results completed on one authenticated TLS connection")
	// Test-only private counter seam: exhaustion must refuse without a wrapped
	// request, reconnect, or retry. No production counter override is exposed.
	client.id = ^uint64(0)
	if _, err := client.Result(context.Background(), f.initial.Grant, nonce[:]); !errors.Is(err, ErrLimit) {
		t.Fatalf("counter exhaustion: %v", err)
	}
	if client.id != ^uint64(0) {
		t.Fatal("exhausted counter wrapped")
	}
	if _, err := client.Result(context.Background(), f.initial.Grant, nonce[:]); !errors.Is(err, ErrClosed) {
		t.Fatalf("exhausted connection remained usable: %v", err)
	}
	request := lifecycleRequest{ID: ^uint64(0), Result: &lifecycleResultRequest{f.initial.Grant, nonce[:]}}
	if !request.valid() {
		t.Fatal("maximum nonzero wire counter rejected")
	}
	request.ID = 0
	if request.valid() {
		t.Fatal("wrapped wire counter accepted")
	}
}

// Observe actual TLS read deadlines through the shared test-only raw-connection
// wrapper without a production timeout or authority seam.
func connectObservedLifecycle(t *testing.T, f *lifecycleFixture, server *LifecycleServer) (*LifecycleClient, *testWorker, *controlDeadlineConn, context.CancelFunc) {
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
	client, err := NewLifecycleClient(context.Background(), right, f.cc)
	must(t, err)
	t.Cleanup(func() { client.Close() })
	return client, worker, raw, cancel
}

func lifecycleIdleMemory(t *testing.T, server *LifecycleServer, slots int) {
	t.Helper()
	server.memory.mu.Lock()
	used := server.memory.used
	server.memory.mu.Unlock()
	if used != 0 || len(server.slots) != slots {
		t.Fatalf("retained lifecycle resources: memory=%d slots=%d, want slots=%d", used, len(server.slots), slots)
	}
}

func TestLifecycleTLSIdleSurvivesFrameBudget(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	limits, err := lifecycleLimits(Limits{})
	must(t, err)
	limits.ReadTimeout = 50 * time.Millisecond
	f.sc.Limits = limits
	server, err := NewLifecycleServer(f.authority, f.sc)
	must(t, err)
	client, worker, raw, _ := connectObservedLifecycle(t, f, server)
	// Both initial and later idle periods exceed the frame budget, on the same
	// connection with no heartbeats, reconnects, or replay.
	for id := uint64(1); id <= 2; id++ {
		if !nextControlDeadline(t, raw).IsZero() {
			t.Fatal("authenticated idle read retained a deadline")
		}
		time.Sleep(3 * limits.ReadTimeout)
		select {
		case <-worker.done:
			t.Fatalf("idle connection expired: %v", worker.err)
		default:
		}
		lifecycleIdleMemory(t, server, 1)
		_, err := client.Result(context.Background(), f.initial.Grant, bytes.Repeat([]byte{byte(id)}, 32))
		must(t, err)
		if client.id != id || nextControlDeadline(t, raw).IsZero() {
			t.Fatal("first decrypted byte did not arm the frame deadline")
		}
	}
	client.Close()
	worker.wait(t)
	lifecycleIdleMemory(t, server, 0)
}

func TestLifecycleTLSPartialFramesRemainBounded(t *testing.T) {
	for _, size := range []int{1, 2, 3, 4, 5} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			limits, err := lifecycleLimits(Limits{})
			must(t, err)
			limits.ReadTimeout = 100 * time.Millisecond
			f.sc.Limits = limits
			server, err := NewLifecycleServer(f.authority, f.sc)
			must(t, err)
			client, worker, raw, _ := connectObservedLifecycle(t, f, server)
			if !nextControlDeadline(t, raw).IsZero() {
				t.Fatal("idle deadline")
			}
			var frame bytes.Buffer
			must(t, writeFrame(&frame, lifecycleRequest{ID: 1, Result: &lifecycleResultRequest{f.initial.Grant, make([]byte, 32)}}, lifecycleFrameBytes, &budget{}))
			must(t, writeFull(client.conn, frame.Bytes()[:1]))
			deadline := nextControlDeadline(t, raw)
			if deadline.IsZero() {
				t.Fatal("partial frame has no deadline")
			}
			if size > 1 {
				must(t, writeFull(client.conn, frame.Bytes()[1:size]))
			}
			err = worker.wait(t)
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() || time.Now().Before(deadline) {
				t.Fatalf("partial frame did not hit its read deadline: %v", err)
			}
			select {
			case extra := <-raw.deadlines:
				t.Fatalf("partial frame extended its deadline: %v", extra)
			default:
			}
			lifecycleIdleMemory(t, server, 0)
		})
	}
}

func TestLifecycleTLSCancellationJoinsIdleAndPartialFrames(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			server, err := NewLifecycleServer(f.authority, f.sc)
			must(t, err)
			client, worker, raw, cancel := connectObservedLifecycle(t, f, server)
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
			lifecycleIdleMemory(t, server, 0)
		})
	}
}
