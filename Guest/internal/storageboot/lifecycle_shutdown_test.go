package storageboot

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type shutdownReadResult struct {
	net.Conn
	readErr     error
	deadlineErr error
}

func (c shutdownReadResult) Read([]byte) (int, error)        { return 0, c.readErr }
func (c shutdownReadResult) SetReadDeadline(time.Time) error { return c.deadlineErr }

func TestLifecycleOwnerEOFRequiresReadObservation(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		readErr, deadlineErr error
		uncertain            bool
	}{
		{"eof", io.EOF, nil, false},
		{"peer-closed-before-deadline-clear", io.EOF, io.ErrClosedPipe, false},
		{"local-transport-fault", io.ErrClosedPipe, nil, true},
		{"timeout-is-not-eof", errors.New("timeout"), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := awaitLifecycleOwnerEOF(shutdownReadResult{readErr: tc.readErr, deadlineErr: tc.deadlineErr})
			if errors.Is(err, ErrShutdownUncertain) != tc.uncertain {
				t.Fatal(err)
			}
			if !tc.uncertain && !errors.Is(err, io.EOF) {
				t.Fatal("missing actual EOF", err)
			}
		})
	}
}

func TestLifecyclePrivateEOFBeforeConfigureStartsNoWorker(t *testing.T) {
	host, guest := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- lifecycleSession(context.Background(), guest, lifecycleTestBinding(), func(LifecycleConfiguration, string, workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
			t.Error("started without configuration")
			return nil, nil, errors.New("unexpected start")
		}, time.Second)
	}()
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	host.Close()
	if err := <-done; !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestLifecyclePrivateFailureWaitsForWorkerReap(t *testing.T) {
	for _, failConstruction := range []bool{false, true} {
		name := "ready-write-failure"
		if failConstruction {
			name = "configuration-failure"
		}
		t.Run(name, func(t *testing.T) {
			_, starter, cfg := newTestLifecycleSupervisor(t)
			host, guest := net.Pipe()
			defer host.Close()
			started := make(chan *fakeLifecycleWorker, 1)
			done := make(chan error, 1)
			start := starter.start(t)
			go func() {
				done <- lifecycleSession(context.Background(), guest, lifecycleTestBinding(), func(c LifecycleConfiguration, id string, gate workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
					w, ready, err := start(c, id, gate)
					worker := w.(*fakeLifecycleWorker)
					worker.mu.Lock()
					worker.autoDone = false
					worker.mu.Unlock()
					started <- worker
					if failConstruction {
						return w, nil, errors.New("construction failed")
					}
					return w, ready, err
				}, time.Second)
			}()
			if _, err := ReadLifecycleFrame(host); err != nil {
				t.Fatal(err)
			}
			configure := lifecycleFrame("configure", lifecycleTestBinding())
			configure.Configuration = &cfg
			if err := WriteLifecycleFrame(host, &configure); err != nil {
				t.Fatal(err)
			}
			worker := <-started
			host.Close() // actual private owner EOF, including failed Ready write
			deadline := time.After(time.Second)
			for {
				if kills, _ := worker.counts(); kills > 0 {
					break
				}
				select {
				case <-deadline:
					t.Fatal("worker not killed")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			select {
			case <-done:
				t.Fatal("unwound before reaping")
			default:
			}
			worker.finish(true)
			if err := <-done; err == nil {
				t.Fatal("expected private session failure")
			}
			if _, closes := worker.counts(); closes != 1 {
				t.Fatal("worker not closed", closes)
			}
		})
	}
}

func TestLifecyclePrivateReadyFaultWaitsForActualOwnerEOF(t *testing.T) {
	_, starter, cfg := newTestLifecycleSupervisor(t)
	host, guest := net.Pipe()
	defer host.Close()
	done := make(chan error, 1)
	go func() {
		done <- lifecycleSession(context.Background(), guest, lifecycleTestBinding(), starter.start(t), time.Second)
	}()
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	configure := lifecycleFrame("configure", lifecycleTestBinding())
	configure.Configuration = &cfg
	if err := WriteLifecycleFrame(host, &configure); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	_, worker := starter.snapshot()
	// Validly encoded but invalid as a post-Ready command. This is a local
	// protocol fault, not evidence that the persistent owner has left.
	if err := WriteLifecycleFrame(host, &configure); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("local fault terminated working service")
	case <-time.After(20 * time.Millisecond):
	}
	if kills, closes := worker.counts(); kills != 0 || closes != 0 {
		t.Fatal("retired without private EOF", kills, closes)
	}
	host.Close()
	if err := <-done; err == nil || errors.Is(err, ErrShutdownUncertain) {
		t.Fatal(err)
	}
	if kills, closes := worker.counts(); kills == 0 || closes != 1 {
		t.Fatal("EOF did not join worker", kills, closes)
	}
}

// The idle command read clears its deadline, then arms a positive deadline
// after the first byte. The next clear is the post-fault owner-EOF drain.
// Cancel exactly there, without sleeps or treating local close as peer exit.
type cancelDuringOwnerDrain struct {
	net.Conn
	cancel context.CancelFunc
	armed  bool
	drain  bool
}

func (c *cancelDuringOwnerDrain) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() && c.armed {
		c.drain = true
		c.cancel()
	} else if !deadline.IsZero() {
		c.armed = true
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *cancelDuringOwnerDrain) Read(p []byte) (int, error) {
	if c.drain {
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Read(p)
}

func TestLifecycleCancellationDuringOwnerDrainPreservesUncertainty(t *testing.T) {
	_, starter, cfg := newTestLifecycleSupervisor(t)
	host, guest := net.Pipe()
	defer host.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- lifecycleSession(ctx, &cancelDuringOwnerDrain{Conn: guest, cancel: cancel},
			lifecycleTestBinding(), starter.start(t), time.Second)
	}()
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	configure := lifecycleFrame("configure", lifecycleTestBinding())
	configure.Configuration = &cfg
	if err := WriteLifecycleFrame(host, &configure); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	if err := WriteLifecycleFrame(host, &configure); err != nil {
		t.Fatal(err)
	}
	err := <-done
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrShutdownUncertain) {
		t.Fatal("cancellation discarded uncertain owner EOF", err)
	}
}

func TestLifecyclePrivateUncertainReapRetainsOwner(t *testing.T) {
	_, starter, cfg := newTestLifecycleSupervisor(t)
	host, guest := net.Pipe()
	defer host.Close()
	done := make(chan error, 1)
	start := starter.start(t)
	go func() {
		done <- lifecycleSession(context.Background(), guest, lifecycleTestBinding(), func(c LifecycleConfiguration, id string, gate workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
			w, ready, err := start(c, id, gate)
			worker := w.(*fakeLifecycleWorker)
			worker.mu.Lock()
			worker.reap = false
			worker.mu.Unlock()
			return w, ready, err
		}, time.Second)
	}()
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	configure := lifecycleFrame("configure", lifecycleTestBinding())
	configure.Configuration = &cfg
	if err := WriteLifecycleFrame(host, &configure); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	host.Close()
	err := <-done
	if !errors.Is(err, ErrShutdownUncertain) {
		t.Fatal("uncertain reap lost marker", err)
	}
	var retained *lifecycleShutdownUncertain
	if !errors.As(err, &retained) || len(retained.owners) != 1 {
		t.Fatal("worker ownership not retained")
	}
	_, worker := starter.snapshot()
	if _, closes := worker.counts(); closes != 0 {
		t.Fatal("closed uncertain process owner")
	}
}

func TestLifecycleShutdownWaitsForPositiveReapWithoutHoldingMutex(t *testing.T) {
	s, starter, _ := newTestLifecycleSupervisor(t)
	_, worker := starter.snapshot()
	worker.mu.Lock()
	worker.autoDone = false
	worker.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- s.close() }()
	deadline := time.After(time.Second)
	for {
		kills, closes := worker.counts()
		if closes != 0 {
			t.Fatal("closed before Wait")
		}
		if kills != 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("shutdown did not kill")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	admission := make(chan bool, 1)
	go func() { s.mu.Lock(); admission <- s.closed; s.mu.Unlock() }()
	select {
	case closed := <-admission:
		if !closed {
			t.Fatal("admission remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("mutex held across wait")
	}
	select {
	case <-done:
		t.Fatal("returned before Wait")
	default:
	}
	worker.finish(true)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, closes := worker.counts(); closes != 1 {
		t.Fatal("worker not closed after reap", closes)
	}
}
