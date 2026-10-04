package storageboot

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	a "dev.cengine/guest/internal/storageauthority"
	s "dev.cengine/guest/internal/storageservice"
)

// inProcessLifecycle is the test seam replacing the process launch: the real
// start packet codec, serveLifecycleWorker and lifecyclePacketWorker run over
// channels instead of storageworker's FD3 transport.
type inProcessLifecycle struct {
	mu   sync.Mutex
	errs []error
	wg   sync.WaitGroup
}

func (ip *inProcessLifecycle) starter(root *os.File, binding diskbootstrap.StorageBinding, fresh func() error, services func(*s.LifecycleService) (func() error, error)) lifecycleWorkerStarter {
	return ip.starterWithResume(root, binding, fresh, services, &lifecycleResumeGate{})
}

func (ip *inProcessLifecycle) starterWithResume(root *os.File, binding diskbootstrap.StorageBinding, fresh func() error, services func(*s.LifecycleService) (func() error, error), resume *lifecycleResumeGate) lifecycleWorkerStarter {
	gate := &lifecycleFreshGate{fresh: fresh}
	return func(cfg LifecycleConfiguration, workerID string, startGate workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
		if cfg.validate() != nil || !lifecycleRootSigned(cfg.RootPublicKey, cfg.Signed) {
			return nil, nil, errors.New("configuration")
		}
		verifiedResume, err := resume.take(cfg)
		if err != nil {
			return nil, nil, err
		}
		verifiedFresh, err := gate.take(cfg.Action)
		if err != nil {
			return nil, nil, err
		}
		raw, err := encodeLifecycleWorkerStart(lifecycleWorkerStart{Version: 2, Type: lifecycleWorkerType, Operation: "start", WorkerUUID: workerID,
			Binding: binding, Root: workerRootIdentity{1, 1, 1}, Configuration: cfg, ManagementAddress: "127.0.0.1", VerifiedFresh: verifiedFresh, VerifiedResume: verifiedResume})
		if err != nil {
			return nil, nil, err
		}
		toWorker, fromWorker := make(chan []byte), make(chan []byte)
		killed, done := make(chan struct{}), make(chan struct{})
		var killOnce sync.Once
		ip.wg.Add(1)
		if err = startGate(func() error {
			go func() {
				defer ip.wg.Done()
				defer close(done)
				h, err := decodeLifecycleWorkerStart(raw)
				if err == nil {
					err = serveLifecycleWorker(root, h, services, func(b []byte) error {
						select {
						case fromWorker <- b:
							return nil
						case <-killed:
							return errors.New("killed")
						}
					}, func() ([]byte, error) {
						select {
						case b := <-toWorker:
							return b, nil
						case <-killed:
							return nil, errors.New("killed")
						}
					})
				}
				ip.mu.Lock()
				ip.errs = append(ip.errs, err)
				ip.mu.Unlock()
			}()
			return nil
		}); err != nil {
			ip.wg.Done()
			return nil, nil, err
		}
		w := &lifecyclePacketWorker{binding: binding, doneCh: done, closef: func() error { return nil },
			killf:   func() error { killOnce.Do(func() { close(killed) }); return nil },
			reapedf: func() bool { return lifecycleWorkerExited(&lifecyclePacketWorker{doneCh: done}) },
			send: func(p []byte) ([]byte, error) {
				select {
				case toWorker <- p:
				case <-done:
					return nil, errors.New("lost")
				}
				select {
				case r := <-fromWorker:
					return r, nil
				case <-done:
					return nil, errors.New("lost")
				}
			}}
		select {
		case r := <-fromWorker:
			ready, err := readLifecycleWorkerReady(r, binding, workerID)
			return w, ready, err
		case <-done:
			return w, nil, errors.New("worker-lost")
		}
	}
}

// lifecycleSessionInProcess runs the production session with the in-process
// worker, then joins every worker and reports their errors with the session's.
func lifecycleSessionInProcess(ctx context.Context, conn net.Conn, root *os.File, binding diskbootstrap.StorageBinding, fresh func() error, services func(*s.LifecycleService) (func() error, error), budget time.Duration) error {
	ip := &inProcessLifecycle{}
	var start lifecycleWorkerStarter
	if root != nil {
		start = ip.starter(root, binding, fresh, services)
	}
	err := lifecycleSession(ctx, conn, binding, start, budget)
	ip.wg.Wait()
	ip.mu.Lock()
	defer ip.mu.Unlock()
	return errors.Join(append([]error{err}, ip.errs...)...)
}

func lifecycleTestStart(t *testing.T) lifecycleWorkerStart {
	cfg, _ := lifecycleTestConfig(t)
	return lifecycleWorkerStart{Version: 2, Type: lifecycleWorkerType, Operation: "start", WorkerUUID: lifecycleTestID(t),
		Binding: lifecycleTestBinding(), Root: workerRootIdentity{1, 2, 3}, Configuration: cfg, ManagementAddress: "10.0.0.2", VerifiedFresh: true}
}

func TestLifecycleWorkerStartPacketClosed(t *testing.T) {
	h := lifecycleTestStart(t)
	raw, err := encodeLifecycleWorkerStart(h)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeLifecycleWorkerStart(raw); err != nil || got.WorkerUUID != h.WorkerUUID || !got.VerifiedFresh {
		t.Fatal("round trip", err)
	}
	text := string(raw)
	for name, bad := range map[string]string{
		"unknown":   strings.Replace(text, `{"binding"`, `{"extra":1,"binding"`, 1),
		"duplicate": strings.Replace(text, `{"binding"`, `{"version":2,"binding"`, 1),
		"space":     strings.Replace(text, `,"type"`, `, "type"`, 1),
		"trailing":  text + " ",
		"version":   strings.Replace(text, `"version":2`, `"version":1`, 1),
		"operation": strings.Replace(text, `"operation":"start"`, `"operation":"challenge"`, 1),
		"fresh":     strings.Replace(text, `"verifiedFresh":true`, `"verifiedFresh":false`, 1),
		"root":      strings.Replace(text, `"device":1`, `"device":0`, 1),
		"address":   strings.Replace(text, `"10.0.0.2"`, `"0.0.0.0"`, 1),
		"empty":     "",
	} {
		if bad == text && name != "trailing" {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := decodeLifecycleWorkerStart([]byte(bad)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// verifiedFresh is only PID1's initialize evidence: never on open.
	open := h
	open.VerifiedFresh = false
	if _, err := encodeLifecycleWorkerStart(open); err == nil {
		t.Fatal("initialize without fresh evidence encoded")
	}
	h.Configuration.Signed.Signature[0] ^= 1
	if _, err := encodeLifecycleWorkerStart(h); err == nil {
		t.Fatal("unsigned configuration encoded")
	}
}

func TestLifecycleFreshGateConsumedOnceOnlyForInitialize(t *testing.T) {
	calls := 0
	g := &lifecycleFreshGate{fresh: func() error { calls++; return nil }}
	if ok, err := g.take("open"); ok || err != nil || calls != 0 {
		t.Fatal("open consumed fresh")
	}
	if ok, err := g.take("initialize"); !ok || err != nil || calls != 1 {
		t.Fatal("initialize did not consume fresh")
	}
	if ok, err := g.take("initialize"); ok || err == nil || calls != 1 {
		t.Fatal("fresh consumed twice")
	}
	failing := &lifecycleFreshGate{fresh: func() error { return errors.New("stale") }}
	if ok, err := failing.take("initialize"); ok || err == nil {
		t.Fatal("failed fresh admitted")
	}
}

func TestLifecycleWorkerConstructRequiresVerifiedFresh(t *testing.T) {
	dir := t.TempDir()
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	h := lifecycleTestStart(t)
	h.VerifiedFresh = false
	if _, err := lifecycleWorkerConstruct(root, &h); err == nil {
		t.Fatal("initialize without PID1 fresh evidence constructed")
	}
	h.Configuration.Signed.Signature[0] ^= 1
	h.VerifiedFresh = true
	if _, err := lifecycleWorkerConstruct(root, &h); err == nil {
		t.Fatal("unsigned configuration constructed")
	}
	if _, err := os.Stat(filepath.Join(dir, "volumes")); !os.IsNotExist(err) {
		t.Fatal("filesystem mutated before verification")
	}
	h.Configuration.Signed.Signature[0] ^= 1
	service, err := lifecycleWorkerConstruct(root, &h)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

// Keep the service idle so its own active-work checks cannot mask an unwanted
// Close after an incomplete endpoint join (e.g. a handler before admission).
func TestLifecycleWorkerStopControlsServiceClose(t *testing.T) {
	stopFailure := errors.New("stop failure")
	for _, tc := range []struct {
		name    string
		stopErr error
		busy    bool
	}{
		{"joined", nil, false},
		{"joined-with-error", stopFailure, false},
		{"busy", a.ErrBusy, true},
		{"joined-error-and-busy", errors.Join(stopFailure, a.ErrBusy), true},
	} {
		for _, phase := range []string{"receive", "start"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				root, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				h := lifecycleTestStart(t)
				failure := errors.New(phase + " failure")
				var owner *s.LifecycleService
				stops, sends := 0, 0
				err = serveLifecycleWorker(root, &h, func(service *s.LifecycleService) (func() error, error) {
					owner = service
					stop := func() error {
						stops++
						if _, err := service.Scope(); err != nil {
							t.Error("service closed before stop", err)
						}
						return tc.stopErr
					}
					if phase == "start" {
						return stop, failure
					}
					return stop, nil
				}, func([]byte) error {
					sends++
					return nil
				}, func() ([]byte, error) { return nil, failure })
				if owner == nil {
					t.Fatal("service not constructed", err)
				}
				defer func() {
					if err := owner.Close(); err != nil {
						t.Error("test cleanup", err)
					}
				}()
				if !errors.Is(err, failure) || (tc.stopErr != nil && !errors.Is(err, tc.stopErr)) {
					t.Fatal("lost worker or stop error", err)
				}
				if stops != 1 || (phase == "start" && sends != 0) || (phase == "receive" && sends != 1) {
					t.Fatalf("unexpected stop/Ready counts: %d/%d", stops, sends)
				}
				_, scopeErr := owner.Scope()
				if tc.busy {
					if scopeErr != nil {
						t.Fatal("incomplete join closed the service", scopeErr)
					}
				} else if !errors.Is(scopeErr, a.ErrClosed) {
					t.Fatal("completed join did not close the service", scopeErr)
				}
			})
		}
	}
}

func TestLifecycleSessionDispatchesThroughSupervisor(t *testing.T) {
	cfg, _ := lifecycleTestConfig(t)
	b := lifecycleTestBinding()
	starter := &fakeLifecycleStarter{}
	host, guest := net.Pipe()
	defer host.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- lifecycleSession(ctx, guest, b, starter.start(t), time.Second) }()
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	config := lifecycleFrame("configure", b)
	config.Configuration = &cfg
	if err := WriteLifecycleFrame(host, &config); err != nil {
		t.Fatal(err)
	}
	ready, err := ReadLifecycleFrame(host)
	if err != nil {
		t.Fatal(err)
	}
	calls, worker := starter.snapshot()
	if calls != 1 || ready.Operation != "ready" || ready.Ready.WorkerUUID != worker.ready.WorkerUUID {
		t.Fatal("ready is not the first worker Ready")
	}
	var mu sync.Mutex
	fail := false
	worker.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return nil, errors.New("lost")
		}
		r := lifecycleSupervisorReply(f)
		r.Ready = copyLifecycleReady(ready.Ready)
		return r, nil
	}
	sequence := uint64(0)
	send := func(command, workerID string) *LifecycleFrame {
		t.Helper()
		sequence++
		seq := sequence
		f := lifecycleFrame("command", b)
		f.Sequence, f.ServiceEpoch, f.WorkerUUID, f.Command = &seq, ready.Ready.ServiceEpoch, workerID, command
		if command == "issue-controller" {
			f.CSR = []byte{1}
		}
		if err := WriteLifecycleFrame(host, &f); err != nil {
			t.Fatal(err)
		}
		reply, err := ReadLifecycleFrame(host)
		if err != nil || reply.Operation != "reply" || *reply.Sequence != seq || reply.WorkerUUID != workerID {
			t.Fatal("reply envelope", err)
		}
		return reply
	}
	if r := send("query", ready.Ready.WorkerUUID); r.Code != "" || r.Ready == nil || r.Ready.ServiceEpoch != ready.Ready.ServiceEpoch {
		t.Fatal("query not forwarded", r.Code)
	}
	if r := send("service-status", ready.Ready.WorkerUUID); r.Status == nil || r.Status.Phase != "ready" {
		t.Fatal("status not answered by supervisor")
	}
	if r := send("query", lifecycleTestID(t)); r.Code != "stale-worker" {
		t.Fatal("stale worker admitted", r.Code)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	if r := send("issue-controller", ready.Ready.WorkerUUID); r.Code != "worker-lost" {
		t.Fatal("lost worker hidden", r.Code)
	}
	if r := send("query", ready.Ready.WorkerUUID); r.Code != "worker-lost" {
		t.Fatal("lost state not retained", r.Code)
	}
	bad := lifecycleFrame("command", b)
	wrong := sequence + 2
	bad.Sequence, bad.ServiceEpoch, bad.WorkerUUID, bad.Command = &wrong, ready.Ready.ServiceEpoch, ready.Ready.WorkerUUID, "query"
	if err := WriteLifecycleFrame(host, &bad); err != nil {
		t.Fatal(err)
	}
	// Sequence rejection alone is not owner death; the persistent owner
	// closes its private channel before orderly worker retirement.
	_ = host.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("sequence gap accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session did not end")
	}
	if kills, closes := worker.counts(); kills == 0 || closes == 0 {
		t.Fatal("session exit did not close supervisor-owned worker")
	}
}

func TestLifecycleSessionRejectsUnsignedBeforeStart(t *testing.T) {
	cfg, _ := lifecycleTestConfig(t)
	cfg.Signed.Signature[0] ^= 1
	b := lifecycleTestBinding()
	starter := &fakeLifecycleStarter{}
	host, guest := net.Pipe()
	defer host.Close()
	done := make(chan error, 1)
	go func() { done <- lifecycleSession(context.Background(), guest, b, starter.start(t), time.Second) }()
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	config := lifecycleFrame("configure", b)
	config.Configuration = &cfg
	if err := WriteLifecycleFrame(host, &config); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("unsigned configuration accepted")
	}
	if calls, _ := starter.snapshot(); calls != 0 {
		t.Fatal("worker started before signature verification")
	}
}
