package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

type fakeLifecycleWorker struct {
	mu       sync.Mutex
	doneCh   chan struct{}
	once     sync.Once
	reap     bool // whether kill proves a real Wait
	autoDone bool // whether kill closes done
	isReaped bool
	kills    int
	closes   int
	ready    *LifecycleReady
	respond  func(*LifecycleFrame) (*LifecycleFrame, error)
}

func newFakeLifecycleWorker(ready *LifecycleReady) *fakeLifecycleWorker {
	return &fakeLifecycleWorker{doneCh: make(chan struct{}), reap: true, autoDone: true, ready: copyLifecycleReady(ready)}
}
func (w *fakeLifecycleWorker) finish(reaped bool) {
	w.once.Do(func() {
		w.mu.Lock()
		w.isReaped = reaped
		w.mu.Unlock()
		close(w.doneCh)
	})
}
func (w *fakeLifecycleWorker) exchange(f *LifecycleFrame) (*LifecycleFrame, error) {
	w.mu.Lock()
	respond := w.respond
	w.mu.Unlock()
	if respond != nil {
		return respond(f)
	}
	reply := lifecycleSupervisorReply(f)
	reply.Ready = copyLifecycleReady(w.ready)
	return reply, nil
}
func (w *fakeLifecycleWorker) kill() error {
	w.mu.Lock()
	w.kills++
	auto, reap := w.autoDone, w.reap
	w.mu.Unlock()
	if auto {
		w.finish(reap)
	}
	return nil
}
func (w *fakeLifecycleWorker) done() <-chan struct{} { return w.doneCh }
func (w *fakeLifecycleWorker) reaped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.isReaped
}
func (w *fakeLifecycleWorker) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closes++
	return nil
}
func (w *fakeLifecycleWorker) counts() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.kills, w.closes
}

type fakeLifecycleStarter struct {
	mu      sync.Mutex
	calls   int
	last    *LifecycleReady
	current *fakeLifecycleWorker
	mutate  func(*LifecycleReady)
	block   chan struct{}
	entered chan struct{}
	fail    bool
}

func lifecycleTestHex(t testing.TB) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
func lifecycleTestID(t testing.TB) string {
	v, err := a.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return string(v)
}

func (f *fakeLifecycleStarter) start(t testing.TB) lifecycleWorkerStarter {
	return func(cfg LifecycleConfiguration, workerID string, gate workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
		f.mu.Lock()
		f.calls++
		block, entered, mutate, fail, last := f.block, f.entered, f.mutate, f.fail, f.last
		f.mu.Unlock()
		if entered != nil {
			entered <- struct{}{}
		}
		if block != nil {
			<-block
		}
		if fail {
			return nil, nil, errors.New("start")
		}
		ready := &LifecycleReady{Identity: cfg.Signed.Grant.Identity, ServiceEpoch: lifecycleTestID(t), WorkerUUID: workerID,
			ControllerEpoch: cfg.Signed.Grant.ExpectedEpoch + 1, ControllerKey: string(cfg.Signed.Grant.NewKey), Revision: 1, OpenRevision: 1,
			TLSRootDER: []byte(lifecycleTestHex(t)), ServerDER: []byte(lifecycleTestHex(t)), ServerSPKI: lifecycleTestHex(t)}
		root, _ := p.PublicKeyFingerprint(ed25519.PublicKey(cfg.RootPublicKey))
		ready.BootstrapKey = root.String()
		if last != nil {
			ready.Revision, ready.OpenRevision = last.Revision+2, last.OpenRevision+1
		}
		if mutate != nil {
			mutate(ready)
		}
		w := newFakeLifecycleWorker(ready)
		_ = gate(func() error { return nil }) // refusal after close must not suppress ownership
		f.mu.Lock()
		f.last, f.current = copyLifecycleReady(ready), w
		f.mu.Unlock()
		return w, ready, nil
	}
}
func (f *fakeLifecycleStarter) snapshot() (int, *fakeLifecycleWorker) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.current
}

func lifecycleSupervisorReply(f *LifecycleFrame) *LifecycleFrame {
	reply := lifecycleFrame("reply", f.Binding)
	seq := *f.Sequence
	reply.Sequence, reply.ServiceEpoch, reply.WorkerUUID = &seq, f.ServiceEpoch, f.WorkerUUID
	return &reply
}

var lifecycleTestSequence atomic.Uint64

func lifecycleSupervisorCommand(r *LifecycleReady, command string) *LifecycleFrame {
	f := lifecycleFrame("command", lifecycleTestBinding())
	seq := lifecycleTestSequence.Add(1)
	f.Sequence, f.ServiceEpoch, f.WorkerUUID, f.Command = &seq, r.ServiceEpoch, r.WorkerUUID, command
	return &f
}

func newTestLifecycleSupervisor(t testing.TB) (*lifecycleSupervisor, *fakeLifecycleStarter, LifecycleConfiguration) {
	cfg, _ := lifecycleTestConfig(t.(*testing.T))
	starter := &fakeLifecycleStarter{}
	s, err := newLifecycleSupervisor(cfg, starter.start(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	return s, starter, cfg
}

func lifecycleTestReplacement(t testing.TB, s *lifecycleSupervisor, cfg LifecycleConfiguration) LifecycleReplacementRequest {
	s.mu.Lock()
	ready, signed, now := copyLifecycleReady(s.ready), copyLifecycleSigned(s.signed), s.now
	s.mu.Unlock()
	reopen := lifecycleTestSignChange(t, p.LifecycleServiceChangeRequest{OperationID: lifecycleTestID(t), Predecessor: lifecycleServiceState(ready, signed.Grant)})
	return LifecycleReplacementRequest{PredecessorWorkerUUID: ready.WorkerUUID, Configuration: LifecycleConfiguration{
		Action: "open", RootPublicKey: bytes.Clone(cfg.RootPublicKey), Signed: signed, NowUnixSeconds: now + 1, LifetimeSeconds: cfg.LifetimeSeconds, Reopen: reopen}}
}

func waitLifecycleReplacement(t testing.TB, s *lifecycleSupervisor, r LifecycleReplacementRequest) *LifecycleReplacementStatus {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, code := s.replacementStatus(r.Configuration.Reopen.Request.Predecessor.Context.ServiceEpoch, r.PredecessorWorkerUUID)
		if code != "" {
			t.Fatalf("status %s", code)
		}
		if status.Phase != "pending" {
			return status
		}
		time.Sleep(50 * time.Microsecond)
	}
	t.Fatal("replacement did not finish")
	return nil
}

func TestLifecycleSupervisorExactRetriesLaunchOnceAndRecoverLostReply(t *testing.T) {
	s, starter, cfg := newTestLifecycleSupervisor(t)
	old := copyLifecycleReady(s.ready)
	request := lifecycleTestReplacement(t, s, cfg)
	status, code := s.replaceService(request)
	if code != "" || status.Phase != "pending" {
		t.Fatalf("%v %s", status, code)
	}
	retry, code := s.replaceService(request)
	if code != "" || (retry.Phase != "pending" && retry.Phase != "succeeded") {
		t.Fatalf("retry %v %s", retry, code)
	}
	done := waitLifecycleReplacement(t, s, request) // lost-reply recovery by predecessor pair
	if done.Phase != "succeeded" || done.Ready.WorkerUUID == old.WorkerUUID {
		t.Fatalf("%+v", done)
	}
	again, code := s.replaceService(request)
	if code != "" || again.Phase != "succeeded" || !reflect.DeepEqual(again, done) {
		t.Fatalf("terminal retry %v %s", again, code)
	}
	if calls, _ := starter.snapshot(); calls != 2 {
		t.Fatalf("starts %d", calls)
	}
	changed := request
	changed.Configuration.NowUnixSeconds++
	if _, code = s.replaceService(changed); code != "replacement-conflict" {
		t.Fatalf("changed bytes %s", code)
	}
	if _, code = s.replacementStatus(lifecycleTestID(t), old.WorkerUUID); code != "replacement-conflict" {
		t.Fatalf("inexact status %s", code)
	}
	st, code := s.status(done.Ready.ServiceEpoch, done.Ready.WorkerUUID)
	if code != "" || st.Phase != "ready" {
		t.Fatalf("%v %s", st, code)
	}
	if _, code = s.status(old.ServiceEpoch, old.WorkerUUID); code != "stale-worker" {
		t.Fatalf("old pair %s", code)
	}
}

func TestLifecycleSupervisorPendingRetryConflictAndDispatch(t *testing.T) {
	s, starter, cfg := newTestLifecycleSupervisor(t)
	starter.mu.Lock()
	starter.block = make(chan struct{})
	starter.mu.Unlock()
	request := lifecycleTestReplacement(t, s, cfg)
	frame := lifecycleSupervisorCommand(s.ready, "replace-service")
	frame.ReplacementRequest = &request
	if frame.validate() != nil {
		t.Fatal("invalid replace frame")
	}
	reply, code := s.dispatch(frame)
	if code != "" || reply.Replacement.Phase != "pending" || reply.validate() != nil {
		t.Fatalf("%v %s", reply, code)
	}
	changed := request
	changed.Configuration.LifetimeSeconds++
	if _, code = s.replaceService(changed); code != "replacement-conflict" {
		t.Fatalf("pending changed %s", code)
	}
	other := lifecycleTestReplacement(t, s, cfg)
	if _, code = s.replaceService(other); code != "worker-busy" {
		t.Fatalf("second op %s", code)
	}
	st, _ := s.status(request.Configuration.Reopen.Request.Predecessor.Context.ServiceEpoch, request.PredecessorWorkerUUID)
	if st.Phase != "replacing" {
		t.Fatal(st.Phase)
	}
	if _, code = s.command(lifecycleSupervisorCommand(s.ready, "query")); code != "worker-busy" {
		t.Fatalf("query during pending %s", code)
	}
	close(starter.block)
	if waitLifecycleReplacement(t, s, request).Phase != "succeeded" {
		t.Fatal("not succeeded")
	}
}

func TestLifecycleSupervisorNoStartBeforeReaped(t *testing.T) {
	s, starter, cfg := newTestLifecycleSupervisor(t)
	_, first := starter.snapshot()
	first.mu.Lock()
	first.autoDone = false
	first.mu.Unlock()
	request := lifecycleTestReplacement(t, s, cfg)
	if _, code := s.replaceService(request); code != "" {
		t.Fatal(code)
	}
	time.Sleep(20 * time.Millisecond)
	if calls, _ := starter.snapshot(); calls != 1 {
		t.Fatalf("started before reap: %d", calls)
	}
	if kills, _ := first.counts(); kills != 1 {
		t.Fatalf("kills %d", kills)
	}
	first.finish(true)
	if waitLifecycleReplacement(t, s, request).Phase != "succeeded" {
		t.Fatal("not succeeded")
	}
	if _, closes := first.counts(); closes != 1 {
		t.Fatalf("closes %d", closes)
	}
}

func TestLifecycleSupervisorUnreapedFailsWithoutStart(t *testing.T) {
	s, starter, cfg := newTestLifecycleSupervisor(t)
	_, first := starter.snapshot()
	first.mu.Lock()
	first.reap = false
	first.mu.Unlock()
	request := lifecycleTestReplacement(t, s, cfg)
	if _, code := s.replaceService(request); code != "" {
		t.Fatal(code)
	}
	done := waitLifecycleReplacement(t, s, request)
	if done.Phase != "failed" || done.Code != "worker-unreaped" {
		t.Fatalf("%+v", done)
	}
	if calls, _ := starter.snapshot(); calls != 1 {
		t.Fatalf("started %d", calls)
	}
	if _, closes := first.counts(); closes != 0 {
		t.Fatal("closed unreaped handle")
	}
	st, _ := s.status(request.Configuration.Reopen.Request.Predecessor.Context.ServiceEpoch, request.PredecessorWorkerUUID)
	if st.Phase != "failed" {
		t.Fatal(st.Phase)
	}
	if _, code := s.replaceService(lifecycleTestReplacement(t, s, cfg)); code != "stale-worker" {
		t.Fatalf("failed admitted %s", code)
	}
	if err := s.close(); err == nil {
		t.Fatal("uncertain reap accepted")
	}
	if kills, closes := first.counts(); kills < 2 || closes != 0 {
		t.Fatalf("close retained owner %d %d", kills, closes)
	}
}

func TestLifecycleSupervisorCloseRacingStartNeverPublishes(t *testing.T) {
	s, starter, cfg := newTestLifecycleSupervisor(t)
	old := copyLifecycleReady(s.ready)
	starter.mu.Lock()
	starter.block, starter.entered = make(chan struct{}), make(chan struct{}, 1)
	starter.mu.Unlock()
	request := lifecycleTestReplacement(t, s, cfg)
	if _, code := s.replaceService(request); code != "" {
		t.Fatal(code)
	}
	<-starter.entered
	closed := make(chan error, 1)
	go func() { closed <- s.close() }()
	for {
		s.mu.Lock()
		stopping := s.closed
		s.mu.Unlock()
		if stopping {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(starter.block)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, w := starter.snapshot()
		if w != nil && w.ready.WorkerUUID != old.WorkerUUID {
			if kills, closes := w.counts(); kills >= 1 && closes == 1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("returned owner not killed")
		}
		time.Sleep(time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready.WorkerUUID != old.WorkerUUID || s.terminal != nil || s.pending == nil {
		t.Fatal("published after close")
	}
}

func TestLifecycleSupervisorSuccessorValidationNegatives(t *testing.T) {
	cases := map[string]func(old *LifecycleReady, r *LifecycleReady){
		"same-epoch":         func(o, r *LifecycleReady) { r.ServiceEpoch = o.ServiceEpoch },
		"same-tls-root":      func(o, r *LifecycleReady) { r.TLSRootDER = bytes.Clone(o.TLSRootDER) },
		"same-server-key":    func(o, r *LifecycleReady) { r.ServerSPKI = o.ServerSPKI },
		"same-server-der":    func(o, r *LifecycleReady) { r.ServerDER = bytes.Clone(o.ServerDER) },
		"lower-open":         func(o, r *LifecycleReady) { r.OpenRevision = o.OpenRevision },
		"same-revision":      func(o, r *LifecycleReady) { r.Revision = o.Revision },
		"wrong-controller":   func(o, r *LifecycleReady) { r.ControllerKey = lifecycleTestHex(t) },
		"wrong-epoch":        func(o, r *LifecycleReady) { r.ControllerEpoch++ },
		"same-worker":        func(o, r *LifecycleReady) { r.WorkerUUID = o.WorkerUUID },
		"wrong-identity":     func(o, r *LifecycleReady) { r.Identity.Generation++ },
		"wrong-bootstrapkey": func(o, r *LifecycleReady) { r.BootstrapKey = lifecycleTestHex(t) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, starter, cfg := newTestLifecycleSupervisor(t)
			old := copyLifecycleReady(s.ready)
			starter.mu.Lock()
			starter.mutate = func(r *LifecycleReady) { mutate(old, r) }
			starter.mu.Unlock()
			request := lifecycleTestReplacement(t, s, cfg)
			if _, code := s.replaceService(request); code != "" {
				t.Fatal(code)
			}
			done := waitLifecycleReplacement(t, s, request)
			if done.Phase != "failed" || done.Code != "replacement-failed" {
				t.Fatalf("%+v", done)
			}
			calls, w := starter.snapshot()
			if calls != 2 {
				t.Fatalf("retried start %d", calls)
			}
			if kills, _ := w.counts(); kills != 1 {
				t.Fatal("successor not killed")
			}
			s.mu.Lock()
			if s.ready.WorkerUUID != old.WorkerUUID || s.worker != w || !s.failed {
				s.mu.Unlock()
				t.Fatal("published invalid successor or lost owner")
			}
			s.mu.Unlock()
		})
	}
	t.Run("start-error", func(t *testing.T) {
		s, starter, cfg := newTestLifecycleSupervisor(t)
		starter.mu.Lock()
		starter.fail = true
		starter.mu.Unlock()
		request := lifecycleTestReplacement(t, s, cfg)
		_, _ = s.replaceService(request)
		if done := waitLifecycleReplacement(t, s, request); done.Code != "replacement-failed" {
			t.Fatal(done.Code)
		}
	})
}

func TestLifecycleSupervisorAdmissionScope(t *testing.T) {
	s, _, cfg := newTestLifecycleSupervisor(t)
	cases := map[string]func(*LifecycleReplacementRequest){
		"bad-signature": func(r *LifecycleReplacementRequest) {
			r.Configuration.Signed.Signature = bytes.Repeat([]byte{1}, 64)
		},
		"wrong-worker": func(r *LifecycleReplacementRequest) { r.PredecessorWorkerUUID = lifecycleTestID(t) },
		"wrong-open":   func(r *LifecycleReplacementRequest) { r.Configuration.Reopen.Request.Predecessor.OpenRevision++ },
		"wrong-tls": func(r *LifecycleReplacementRequest) {
			r.Configuration.Reopen.Request.Predecessor.Boot.TLSRootSHA256 = lifecycleTestHex(t)
		},
		"clock-regress": func(r *LifecycleReplacementRequest) { r.Configuration.NowUnixSeconds = 1 },
		// Valid shape but no ROOT authorization of the change: never re-signed.
		"sig-forged": func(r *LifecycleReplacementRequest) { r.Configuration.Reopen.Signature[0] ^= 1 },
		"sig-absent": func(r *LifecycleReplacementRequest) { r.Configuration.Reopen.Signature = nil },
	}
	for name, mutate := range cases {
		request := lifecycleTestReplacement(t, s, cfg)
		mutate(&request)
		if name[:4] != "sig-" {
			request.Configuration.Reopen = lifecycleTestSignChange(t, request.Configuration.Reopen.Request)
		}
		if _, code := s.replaceService(request); code == "" {
			t.Fatalf("%s admitted", name)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil || s.terminal != nil {
		t.Fatal("rejected request retained")
	}
}

func lifecycleTakeover(t *testing.T, cfg LifecycleConfiguration, epoch uint64) (a.SignedLifecycleGrant, a.Controller) {
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	g := cfg.Signed.Grant
	g.Operation, g.ID, g.Serial, g.ExpectedEpoch, g.NewKey = a.LifecycleTakeover, a.ID(lifecycleTestID(t)), 5, epoch, a.Fingerprint(lifecycleTestHex(t))
	b, err := a.LifecycleGrantSigningBytes(g)
	if err != nil {
		t.Fatal(err)
	}
	return a.SignedLifecycleGrant{Grant: g, Signature: ed25519.Sign(root, b)}, a.Controller{Epoch: epoch + 1, Key: g.NewKey}
}

func TestLifecycleSupervisorReconcileRequiresAuthorizedSuccessor(t *testing.T) {
	s, starter, cfg := newTestLifecycleSupervisor(t)
	_, w := starter.snapshot()
	signed, controller := lifecycleTakeover(t, cfg, 1)
	adopted := copyLifecycleReady(s.ready)
	adopted.ControllerEpoch, adopted.ControllerKey, adopted.Revision = controller.Epoch, string(controller.Key), adopted.Revision+1
	w.mu.Lock()
	w.ready = copyLifecycleReady(adopted) // worker already applied the takeover
	w.mu.Unlock()

	reconcile := func() (*LifecycleFrame, string) {
		f := lifecycleSupervisorCommand(s.ready, "reconcile-controller")
		f.Signed, f.Controller = &signed, &controller
		return s.command(f)
	}
	if _, code := reconcile(); code != "command" {
		t.Fatalf("unauthorized reconcile %s", code)
	}
	if _, code := s.command(lifecycleSupervisorCommand(s.ready, "query")); code != "command" {
		t.Fatalf("query adopted %s", code)
	}
	// A failed authorize-successor reply must not retain the grant.
	w.mu.Lock()
	w.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		r := lifecycleSupervisorReply(f)
		r.Code = "service"
		return r, nil
	}
	w.mu.Unlock()
	authorize := lifecycleSupervisorCommand(s.ready, "authorize-successor")
	authorize.Signed, authorize.CSR = &signed, []byte("csr")
	if reply, code := s.command(authorize); code != "" || reply.Code != "service" || s.successor != nil {
		t.Fatal("failed authorize retained")
	}
	w.mu.Lock()
	w.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		r := lifecycleSupervisorReply(f)
		r.Certificate = []byte("cert")
		return r, nil
	}
	w.mu.Unlock()
	authorize = lifecycleSupervisorCommand(s.ready, "authorize-successor")
	authorize.Signed, authorize.CSR = &signed, []byte("csr")
	if _, code := s.command(authorize); code != "" {
		t.Fatal(code)
	}
	if _, code := s.replaceService(lifecycleTestReplacement(t, s, cfg)); code != "worker-busy" {
		t.Fatalf("replace with successor pending %s", code)
	}
	w.mu.Lock()
	w.respond = nil
	w.mu.Unlock()
	if _, code := reconcile(); code != "" {
		t.Fatal(code)
	}
	s.mu.Lock()
	if !lifecycleSignedEqual(s.signed, signed) || s.successor != nil || s.ready.ControllerKey != string(controller.Key) {
		s.mu.Unlock()
		t.Fatal("not committed")
	}
	s.mu.Unlock()
	if _, code := reconcile(); code != "" { // exact retry of current grant
		t.Fatalf("retry %s", code)
	}
	if _, code := s.command(lifecycleSupervisorCommand(s.ready, "query")); code != "" {
		t.Fatalf("query after reconcile %s", code)
	}
	request := lifecycleTestReplacement(t, s, cfg)
	if _, code := s.replaceService(request); code != "" {
		t.Fatal(code)
	}
	if done := waitLifecycleReplacement(t, s, request); done.Phase != "succeeded" || done.Ready.ControllerKey != string(controller.Key) {
		t.Fatalf("%+v", done)
	}
}

func TestLifecycleSupervisorQueryCannotChangeServiceIdentity(t *testing.T) {
	s, starter, _ := newTestLifecycleSupervisor(t)
	_, w := starter.snapshot()
	w.mu.Lock()
	w.ready.OpenRevision++
	w.ready.Revision++
	w.mu.Unlock()
	if _, code := s.command(lifecycleSupervisorCommand(s.ready, "query")); code != "worker-lost" {
		t.Fatalf("open revision changed %s", code)
	}
	st, _ := s.status(s.ready.ServiceEpoch, s.ready.WorkerUUID)
	if st.Phase != "worker-lost" {
		t.Fatal(st.Phase)
	}
}

func lifecycleTestNotification(r *LifecycleReady) a.DataHello {
	return a.DataHello{Epoch: a.ID(r.ServiceEpoch), Binding: a.Binding{
		Store: r.Identity.Store, Volume: "dddddddd-dddd-4ddd-9ddd-dddddddddddd", Attachment: "eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee",
		Container: a.ContainerID(r.ServerSPKI), Launch: "ffffffff-ffff-4fff-bfff-ffffffffffff", Key: a.Fingerprint(r.BootstrapKey),
		Role: a.RuntimeRole, Mode: a.ReadWrite,
	}}
}

func TestLifecycleSupervisorNotificationsBindCurrentReady(t *testing.T) {
	ok := true
	for name, tc := range map[string]struct {
		mutate func(*LifecycleFrame, *LifecycleReady)
		code   string
	}{
		"current entries": {func(r *LifecycleFrame, ready *LifecycleReady) {
			list := []a.DataHello{lifecycleTestNotification(ready), lifecycleTestNotification(ready)}
			r.Notifications = &list
		}, ""},
		"empty list":      {func(r *LifecycleFrame, _ *LifecycleReady) { list := []a.DataHello{}; r.Notifications = &list }, ""},
		"missing payload": {func(r *LifecycleFrame, _ *LifecycleReady) { r.OK = &ok }, "worker-lost"},
		"foreign envelope": {func(r *LifecycleFrame, ready *LifecycleReady) {
			list := []a.DataHello{}
			r.Notifications, r.ServiceEpoch = &list, lifecycleTestID(t)
		}, "worker-lost"},
		"stale entry epoch": {func(r *LifecycleFrame, ready *LifecycleReady) {
			n := lifecycleTestNotification(ready)
			n.Epoch = a.ID(lifecycleTestID(t))
			list := []a.DataHello{lifecycleTestNotification(ready), n}
			r.Notifications = &list
		}, "worker-lost"},
		"foreign entry store": {func(r *LifecycleFrame, ready *LifecycleReady) {
			n := lifecycleTestNotification(ready)
			n.Binding.Store = a.ID(lifecycleTestID(t))
			list := []a.DataHello{n}
			r.Notifications = &list
		}, "worker-lost"},
	} {
		s, starter, _ := newTestLifecycleSupervisor(t)
		_, w := starter.snapshot()
		ready := copyLifecycleReady(s.ready)
		w.mu.Lock()
		w.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
			r := lifecycleSupervisorReply(f)
			tc.mutate(r, ready)
			return r, nil
		}
		w.mu.Unlock()
		reply, code := s.command(lifecycleSupervisorCommand(ready, "notifications"))
		if code != tc.code {
			t.Fatalf("%s: %q", name, code)
		}
		if code == "" && (reply == nil || reply.Notifications == nil) {
			t.Fatalf("%s: no payload", name)
		}
		if code != "" {
			if st, _ := s.status(ready.ServiceEpoch, ready.WorkerUUID); st.Phase != "worker-lost" {
				t.Fatalf("%s: %s", name, st.Phase)
			}
		}
	}
}

func TestLifecycleSupervisorBoundedAcrossManyReplacements(t *testing.T) {
	typ := reflect.TypeOf(lifecycleSupervisor{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() == reflect.Map || f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() != reflect.Uint8 || f.Type.Kind() == reflect.Array {
			t.Fatalf("unbounded field %s", f.Name)
		}
	}
	s, starter, cfg := newTestLifecycleSupervisor(t)
	n := 5000
	if testing.Short() {
		n = 200
	}
	for i := 0; i < n; i++ {
		request := lifecycleTestReplacement(t, s, cfg)
		if _, code := s.replaceService(request); code != "" {
			t.Fatalf("%d %s", i, code)
		}
		if done := waitLifecycleReplacement(t, s, request); done.Phase != "succeeded" {
			t.Fatalf("%d %+v", i, done)
		}
	}
	if calls, _ := starter.snapshot(); calls != n+1 {
		t.Fatalf("starts %d", calls)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	digest := sha256.Sum256(s.ready.TLSRootDER)
	if s.pending != nil || s.terminal == nil || s.successor != nil || len(s.root) != ed25519.PublicKeySize || len(s.signed.Signature) != 64 ||
		s.terminal.Request.Configuration.Reopen.Request.Predecessor.Boot.TLSRootSHA256 == hex.EncodeToString(digest[:]) {
		t.Fatal("state grew or stale terminal")
	}
}
