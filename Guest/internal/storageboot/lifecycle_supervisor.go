package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// lifecycleWorker is the v2 process-ownership seam. reaped must be based on the
// sole real Wait, never EOF, a signal or cancellation.
type lifecycleWorker interface {
	exchange(*LifecycleFrame) (*LifecycleFrame, error)
	kill() error
	done() <-chan struct{}
	reaped() bool
	close() error
}

// lifecycleWorkerStarter launches exactly once per call with the exact
// configuration; the supervisor never retries a start.
type lifecycleWorkerStarter func(LifecycleConfiguration, string, workerStartGate) (lifecycleWorker, *LifecycleReady, error)

// lifecycleSupervisor retains bounded state only: no history, seen sets or caps.
// Internal codes (stale-worker, worker-busy, worker-lost, replacement-conflict,
// command) are all members of the closed v2 wire Code set.
type lifecycleSupervisor struct {
	mu             sync.Mutex
	root           ed25519.PublicKey // bootstrap ROOT; immutable
	now            uint64            // latest admitted clock; replacements cannot regress it
	start          lifecycleWorkerStarter
	worker         lifecycleWorker
	challenger     lifecycleWorker
	lifetime       uint64
	ready          *LifecycleReady
	signed         a.SignedLifecycleGrant  // current grant; changed by reconcile or signed handoff
	successor      *a.SignedLifecycleGrant // retained only after a successful authorize-successor
	pending        *LifecycleReplacementStatus
	terminal       *LifecycleReplacementStatus
	fencePending   bool                      // unresolved transport receipt
	logicalHandoff *a.SignedLifecycleHandoff // exact signed fence, unresolved even after correlated busy
	active         bool
	lost           bool
	failed         bool
	closed         bool
	joining        sync.WaitGroup // admitted replacement owner, including a racing start
	closeOnce      sync.Once
	closeErr       error
}

func copyLifecycleReady(r *LifecycleReady) *LifecycleReady {
	if r == nil {
		return nil
	}
	next := *r
	next.TLSRootDER = bytes.Clone(r.TLSRootDER)
	next.ServerDER = bytes.Clone(r.ServerDER)
	return &next
}
func copyLifecycleSigned(s a.SignedLifecycleGrant) a.SignedLifecycleGrant {
	s.Signature = bytes.Clone(s.Signature)
	return s
}
func copyLifecycleConfiguration(c LifecycleConfiguration) LifecycleConfiguration {
	c.RootPublicKey = bytes.Clone(c.RootPublicKey)
	c.Signed = copyLifecycleSigned(c.Signed)
	c.Reopen = c.Reopen.Clone() // no retained caller signature storage
	if c.Cold != nil {
		cold := *c.Cold
		cold.Signature = bytes.Clone(cold.Signature)
		cold.Request.Takeover = copyLifecycleSigned(cold.Request.Takeover)
		c.Cold = &cold
	}
	if c.Resume != nil {
		resume := *c.Resume
		resume.Signature = bytes.Clone(resume.Signature)
		resume.Request.Takeover = copyLifecycleSigned(resume.Request.Takeover)
		c.Resume = &resume
	}
	return c
}
func copyLifecycleReplacement(r *LifecycleReplacementStatus) *LifecycleReplacementStatus {
	if r == nil {
		return nil
	}
	next := *r
	next.Request.Configuration = copyLifecycleConfiguration(r.Request.Configuration)
	next.Ready = copyLifecycleReady(r.Ready)
	return &next
}
func lifecycleSignedEqual(x, y a.SignedLifecycleGrant) bool {
	return x.Grant == y.Grant && bytes.Equal(x.Signature, y.Signature)
}

// Byte-exact comparison through the canonical transport encoding.
func lifecycleReplacementEqual(x, y LifecycleReplacementRequest) bool {
	bx, ex := lifecycleCanonical(&x)
	by, ey := lifecycleCanonical(&y)
	return ex == nil && ey == nil && bytes.Equal(bx, by)
}
func lifecycleRootSigned(key []byte, signed a.SignedLifecycleGrant) bool {
	msg, err := a.LifecycleGrantSigningBytes(signed.Grant)
	return err == nil && len(key) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(key), msg, signed.Signature)
}

// lifecycleServiceState derives the full predecessor state from Ready + grant.
func lifecycleServiceState(r *LifecycleReady, g a.LifecycleGrant) p.LifecycleServiceState {
	digest := sha256.Sum256(r.TLSRootDER)
	return p.LifecycleServiceState{Grant: g,
		Context:      p.LifecycleServiceContext{ServiceEpoch: r.ServiceEpoch, ControllerEpoch: r.ControllerEpoch, ControllerKey: r.ControllerKey},
		OpenRevision: r.OpenRevision,
		Boot: p.LifecycleBootTrustFields{Identity: r.Identity, ServiceEpoch: r.ServiceEpoch,
			TLSRootSHA256: hex.EncodeToString(digest[:]), ServerSPKI: r.ServerSPKI, BootstrapKey: r.BootstrapKey}}
}

// lifecycleSuccessorValid checks a replacement/reopen Ready against its request.
func lifecycleSuccessorValid(reopen p.LifecycleServiceChangeRequest, old *LifecycleReady, next *LifecycleReady, workerID string, g a.LifecycleGrant) bool {
	if !lifecycleReadyValid(next) || next.WorkerUUID != workerID {
		return false
	}
	if old != nil && (next.WorkerUUID == old.WorkerUUID || next.Identity != old.Identity || next.BootstrapKey != old.BootstrapKey ||
		next.ControllerEpoch != old.ControllerEpoch || next.ControllerKey != old.ControllerKey || next.ServiceEpoch == old.ServiceEpoch ||
		bytes.Equal(next.TLSRootDER, old.TLSRootDER) || bytes.Equal(next.ServerDER, old.ServerDER) || next.ServerSPKI == old.ServerSPKI ||
		next.Revision <= old.Revision || old.OpenRevision != reopen.Predecessor.OpenRevision) {
		return false
	}
	confirmation := p.LifecycleServiceChangeConfirmation{Request: reopen, Successor: lifecycleServiceState(next, g)}
	return confirmation.Validate() == nil && next.OpenRevision > reopen.Predecessor.OpenRevision
}

// Initial construction is one-shot. A nonnil supervisor on failure still owns
// any partially started worker and must be closed by the boot-session owner.
func newLifecycleSupervisor(cfg LifecycleConfiguration, start lifecycleWorkerStarter) (*lifecycleSupervisor, error) {
	if cfg.validate() != nil || start == nil || !lifecycleRootSigned(cfg.RootPublicKey, cfg.Signed) {
		return nil, errors.New("configuration")
	}
	root, err := p.PublicKeyFingerprint(ed25519.PublicKey(cfg.RootPublicKey))
	if err != nil {
		return nil, errors.New("configuration")
	}
	workerID, err := newWorkerUUID()
	if err != nil {
		return nil, err
	}
	cfg = copyLifecycleConfiguration(cfg)
	s := &lifecycleSupervisor{root: bytes.Clone(cfg.RootPublicKey), now: cfg.NowUnixSeconds, lifetime: cfg.LifetimeSeconds, start: start, signed: copyLifecycleSigned(cfg.Signed)}
	worker, ready, err := start(copyLifecycleConfiguration(cfg), workerID, s.startGate)
	s.worker = worker
	if err != nil {
		s.failed = true
		return s, err
	}
	g := cfg.Signed.Grant
	ok := worker != nil && lifecycleReadyValid(ready) && ready.WorkerUUID == workerID && ready.Identity == g.Identity &&
		ready.ControllerEpoch == g.ExpectedEpoch+1 && ready.ControllerKey == string(g.NewKey) && ready.BootstrapKey == root.String()
	if ok && cfg.Action == "open" {
		ok = lifecycleSuccessorValid(cfg.Reopen.Request, nil, ready, workerID, g)
	}
	if ok && cfg.Action == "cold-open-takeover" {
		prior := cfg.Cold.Request.Predecessor
		ok = ready.ServiceEpoch != string(prior.ServiceEpoch) && ready.OpenRevision > prior.OpenRevision
	}
	if ok && cfg.Action == "resume-open-takeover" {
		// Empty layouts publish revision 1; exact unused genesis advances
		// revision 1 to 2. Neither admits an advanced/workload registry.
		ok = (ready.OpenRevision == 1 || ready.OpenRevision == 2) && ready.Revision == ready.OpenRevision && ready.ControllerEpoch == 2
	}
	if !ok {
		s.failed = true
		return s, errors.New("configuration")
	}
	s.ready = copyLifecycleReady(ready)
	return s, nil
}

func (s *lifecycleSupervisor) startGate(send func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("worker-lost")
	}
	return send()
}
func lifecycleWorkerExited(w lifecycleWorker) bool {
	if w == nil {
		return true
	}
	select {
	case <-w.done():
		return true
	default:
		return false
	}
}
func (s *lifecycleSupervisor) currentLocked(epoch, worker string) bool {
	return !s.closed && s.ready != nil && s.ready.ServiceEpoch == epoch && s.ready.WorkerUUID == worker
}

// status answers only for the current (service epoch, worker UUID) pair.
func (s *lifecycleSupervisor) status(epoch, worker string) (*LifecycleServiceStatus, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.currentLocked(epoch, worker) {
		return nil, "stale-worker"
	}
	phase := "ready"
	switch {
	case s.pending != nil:
		phase = "replacing"
	case s.failed:
		phase = "failed"
	case s.lost || lifecycleWorkerExited(s.worker):
		phase = "worker-lost"
	}
	return &LifecycleServiceStatus{Phase: phase}, ""
}

// command forwards private commands. Only reconcile-controller or ROOT-signed
// fence-handoff may change retained grant/C; neither changes E/worker/TLS/open.
func (s *lifecycleSupervisor) command(request *LifecycleFrame) (*LifecycleFrame, string) {
	s.mu.Lock()
	if request == nil || request.Sequence == nil || !s.currentLocked(request.ServiceEpoch, request.WorkerUUID) {
		s.mu.Unlock()
		return nil, "stale-worker"
	}
	if s.pending != nil || s.active {
		s.mu.Unlock()
		return nil, "worker-busy"
	}
	if s.failed || s.lost || lifecycleWorkerExited(s.worker) {
		s.mu.Unlock()
		return nil, "worker-lost"
	}
	if (s.fencePending && request.Command != "fence-handoff") ||
		(s.logicalHandoff != nil && (request.Command != "fence-handoff" || !sameLifecycleSignedHandoff(s.logicalHandoff, request.Handoff))) {
		s.mu.Unlock()
		return nil, "worker-busy"
	}
	if lifecycleIsolationCommand(request.Command) {
		// Exclusivity requires a separately authenticated, reaped challenger.
		// Never forward it to the original service or synthesize its proof.
		if pc.CurrentProfile() != pc.FullProfile || request.validate() != nil {
			s.mu.Unlock()
			return nil, "command"
		}
	}
	if request.Command == "second-service-exclusivity" {
		return s.challengeLocked(request)
	}
	if lifecycleConsumerCommand(request.Command) {
		q := lifecycleConsumerRequest(request)
		if pc.CurrentProfile() != pc.FullProfile || request.validate() != nil || q.WorkerScope.StoreUUID != string(s.ready.Identity.Store) {
			s.mu.Unlock()
			return nil, "command"
		}
	}
	if lifecycleCompatibilityCommand(request.Command) {
		if pc.CurrentProfile() != pc.FullProfile || request.validate() != nil {
			s.mu.Unlock()
			return nil, "command"
		}
		if request.Command == "prepare-compatibility-worker-exit" || request.Command == "prepare-compatibility-checkpoint-exit" {
			return s.compatibilityExitLocked(request)
		}
	}
	switch request.Command {
	case "consumer-observation-arm", "consumer-observation-query", "consumer-observation-finalize":
	case "prepare-compatibility-arm", "prepare-compatibility-observe", "prepare-compatibility-release":
	case "isolation-state", "legacy-connection":
	case "issue-controller", "authorize-retirement", "notifications", "query":
	case "fence-handoff":
		if !s.admitHandoffLocked(request) {
			s.mu.Unlock()
			return nil, "command"
		}
	case "authorize-successor":
		if request.Signed == nil || request.Signed.Grant.Operation != a.LifecycleTakeover {
			s.mu.Unlock()
			return nil, "command"
		}
	case "reconcile-controller":
		// Admission: exactly the authorized successor, or an exact retry of current.
		signed, controller := request.Signed, request.Controller
		if signed == nil || controller == nil || controller.Epoch != signed.Grant.ExpectedEpoch+1 || controller.Key != signed.Grant.NewKey ||
			!(s.successor != nil && lifecycleSignedEqual(*signed, *s.successor) || lifecycleSignedEqual(*signed, s.signed)) {
			s.mu.Unlock()
			return nil, "command"
		}
	default:
		s.mu.Unlock()
		return nil, "command"
	}
	s.active = true
	if request.Command == "fence-handoff" {
		s.fencePending = true
		retained := *request.Handoff
		retained.Signature = bytes.Clone(retained.Signature)
		s.logicalHandoff = &retained
	}
	worker := s.worker
	s.mu.Unlock()
	var reply *LifecycleFrame
	var err error
	if packet, ok := worker.(*lifecyclePacketWorker); ok && request.Command == "fence-handoff" {
		reply, err = packet.exchangeValidated(request, func(original, receipt *LifecycleFrame) bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			// Validate against retained ROOT-authorized state without adopting or
			// re-labelling the old receipt as the fresh request's result.
			check := &lifecycleSupervisor{ready: s.ready, signed: s.signed, successor: s.successor}
			if receipt.validate() != nil || !validLifecyclePacketReply(original, receipt) {
				return false
			}
			return receipt.Code == "worker-busy" || (receipt.Code == "" && check.acceptHandoffLocked(original, receipt))
		})
	} else {
		reply, err = worker.exchange(request)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	if s.closed {
		return nil, "worker-lost"
	}
	var pendingFence *lifecycleFencePendingError
	if errors.As(err, &pendingFence) && request.Command == "fence-handoff" {
		s.fencePending = true
		return nil, "worker-busy"
	}
	old := s.ready
	if err != nil || reply == nil || reply.Operation != "reply" || reply.Sequence == nil || *reply.Sequence != *request.Sequence ||
		reply.ServiceEpoch != old.ServiceEpoch || reply.WorkerUUID != old.WorkerUUID {
		s.lost = true
		return nil, "worker-lost"
	}
	if (lifecycleIsolationCommand(request.Command) || lifecycleConsumerCommand(request.Command)) && (reply.validate() != nil || reply.Binding != request.Binding) {
		return nil, "command"
	}
	if request.Command == "fence-handoff" && (reply.validate() != nil || reply.Binding != request.Binding) {
		s.lost = true
		return nil, "command"
	}
	if reply.Code != "" {
		if request.Command == "fence-handoff" {
			// Correlated contention resolves only the transport receipt.
			// The authority may already have committed: keep the logical fence.
			if reply.Code == "worker-busy" {
				s.fencePending = false
			} else {
				s.lost = true
			}
		}
		return reply, ""
	}
	switch request.Command {
	case "isolation-state", "legacy-connection":
		// Ready is a retained lower bound, not a frozen registry revision: real
		// CONTROL/DATA work can advance the registry without a supervisor query.
		// The service itself checks exact before/after state for each probe.
		if !validLifecycleIsolationReply(request, reply) || reply.IsolationProof.Store != string(old.Identity.Store) || reply.IsolationProof.Revision < old.Revision {
			return nil, "command"
		}
	case "consumer-observation-arm", "consumer-observation-query", "consumer-observation-finalize":
		if !validLifecycleConsumerReply(request, reply) {
			return nil, "command"
		}

	case "prepare-compatibility-arm", "prepare-compatibility-observe", "prepare-compatibility-release":
		expected, e := lifecycleCompatibilityQuery(request)
		status := reply.PrepareCompatibilityStatus
		if e != nil || status == nil || reply.validate() != nil || status.Query != expected {
			return nil, "command"
		}
	case "issue-controller":
		if len(reply.Certificate) == 0 {
			s.lost = true
			return nil, "worker-lost"
		}
	case "authorize-successor":
		if len(reply.Certificate) == 0 {
			s.lost = true
			return nil, "worker-lost"
		}
		retained := copyLifecycleSigned(*request.Signed)
		s.successor = &retained
	case "authorize-retirement":
		if reply.OK == nil {
			s.lost = true
			return nil, "worker-lost"
		}
	case "notifications":
		// v1 semantics: every entry must name the current Ready epoch and store.
		if reply.Notifications == nil {
			s.lost = true
			return nil, "worker-lost"
		}
		for _, n := range *reply.Notifications {
			if string(n.Epoch) != old.ServiceEpoch || n.Binding.Store != old.Identity.Store {
				s.lost = true
				return nil, "worker-lost"
			}
		}
	case "fence-handoff":
		if !s.acceptHandoffLocked(request, reply) {
			s.lost = true
			return nil, "command"
		}
		s.fencePending = false
	case "query", "reconcile-controller":
		next := reply.Ready
		if !lifecycleReadyValid(next) || next.Identity != old.Identity || next.ServiceEpoch != old.ServiceEpoch || next.WorkerUUID != old.WorkerUUID ||
			next.BootstrapKey != old.BootstrapKey || next.ServerSPKI != old.ServerSPKI || next.OpenRevision != old.OpenRevision ||
			!bytes.Equal(next.TLSRootDER, old.TLSRootDER) || !bytes.Equal(next.ServerDER, old.ServerDER) || next.Revision < old.Revision {
			s.lost = true
			return nil, "worker-lost"
		}
		epoch, key := old.ControllerEpoch, old.ControllerKey
		if request.Command == "reconcile-controller" {
			epoch, key = request.Controller.Epoch, string(request.Controller.Key)
		}
		if next.ControllerEpoch != epoch || next.ControllerKey != key {
			return nil, "command" // query cannot adopt an unreconciled C/key
		}
		if request.Command == "reconcile-controller" {
			// Commit Ready and the current grant together before replying.
			s.signed, s.successor = copyLifecycleSigned(*request.Signed), nil
		}
		s.ready = copyLifecycleReady(next)
	}
	return reply, ""
}

// replaceService admits one open-only replacement of the current worker.
// Exact retries are resolved by operation ID before any scope check.
func (s *lifecycleSupervisor) replaceService(request LifecycleReplacementRequest) (*LifecycleReplacementStatus, string) {
	// validate verifies the ROOT-signed service change before any pending
	// installation, kill, or start; unsigned host requests stop here.
	if request.validate() != nil || !lifecycleRootSigned(request.Configuration.RootPublicKey, request.Configuration.Signed) {
		return nil, "replacement-conflict"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, "replacement-conflict"
	}
	for _, retained := range []*LifecycleReplacementStatus{s.pending, s.terminal} {
		if retained != nil && retained.Request.Configuration.Reopen.Request.OperationID == request.Configuration.Reopen.Request.OperationID {
			if !lifecycleReplacementEqual(retained.Request, request) {
				return nil, "replacement-conflict"
			}
			return copyLifecycleReplacement(retained), ""
		}
	}
	if s.pending != nil || s.active || s.successor != nil || s.fencePending || s.logicalHandoff != nil {
		return nil, "worker-busy"
	}
	cfg := request.Configuration
	if s.failed || s.ready == nil || !lifecycleSignedEqual(cfg.Signed, s.signed) || !bytes.Equal(cfg.RootPublicKey, s.root) ||
		cfg.Reopen.Request.Predecessor != lifecycleServiceState(s.ready, s.signed.Grant) || request.PredecessorWorkerUUID != s.ready.WorkerUUID ||
		cfg.NowUnixSeconds < s.now {
		return nil, "stale-worker"
	}
	operation := &LifecycleReplacementStatus{Request: request, Phase: "pending"}
	operation.Request.Configuration = copyLifecycleConfiguration(cfg)
	s.pending = operation // freeze ordinary admission before signalling
	s.joining.Add(1)
	go s.replace(operation, s.worker, copyLifecycleReady(s.ready), s.signed.Grant)
	return copyLifecycleReplacement(operation), ""
}

func (s *lifecycleSupervisor) replace(operation *LifecycleReplacementStatus, previous lifecycleWorker, old *LifecycleReady, g a.LifecycleGrant) {
	defer s.joining.Done()
	if previous != nil {
		_ = previous.kill() // delivery/error is not evidence of process death
		<-previous.done()   // deliberately no timeout or context-as-death shortcut
	}
	if previous == nil || !previous.reaped() {
		s.finishReplacement(operation, nil, nil, "worker-unreaped")
		return
	}
	s.mu.Lock()
	// A racing close already killed/closed the retained handle; never close twice.
	release, closed := s.worker == previous && !s.closed, s.closed
	if release {
		s.worker = nil
	}
	s.mu.Unlock()
	if release {
		_ = previous.close() // only now may the birth pidfd be released
	}
	if closed {
		return
	}
	workerID, err := newWorkerUUID()
	if err != nil {
		s.finishReplacement(operation, nil, nil, "replacement-failed")
		return
	}
	// Operation is immutable after admission, so reading it without mu is safe.
	cfg := copyLifecycleConfiguration(operation.Request.Configuration)
	next, ready, err := s.start(cfg, workerID, s.startGate)
	if err != nil || next == nil || !lifecycleSuccessorValid(cfg.Reopen.Request, old, ready, workerID, g) {
		s.finishReplacement(operation, next, nil, "replacement-failed")
		return
	}
	s.finishReplacement(operation, next, ready, "")
}

func (s *lifecycleSupervisor) finishReplacement(operation *LifecycleReplacementStatus, next lifecycleWorker, ready *LifecycleReady, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keep the only possibly live owner even on construction failure or close.
	if next != nil {
		s.worker = next
	}
	if s.closed {
		if next != nil {
			_ = next.kill() // close joins this replacement and proves its Wait
		}
		return
	}
	if s.pending != operation {
		panic("storageboot: lifecycle replacement ownership lost")
	}
	if code == "" {
		s.ready = copyLifecycleReady(ready)
		s.now = operation.Request.Configuration.NowUnixSeconds
		s.lifetime = operation.Request.Configuration.LifetimeSeconds
		s.lost = false
		operation.Phase, operation.Ready = "succeeded", copyLifecycleReady(ready)
	} else {
		s.failed = true // terminal uncertainty: never automatically reopen again
		operation.Phase, operation.Code = "failed", code
		if next != nil {
			_ = next.kill() // retained as owner; not closed until its Wait is proven
		}
	}
	s.terminal, s.pending = operation, nil
}

// replacementStatus is exact lookup only, keyed by the predecessor pair.
func (s *lifecycleSupervisor) replacementStatus(epoch, worker string) (*LifecycleReplacementStatus, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, "replacement-conflict"
	}
	for _, retained := range []*LifecycleReplacementStatus{s.pending, s.terminal} {
		if retained != nil && retained.Request.PredecessorWorkerUUID == worker &&
			retained.Request.Configuration.Reopen.Request.Predecessor.Context.ServiceEpoch == epoch {
			return copyLifecycleReplacement(retained), ""
		}
	}
	return nil, "replacement-conflict"
}

// dispatch routes one validated command frame. Reply envelopes echo the request.
func (s *lifecycleSupervisor) dispatch(request *LifecycleFrame) (*LifecycleFrame, string) {
	if request == nil || request.Operation != "command" || request.Sequence == nil {
		return nil, "command"
	}
	reply := lifecycleFrame("reply", request.Binding)
	sequence := *request.Sequence
	reply.Sequence, reply.ServiceEpoch, reply.WorkerUUID = &sequence, request.ServiceEpoch, request.WorkerUUID
	var code string
	switch request.Command {
	case "service-status":
		reply.Status, code = s.status(request.ServiceEpoch, request.WorkerUUID)
	case "replace-service":
		if request.ReplacementRequest == nil {
			return nil, "command"
		}
		reply.Replacement, code = s.replaceService(*request.ReplacementRequest)
	case "replacement-status":
		reply.Replacement, code = s.replacementStatus(request.ServiceEpoch, request.WorkerUUID)
	default:
		return s.command(request)
	}
	if code != "" {
		return nil, code
	}
	return &reply, ""
}

// close aborts admission, then joins every admitted starter and the sole Wait.
// No mutex is held over a wait. A failed reap retains the worker/pidfd; callers
// must retain PID1 and its root/lease for host hard fallback, never power off.
func (s *lifecycleSupervisor) close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		worker, challenger := s.worker, s.challenger
		s.mu.Unlock()
		for _, owner := range []lifecycleWorker{worker, challenger} {
			if owner != nil {
				_ = owner.kill()
			}
		}
		s.joining.Wait()
		s.mu.Lock()
		worker, challenger = s.worker, s.challenger
		s.mu.Unlock()
		// Includes owners returned by a racing launcher. An uncertain challenger
		// must not prevent joining the original, nor release its own birth pin.
		for _, owner := range []lifecycleWorker{worker, challenger} {
			if owner == nil {
				continue
			}
			_ = owner.kill()
			<-owner.done()
			if !owner.reaped() {
				s.closeErr = errors.Join(s.closeErr, errors.New("lifecycle worker reap uncertain"))
				continue
			}
			s.closeErr = errors.Join(s.closeErr, owner.close())
		}
	})
	return s.closeErr
}
