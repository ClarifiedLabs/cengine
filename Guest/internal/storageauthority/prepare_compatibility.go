package storageauthority

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
)

// This narrow vocabulary deliberately does not import the carrier DTO package.
// Installation is privileged boot wiring, never a principal or control command.
type PrepareCompatibilityPlan struct {
	Stage              string
	Epoch              ID
	Controller         Controller
	Target             Binding
	Bindings           []Binding
	RuntimeAttachments []ID
}
type PrepareCompatibilitySnapshot struct {
	State                 string
	Sequence              uint64
	Admitted              bool
	ReleaseToken          string
	RetirementStarted     bool
	AcceptedInFlight      uint32
	LateAdmissionRejected bool
	ReceiptReplayCount    uint32
	Bound                 *CopyIntent
	RetireOperation       ID
	Receipt               *Receipt
	IO                    *PrepareCompatibilityIO
}
type PrepareCompatibilityWitness struct {
	mu                 sync.Mutex // never Query/authority IO while held
	owner              *Authority
	plan               PrepareCompatibilityPlan
	snapshot           PrepareCompatibilitySnapshot
	release            chan struct{}
	workerExitClaimed  bool
	dropped            bool
	retirementFinished bool
}

func (a *Authority) InstallPrepareCompatibility(plan PrepareCompatibilityPlan) (*PrepareCompatibilityWitness, error) {
	if !prepareCompatibilityEnabled() {
		return nil, ErrUnauthorized
	}
	switch plan.Stage {
	case "full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "drain-durable-reply-lost", "vm-private-bound", "vm-cleaning-transaction-removed", "vm-two-volume-drain-reply-gap":
	default:
		if _, ok := prepareIOCaseFor(plan.Stage); !ok {
			return nil, ErrInvalid
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return nil, err
	}
	if a.prepareCompatibility.Load() != nil || plan.Epoch != a.s.Epoch || plan.Controller != a.s.Controller || plan.Target.Role != PrepareRole || plan.Target.Mode != ReadWrite || len(plan.Bindings) == 0 || len(plan.Bindings) > 64 || len(plan.RuntimeAttachments) > 64 {
		return nil, ErrUnauthorized
	}
	if plan.Stage == "vm-two-volume-drain-reply-gap" && (len(plan.Bindings) != 2 || len(plan.RuntimeAttachments) != 2 || plan.Bindings[0].Volume == plan.Bindings[1].Volume) {
		return nil, ErrInvalid
	}
	prepare, ok := a.s.Prepares[plan.Target.Prepare]
	if !ok || prepare.Phase != Pending || len(prepare.Attachments) != len(plan.Bindings) {
		return nil, ErrConflict
	}
	seen := map[ID]bool{}
	for _, b := range plan.Bindings {
		rec, ok := a.s.Attachments[b.Attachment]
		rt := a.runtime[b.Attachment]
		if !ok || seen[b.Attachment] || rec.Binding != b || rec.Phase != Active || b.Role != PrepareRole || b.Prepare != prepare.ID || b.Container != plan.Target.Container || b.Launch != plan.Target.Launch || rt == nil || rt.connected || rt.count != 0 {
			return nil, ErrConflict
		}
		seen[b.Attachment] = true
	}
	for _, b := range prepare.Attachments {
		if !seen[b.Attachment] {
			return nil, ErrConflict
		}
	}
	if !seen[plan.Target.Attachment] || a.s.Attachments[plan.Target.Attachment].Binding != plan.Target {
		return nil, ErrConflict
	}
	runtime := map[ID]bool{}
	for _, id := range plan.RuntimeAttachments {
		if !validID(id) || runtime[id] || seen[id] {
			return nil, ErrInvalid
		}
		if _, exists := a.s.Attachments[id]; exists {
			return nil, ErrConflict
		}
		runtime[id] = true
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	plan.Bindings = append([]Binding(nil), plan.Bindings...)
	plan.RuntimeAttachments = append([]ID(nil), plan.RuntimeAttachments...)
	w := &PrepareCompatibilityWitness{owner: a, plan: plan, release: make(chan struct{}), snapshot: PrepareCompatibilitySnapshot{State: "armed", ReleaseToken: hex.EncodeToString(random[:])}}
	if c, ok := prepareIOCaseFor(plan.Stage); ok {
		w.snapshot.IO = &PrepareCompatibilityIO{Point: c.point, Errno: c.errnoName}
	}
	a.prepareCompatibility.Store(w)
	return w, nil
}
func (w *PrepareCompatibilityWitness) Snapshot() PrepareCompatibilitySnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.snapshot
	if s.IO != nil {
		v := *s.IO
		s.IO = &v
	}
	if s.Bound != nil {
		v := *s.Bound
		s.Bound = &v
	}
	if s.Receipt != nil {
		v := *s.Receipt
		s.Receipt = &v
	}
	return s
}

// Release never clears a fence. It requires a real Retire transition already
// recorded under authority.mu, then consumes exactly one private random token.
func (w *PrepareCompatibilityWitness) Release(stage, token string) error {
	if w == nil {
		return ErrInvalid
	}
	// These stages park while owning authority.mu. Reject without acquiring it;
	// admission Release/retirement semantics below remain unchanged.
	if w.plan.Stage == "vm-private-bound" || w.plan.Stage == "vm-cleaning-transaction-removed" {
		return ErrConflict
	}
	a := w.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	rec := a.s.Attachments[w.plan.Target.Attachment]
	if w.workerExitClaimed || stage != w.plan.Stage || (stage != "full-frame-before-admit" && stage != "admitted-queued") || w.snapshot.State != "observed" || !w.snapshot.RetirementStarted || rec.Binding != w.plan.Target || (rec.Phase != Retiring && rec.Phase != Drained) || rec.Retirement == "" || subtle.ConstantTimeCompare([]byte(token), []byte(w.snapshot.ReleaseToken)) != 1 {
		return ErrConflict
	}
	w.snapshot.State = "released"
	close(w.release)
	return nil
}
func (a *Authority) PrepareCompatibilityAdmission(h DataHello, sequence uint64, g *Guard) {
	w := a.prepareCompatibility.Load()
	if w == nil || h.Epoch != w.plan.Epoch || h.Binding != w.plan.Target || sequence == 0 {
		return
	}
	admitted := g != nil
	if !admitted && w.plan.Stage != "full-frame-before-admit" || admitted && w.plan.Stage != "admitted-queued" {
		return
	}
	if admitted && (g.token == nil || g.token.owner != a || g.token.binding != h.Binding) {
		return
	}
	w.mu.Lock()
	if w.snapshot.State != "armed" {
		w.mu.Unlock()
		return
	}
	w.snapshot.State = "observed"
	w.snapshot.Sequence = sequence
	w.snapshot.Admitted = admitted
	w.mu.Unlock()
	<-w.release // no EOF/context/deadline/release callback
}
func (a *Authority) PrepareCompatibilityAdmissionResult(h DataHello, sequence uint64, err error) {
	w := a.prepareCompatibility.Load()
	if w == nil || w.plan.Stage != "full-frame-before-admit" || h.Binding != w.plan.Target || h.Epoch != w.plan.Epoch {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.snapshot.State == "released" && w.snapshot.Sequence == sequence && err == ErrBlocked {
		w.snapshot.LateAdmissionRejected = true
		if w.retirementFinished {
			w.snapshot.State = "finished"
		}
	}
}
func (a *Authority) compatibilityRetirementLocked(rec Attachment, operation ID) {
	w := a.prepareCompatibility.Load()
	if w == nil || rec.Binding != w.plan.Target || rec.Retirement == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.snapshot.RetirementStarted {
		w.snapshot.RetirementStarted = true
		if rt := a.runtime[rec.Binding.Attachment]; rt != nil {
			w.snapshot.AcceptedInFlight = uint32(rt.count)
		}
	}
	// The arming controller owns the carrier claim that supplies the explicit
	// release token, and the host never re-adopts that claim after it restarts.
	// A successor controller's Retire is therefore the only remaining way an
	// admission held for that claim can finish, so it releases the hold exactly
	// once. The arming controller's own Retire still waits for the explicit
	// release action; a claimed worker exit already owns the outcome.
	if a.s.Controller != w.plan.Controller && (w.plan.Stage == "full-frame-before-admit" || w.plan.Stage == "admitted-queued") &&
		w.snapshot.State == "observed" && !w.workerExitClaimed {
		w.snapshot.State = "released"
		close(w.release)
	}
}
func (a *Authority) compatibilityDrainedLocked(rec Attachment, receipt Receipt) {
	w := a.prepareCompatibility.Load()
	if w == nil || rec.Binding != w.plan.Target {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	rt := a.runtime[rec.Binding.Attachment]
	if rt == nil || rt.count != 0 {
		return
	}
	w.retirementFinished = true
	w.snapshot.AcceptedInFlight = uint32(rt.count)
	switch w.plan.Stage {
	case "full-frame-before-admit":
		if w.snapshot.State == "released" && w.snapshot.LateAdmissionRejected {
			w.snapshot.State = "finished"
		}
	case "transaction-published-bind-reply-lost":
		if w.snapshot.State == "observed" && w.snapshot.Bound != nil {
			w.snapshot.State = "finished"
		}
	case "vm-two-volume-drain-reply-gap":
		if w.snapshot.State == "armed" {
			w.snapshot.RetireOperation = rec.Retirement
			w.snapshot.Receipt = &receipt
		}
	case "drain-durable-reply-lost":
		if w.snapshot.State == "armed" {
			w.snapshot.State = "observed"
			w.snapshot.RetireOperation = rec.Retirement
			w.snapshot.Receipt = &receipt
		}
	case "admitted-queued":
		if w.snapshot.State == "released" {
			w.snapshot.State = "finished"
		}
	}
}

// Called only at the successful control reply boundary. Receipt replay counts
// are actual matching production replies, not status queries or supplied counts.
func (a *Authority) PrepareCompatibilityRetireReply(req RetireRequest, receipt Receipt) bool {
	w := a.prepareCompatibility.Load()
	if w != nil && w.plan.Stage == "vm-two-volume-drain-reply-gap" {
		if a.observeTwoVolumeDrainReply(w, req, receipt) {
			select {} // crash-only hold: no EOF, deadline, observer ACK or release path
		}
		return false
	}
	if w == nil || w.plan.Stage != "drain-durable-reply-lost" {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.snapshot.Receipt == nil || req.Operation != w.snapshot.RetireOperation || receipt != *w.snapshot.Receipt || req.Store != receipt.Store || req.Volume != receipt.Volume || req.Attachment != receipt.Attachment {
		return false
	}
	if !w.dropped {
		w.dropped = true
		return true
	}
	if w.snapshot.ReceiptReplayCount < ^uint32(0) {
		w.snapshot.ReceiptReplayCount++
	}
	w.snapshot.State = "finished"
	return false
}

// Exact live guard + actual discharged provision obligation + actual returned
// BOUND intent. No observation can be made from a caller-supplied snapshot alone.
func (g *Guard) PrepareCompatibilityBoundReply(sequence uint64, intent CopyIntent) bool {
	a, err := g.copyAuthority()
	if err != nil {
		return false
	}
	w := a.prepareCompatibility.Load()
	if w == nil || w.plan.Stage != "transaction-published-bind-reply-lost" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if g.token.released || g.token.binding != w.plan.Target || g.token.epoch != w.plan.Epoch || g.token.boundSequence != sequence || g.token.publishedCopy != intent.ID || !intent.InitialCaptured || sequence == 0 || a.copyIO != nil || intent.Phase != CopyBound || intent != a.s.Copy.Intents[g.token.binding.Volume] || !a.validCopyRoot(intent.Root, g.token.binding) || !validCopyDirectory(intent.Transaction) {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.snapshot.State != "armed" {
		return false
	}
	w.snapshot.State = "observed"
	w.snapshot.Sequence = sequence
	w.snapshot.Bound = &intent
	return true
}
