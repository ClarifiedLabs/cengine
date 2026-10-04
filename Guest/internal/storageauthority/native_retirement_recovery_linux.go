//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storageauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// NativeRetirementRecoveryStage names only successful, real journal boundaries.
// This adapter is absent from production builds and cannot inject IO success.
type NativeRetirementRecoveryStage uint8

const (
	NativeRetirementCertified NativeRetirementRecoveryStage = iota + 1
	NativeRetirementPrepared
	NativeRetirementPublished
	NativeRetirementCandidate
)

type NativeRetirementRecoveryPlan struct {
	Stage      NativeRetirementRecoveryStage
	Binding    Binding
	Epoch      ID
	Controller Controller
	Operation  ID
}

func (p NativeRetirementRecoveryPlan) Validate() error {
	if p.Stage < NativeRetirementCertified || p.Stage > NativeRetirementCandidate ||
		!validID(p.Binding.Store) || !bindingValid(p.Binding, &diskState{Store: Store{ID: p.Binding.Store}}) ||
		p.Binding.Role != RuntimeRole || p.Binding.Mode != ReadWrite ||
		!validID(p.Epoch) || !validID(p.Operation) || p.Controller.Epoch == 0 || !validKey(p.Controller.Key) {
		return ErrInvalid
	}
	return nil
}

// These value-only views expose public journal evidence, never a capability.
type NativeRetirementRecoveryCertificate retirementProof
type NativeRetirementRecoveryMetadata commitProof

type NativeRetirementRecoveryObservation struct {
	Plan             NativeRetirementRecoveryPlan
	Certificate      NativeRetirementRecoveryCertificate
	Metadata         *NativeRetirementRecoveryMetadata
	ReadyTemporary   *NativeRetirementRecoveryMetadata
	CandidateDigest  string
	StateDigest      string
	BarrierSucceeded uint32
}

type nativeRetirementRecoveryResult struct {
	observation NativeRetirementRecoveryObservation
	err         error
}

type NativeRetirementRecoveryWitness struct {
	owner               *Authority
	barrier             Barrier
	plan                NativeRetirementRecoveryPlan
	before              uint64
	barriers            atomic.Uint32
	fired, held, waited atomic.Bool
	observed            chan nativeRetirementRecoveryResult
	release             chan struct{}
	abandon             chan struct{}
}

// Install before Retire, with the exact ACTIVE binding. No callback, path, fd,
// principal, fault, or syscall is supplied by the caller; existing hooks conflict.
func (a *Authority) NewNativeRetirementRecoveryWitness(p NativeRetirementRecoveryPlan) (*NativeRetirementRecoveryWitness, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return nil, err
	}
	rec := a.s.Attachments[p.Binding.Attachment]
	if a.s.Store.ID != p.Binding.Store || a.s.Epoch != p.Epoch || a.s.Controller != p.Controller ||
		rec.Binding != p.Binding || rec.Phase != Active || rec.Receipt != nil || rec.Retirement != "" ||
		a.s.Revision > ^uint64(0)-2 || a.inflight != 0 || a.drains != 0 || a.dataIO != nil || a.copyIO != nil ||
		a.j.fault != nil || a.j.afterStep != nil || a.j.prepareIOFault != nil {
		return nil, ErrConflict
	}
	if _, exists := a.s.Operations[p.Operation]; exists {
		return nil, ErrConflict
	}
	w := &NativeRetirementRecoveryWitness{owner: a, barrier: a.barrier, plan: p, before: a.s.Revision,
		observed: make(chan nativeRetirementRecoveryResult, 1), release: make(chan struct{}), abandon: make(chan struct{})}
	realBarrier := a.barrier
	a.barrier = func(b Binding, root *os.File) error {
		err := realBarrier(b, root)
		if err == nil && b == p.Binding {
			w.barriers.Add(1)
		}
		return err
	}
	a.j.afterStep = w.afterStep
	return w, nil
}

// Wait never acquires authority.mu: the actual journal writer holds it at the cut.
func (w *NativeRetirementRecoveryWitness) Wait(ctx context.Context) (NativeRetirementRecoveryObservation, error) {
	if w == nil || w.owner == nil || ctx == nil || !w.waited.CompareAndSwap(false, true) {
		return NativeRetirementRecoveryObservation{}, ErrInvalid
	}
	select {
	case result := <-w.observed:
		return result.observation, result.err
	case <-ctx.Done():
		// A failed observation is never crash evidence. Do not strand a later
		// selected writer under authority.mu after its sole observer has left.
		close(w.abandon)
		return NativeRetirementRecoveryObservation{}, ctx.Err()
	}
}

// Release is one-way and is eligible only once the real step is held.
func (w *NativeRetirementRecoveryWitness) Release() error {
	if w == nil || !w.held.CompareAndSwap(true, false) {
		return ErrConflict
	}
	close(w.release)
	return nil
}

func (w *NativeRetirementRecoveryWitness) afterStep(step string) {
	want := "barrier-complete-parent-sync"
	if w.plan.Stage == NativeRetirementCandidate {
		want = "barrier-complete-write" // complete bytes, before candidate fsync
	}
	if w.plan.Stage == NativeRetirementPrepared {
		want = "proof-ready-close"
	}
	if w.plan.Stage == NativeRetirementPublished {
		want = "state-parent-sync"
	}
	// In particular, never hold the earlier retirement-intent transaction.
	if step != want || w.barriers.Load() != 1 || !w.fired.CompareAndSwap(false, true) {
		return
	}
	defer func() {
		// The selected writer still holds authority.mu. Existing hooks were
		// rejected at installation, and no new one can race this restoration.
		w.owner.j.afterStep = nil
		w.owner.barrier = w.barrier
	}()
	select {
	case <-w.abandon:
		return
	default:
	}
	observation, err := w.observe()
	if err != nil {
		w.observed <- nativeRetirementRecoveryResult{err: err}
		return
	}
	w.held.Store(true)
	w.observed <- nativeRetirementRecoveryResult{observation: observation}
	select {
	case <-w.release:
	case <-w.abandon:
		w.held.Store(false)
	}
}

// Called under authority.mu, after the actual step. All validation is read-only.
func (w *NativeRetirementRecoveryWitness) observe() (NativeRetirementRecoveryObservation, error) {
	a, plan := w.owner, w.plan
	o := NativeRetirementRecoveryObservation{Plan: plan, BarrierSucceeded: w.barriers.Load()}
	rec := a.s.Attachments[plan.Binding.Attachment]
	rt := a.runtime[plan.Binding.Attachment]
	root, err := identity(a.roots[plan.Binding.Volume])
	if err != nil {
		return o, err
	}
	store, err := identity(a.j.root)
	if err != nil {
		return o, err
	}
	if a.available() != nil || a.inflight != 0 || a.drains != 1 || rt == nil || rt.done == nil || rt.count != 0 ||
		a.s.Epoch != plan.Epoch || a.s.Controller != plan.Controller || a.s.Store.Root != store ||
		root != a.s.Volumes[plan.Binding.Volume].Root || rec.Binding != plan.Binding ||
		rec.Phase != Retiring || rec.Receipt != nil || rec.Retirement != plan.Operation ||
		a.s.Revision != w.before+1 || a.s.Operations[plan.Operation] != digest("retire", RetireRequest{
		plan.Operation, plan.Binding.Store, plan.Binding.Volume, plan.Binding.Attachment, plan.Binding.Launch}) {
		return o, ErrConflict
	}
	// Loading an unpublished certificate records its exact name on the journal.
	// Keep even that recovery bookkeeping off the live writer's journal.
	check := *a.j
	p, err := check.loadRetirementProof()
	if err != nil {
		return o, err
	}
	if p == nil || p.Binding != plan.Binding || p.Epoch != plan.Epoch || p.Controller != plan.Controller || p.Operation != plan.Operation ||
		p.Revision != w.before+2 || p.Store != a.s.Store || p.Volume != a.s.Volumes[plan.Binding.Volume] || p.Bootstrap != a.s.Bootstrap {
		return o, ErrConflict
	}
	meta, err := check.loadCommitProof()
	if err != nil {
		return o, err
	}
	// Reuse the production validator on a value copy, without changing the live
	// journal's recovery state or manufacturing a completed certificate.
	check.retirement, check.uncertain = p, meta != nil
	if plan.Stage == NativeRetirementCandidate {
		if check.retirementCandidate != "barrier-"+string(p.Attempt)+".tmp" || meta != nil {
			return o, ErrConflict
		}
	} else if check.retirementCandidate != "" {
		return o, ErrConflict
	}
	if err = check.validateRetirementRecovery(); err != nil {
		return o, err
	}
	o.Certificate = NativeRetirementRecoveryCertificate(*p)
	o.StateDigest, err = a.j.stateDigest()
	if err != nil {
		return o, err
	}
	if plan.Stage == NativeRetirementCertified || plan.Stage == NativeRetirementCandidate {
		if meta != nil || o.StateDigest != p.Prior {
			return o, ErrConflict
		}
		return o, nil
	}
	if meta == nil || meta.Ready != (plan.Stage == NativeRetirementPublished) {
		return o, ErrConflict
	}
	view := NativeRetirementRecoveryMetadata(*meta)
	o.Metadata = &view
	if plan.Stage == NativeRetirementPublished {
		if o.StateDigest != p.Next {
			return o, ErrConflict
		}
		return o, nil
	}
	if o.StateDigest != p.Prior {
		return o, ErrConflict
	}
	raw, err := a.j.nativeRetirementTemporary("proof-", maxCommitProofBytes)
	if err != nil {
		return o, err
	}
	ready := *meta
	ready.Ready = true
	canonical, err := json.Marshal(ready)
	if err != nil || !bytes.Equal(raw, canonical) {
		return o, ErrConflict
	}
	viewReady := NativeRetirementRecoveryMetadata(ready)
	o.ReadyTemporary = &viewReady
	candidate, err := a.j.nativeRetirementTemporary("state-", a.j.maxBytes)
	if err != nil {
		return o, err
	}
	o.CandidateDigest = contentDigest(candidate)
	if o.CandidateDigest != p.Next {
		return o, ErrConflict
	}
	return o, nil
}

// Read one bounded, owned, unpublished temporary; never treat it as authority.
func (j *journal) nativeRetirementTemporary(prefix string, limit int64) ([]byte, error) {
	// A fresh directory description does not share/reposition the journal offset.
	fd, err := unix.Openat(int(j.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "retirement-temporary-observer")
	defer dir.Close()
	names, err := dir.Readdirnames(17)
	if err != nil && err != io.EOF || len(names) > 16 {
		return nil, ErrInvalid
	}
	name := ""
	for _, n := range names {
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ".tmp") {
			if name != "" || !validID(ID(strings.TrimSuffix(strings.TrimPrefix(n, prefix), ".tmp"))) {
				return nil, ErrInvalid
			}
			name = n
		}
	}
	if name == "" {
		return nil, ErrMissing
	}
	f, err := child(dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var st, parent unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if err = unix.Fstat(int(dir.Fd()), &parent); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Dev != parent.Dev || st.Size <= 0 || st.Size > limit {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != st.Size {
		return nil, ErrInvalid
	}
	return raw, nil
}
