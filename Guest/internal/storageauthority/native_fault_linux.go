//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storageauthority

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// NativeFaultStage is deliberately closed. These adapters are linked only into
// the explicitly tagged native test binary; there is no production activation.
type NativeFaultStage uint8

const (
	NativeDataFsync NativeFaultStage = iota + 1
	NativePostCreateNamespace
	NativeRetireIntent
	NativeRetireFinalSyncfs
	NativeRetireReceipt
	NativeRetireBarrierClear
	NativeRetireLostReply
)

type NativeFaultError uint8

const (
	NativeEIO NativeFaultError = iota + 1
	NativeENOSPC
	NativeDropReply
)

// NativeFaultPlan selects one immutable S/E/P/V/A and DATA sequence. It contains
// no key, principal, path, PID, or callback. The matrix is runtime-only:
// Prepare must be empty, not a wildcard for a PREPARE identity.
type NativeFaultPlan struct {
	Stage                                     NativeFaultStage
	Error                                     NativeFaultError
	Store, Epoch, Prepare, Volume, Attachment ID
	Sequence                                  uint64
	RetireOperation                           ID
}

func (p NativeFaultPlan) Validate() error {
	if p.Stage < NativeDataFsync || p.Stage > NativeRetireLostReply ||
		(p.Error != NativeEIO && p.Error != NativeENOSPC && p.Error != NativeDropReply) ||
		!validID(p.Store) || !validID(p.Epoch) || !validID(p.Volume) ||
		!validID(p.Attachment) || p.Prepare != "" {
		return ErrInvalid
	}
	if p.Stage <= NativePostCreateNamespace {
		if p.RetireOperation != "" || p.Error == NativeDropReply || p.Sequence == 0 || p.Sequence > 16 {
			return ErrInvalid
		}
	} else if !validID(p.RetireOperation) || p.Sequence != 0 || (p.Stage == NativeRetireLostReply) != (p.Error == NativeDropReply) {
		return ErrInvalid
	}
	return nil
}

func (p NativeFaultPlan) Matches(b Binding) bool {
	return b.Store == p.Store && b.Prepare == p.Prepare && b.Volume == p.Volume &&
		b.Attachment == p.Attachment && b.Role == RuntimeRole && b.Mode == ReadWrite
}

// NativeFaultWitness observes real obligations and injects one fixed failure.
// It cannot admit, retire, complete durability, mint a principal, or clear poison.
type NativeFaultWitness struct {
	owner                                 *Authority
	plan                                  NativeFaultPlan
	fired, barriers, barrierOK, finalSync atomic.Uint32
	inBarrier, durable                    atomic.Bool
}

func (a *Authority) NewNativeFaultWitness(p NativeFaultPlan) (*NativeFaultWitness, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return nil, err
	}
	if a.s.Store.ID != p.Store || a.s.Epoch != p.Epoch || len(a.s.Attachments) != 0 || a.inflight != 0 || a.dataIO != nil {
		return nil, ErrConflict
	}
	if a.j.fault != nil || a.j.afterStep != nil {
		return nil, ErrConflict
	}
	w := &NativeFaultWitness{owner: a, plan: p}
	// Hooks are private journal boundaries; all unselected IO remains unchanged.
	a.j.fault = w.journalFault
	a.j.afterStep = func(step string) {
		if step == "barrier-clear-sync" && w.retirementMatches(Drained) && w.barrierOK.Load() == 1 {
			w.durable.Store(true)
		}
	}
	realBarrier := a.barrier
	a.barrier = func(b Binding, root *os.File) error {
		a.mu.Lock()
		selected := p.Matches(b) && w.retirementMatches(Retiring)
		a.mu.Unlock()
		if !selected {
			return realBarrier(b, root)
		}
		w.inBarrier.Store(true)
		w.barriers.Add(1)
		defer w.inBarrier.Store(false)
		err := realBarrier(b, root)
		if err == nil {
			w.barrierOK.Add(1)
		}
		return err
	}
	return w, nil
}

// ReadyForInstall checks exact ownership without exposing the owner. Recheck
// freshness at installation: a witness minted before DATA registration must not
// authorize a later install after the connection (or even its session) closes.
func (w *NativeFaultWitness) ReadyForInstall(owner *Authority) bool {
	if w == nil || owner == nil || w.owner != owner {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.available() == nil && owner.s.Store.ID == w.plan.Store &&
		owner.s.Epoch == w.plan.Epoch && len(owner.s.Attachments) == 0 &&
		owner.inflight == 0 && owner.dataIO == nil
}

// NativeFaultObservation is bounded evidence, not a drain receipt.
type NativeFaultObservation struct{ Fired, BarrierCalls, BarrierSucceeded, FinalSyncCalls uint32 }

func (w *NativeFaultWitness) Observation() NativeFaultObservation {
	return NativeFaultObservation{w.fired.Load(), w.barriers.Load(), w.barrierOK.Load(), w.finalSync.Load()}
}

func (w *NativeFaultWitness) fire() error {
	if !w.fired.CompareAndSwap(0, 1) {
		return nil
	}
	if w.plan.Error == NativeENOSPC {
		return unix.ENOSPC
	}
	return unix.EIO
}

func (w *NativeFaultWitness) DataFault() error {
	if w.plan.Stage > NativePostCreateNamespace || !w.Pending() {
		return nil
	}
	return w.fire()
}

// Called only by the real registry syncfs seam after its final owners close.
// inBarrier identifies the authority operation, not ownership of the registry
// gate. The caller must supply the actual Barrier binding held under that gate.
func (w *NativeFaultWitness) FinalSyncFault(binding Binding) error {
	if !w.plan.Matches(binding) || !w.inBarrier.Load() {
		return nil
	}
	w.finalSync.Add(1)
	if w.plan.Stage == NativeRetireFinalSyncfs {
		return w.fire()
	}
	return nil
}

// DropReply is one-way and only becomes eligible after REAL barrier-clear sync.
func (w *NativeFaultWitness) DropReply() bool {
	return w.plan.Stage == NativeRetireLostReply && w.durable.Load() && w.fired.CompareAndSwap(0, 1)
}

// Called under owner.mu (journal hooks already hold it). A persisted operation
// digest and exact runtime tuple distinguish the target retirement from others.
func (w *NativeFaultWitness) retirementMatches(phase Phase) bool {
	a, p := w.owner, w.plan
	rec, ok := a.s.Attachments[p.Attachment]
	return ok && a.fault == nil && a.s.Epoch == p.Epoch && p.Matches(rec.Binding) && rec.Phase == phase && rec.Retirement == p.RetireOperation && p.RetireOperation != ""
}

func (w *NativeFaultWitness) journalFault(step string) error {
	p, a := w.plan, w.owner
	if w.fired.Load() != 0 {
		return nil
	}
	if step == "barrier-clear-sync" && p.Stage == NativeRetireBarrierClear && w.retirementMatches(Drained) && w.barrierOK.Load() == 1 {
		return w.fire()
	}
	if step != "state-sync" || !w.retirementMatches(Retiring) {
		return nil
	}
	op, persisted := a.s.Operations[p.RetireOperation]
	if p.Stage == NativeRetireIntent && !persisted && w.barriers.Load() == 0 && w.pendingStateMatches(Retiring) {
		return w.fire()
	}
	if p.Stage == NativeRetireReceipt && persisted && op == digest("retire", RetireRequest{p.RetireOperation, p.Store, p.Volume, p.Attachment, a.s.Attachments[p.Attachment].Binding.Launch}) && w.barrierOK.Load() == 1 && w.pendingStateMatches(Drained) {
		return w.fire()
	}
	return nil
}

// state-sync follows the real temp-file write. Inspect that bounded candidate
// while owner.mu serializes journal writers: an unrelated commit cannot trigger
// receipt injection merely because the target attachment remains RETIRING.
func (w *NativeFaultWitness) pendingStateMatches(phase Phase) bool {
	a, p := w.owner, w.plan
	fd, err := unix.Openat(int(a.j.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	dir := os.NewFile(uintptr(fd), "native-journal-observer")
	defer dir.Close()
	names, err := dir.Readdirnames(16)
	if err != nil && err != io.EOF || len(names) == 16 {
		return false
	}
	candidate := ""
	for _, name := range names {
		if strings.HasPrefix(name, "state-") && strings.HasSuffix(name, ".tmp") && validID(ID(strings.TrimSuffix(strings.TrimPrefix(name, "state-"), ".tmp"))) {
			if candidate != "" {
				return false
			}
			candidate = name
		}
	}
	if candidate == "" {
		return false
	}
	f, err := child(a.j.dir, candidate, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	var next diskState
	d := json.NewDecoder(io.LimitReader(f, a.j.maxBytes+1))
	d.DisallowUnknownFields()
	if d.Decode(&next) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	rec := next.Attachments[p.Attachment]
	if next.Epoch != p.Epoch || next.Store.ID != p.Store || next.Revision != a.s.Revision+1 || !p.Matches(rec.Binding) || rec.Phase != phase || rec.Retirement != p.RetireOperation || next.Operations[p.RetireOperation] != digest("retire", RetireRequest{p.RetireOperation, p.Store, p.Volume, p.Attachment, rec.Binding.Launch}) {
		return false
	}
	if phase == Retiring {
		return rec.Receipt == nil
	}
	return rec.Receipt != nil && *rec.Receipt == (Receipt{SchemaVersion, p.Store, p.Volume, p.Attachment, rec.Binding.Launch, p.Prepare, next.Revision})
}

func (w *NativeFaultWitness) Plan() NativeFaultPlan {
	if w == nil {
		return NativeFaultPlan{}
	}
	return w.plan
}

func (j *journal) readNativeFaultRecord() (record durabilityRecord, err error) {
	f, err := child(j.dir, dataIOName, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return record, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, maxDurabilityBytes+1))
	d.DisallowUnknownFields()
	err = d.Decode(&record)
	if err == nil && d.Decode(new(any)) != io.EOF {
		err = ErrInvalid
	}
	return record, err
}

func (w *NativeFaultWitness) Pending() bool {
	if w == nil || w.owner == nil {
		return false
	}
	a := w.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fault != nil || a.dataIO == nil || a.dataIO.completed {
		return false
	}
	g := a.dataIO.guard
	if g == nil || g.released || g.epoch != w.plan.Epoch || !w.plan.Matches(g.binding) {
		return false
	}
	// Read the actual persisted record, not a test-supplied success assertion.
	record, err := a.j.readNativeFaultRecord()
	return err == nil && record.Epoch == w.plan.Epoch && record.Binding == g.binding && record.Sequence == w.plan.Sequence
}
