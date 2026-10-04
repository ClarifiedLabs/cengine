package storageauthority

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
)

// These names are independent of the wire's numeric action ABI. Only these
// trusted, phase-bounded server operations have a process-crash replay contract.
const (
	CopyOperationBegin         = "begin"
	CopyOperationProvision     = "provision"
	CopyOperationSeal          = "seal"
	CopyOperationCleanup       = "cleanup"
	CopyOperationFinish        = "finish"
	CopyOperationRollback      = "rollback-sealed"
	CopyOperationDirectoryTail = "prepare-directory-tail"
	copyOperationName          = "copy-operation"
	maxCopyOperationBytes      = 16384
)

type copyOperationRecord struct {
	Prior      *copyOperationRecord `json:",omitempty"`
	Version    int
	Epoch      ID
	Controller Controller
	Binding    Binding
	Root       RootIdentity
	Sequence   uint64
	Action     string
	Intent     ID
	Before     CopyIntent
}
type copyOperationToken struct {
	guard          *guardToken
	record         copyOperationRecord
	completed      bool
	clearingReplay bool // only while committing the already-reserved ledger clear
	reusesReplay   bool // exact replay or read-only auxiliary action on a pending replay
}
type CopyOperationObligation struct{ token *copyOperationToken }

func (a *Authority) copyReplayPending(volume ID) bool {
	r, pending := a.s.CopyReplay[volume]
	i, exists := a.s.Copy.Intents[volume]
	return pending && exists && (i.Phase != CopyCompleted || a.completedCopyTailPending(volume)) && (r.Action == CopyOperationBegin || r.Intent == i.ID)
}

func copyDataAction(action string) bool {
	return action == CopyOperationRollback || action == CopyOperationDirectoryTail
}

func (a *Authority) completedCopyTailPending(volume ID) bool {
	r, pending := a.s.CopyReplay[volume]
	i, exists := a.s.Copy.Intents[volume]
	if !pending || !exists || r.Action != CopyOperationDirectoryTail || i.Phase != CopyCompleted || r.Intent != i.ID {
		return false
	}
	// Ownership may move only through the validated all-drained PREPARE chain.
	i.Owner, i.Epoch = r.Binding, r.Epoch
	return i == r.Before
}

// Startup invokes every new-action preflight only after all records and roots
// validate, but before any journal recovery, epoch commit, or marker removal.
func (a *Authority) preflightCopyRecovery(preflight func(*os.File, string, string, CopyIntent) error) error {
	for volume, replay := range a.s.CopyReplay {
		if !copyDataAction(replay.Action) {
			continue
		}
		root := a.roots[volume]
		if preflight == nil || root == nil {
			return ErrRepairRequired
		}
		if err := preflight(root, a.s.Store.DeviceID, replay.Action, a.s.Copy.Intents[volume]); err != nil {
			return fmt.Errorf("%w: copy recovery preflight: %w", ErrRepairRequired, err)
		}
	}
	return nil
}

// PendingCopyOperation returns the actionable replay for the exact live RW
// PREPARE intent, without exposing the private operation record or old owner.
func (g *Guard) PendingCopyOperation(id ID) (string, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return "", err
	}
	if !a.validCopyRoot(intent.Root, g.token.binding) {
		return "", ErrConflict
	}
	if a.copyReplayPending(g.token.binding.Volume) {
		return a.s.CopyReplay[g.token.binding.Volume].Action, nil
	}
	return "", nil
}

// CheckCopyReplay fences ordinary DATA, including reads which may dirty atime.
// Private identity/control operations use their exact intent checks instead.
func (g *Guard) CheckCopyReplay() error {
	a, err := g.copyAuthority()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err = g.copyGuardLocked(false); err != nil {
		return err
	}
	if a.copyReplayPending(g.token.binding.Volume) {
		return ErrBlocked
	}
	return nil
}

// BeginCopyOperation runs under the namespace gate, before even the first
// control syscall. Begin records the exact attachment and pinned root without
// inventing an intent: startup permits only no change or its one BEGUN commit.
func (g *Guard) BeginCopyOperation(sequence uint64, action string, id ID) (*CopyOperationObligation, error) {
	return g.beginCopyOperation(sequence, action, id, false)
}

// BeginCopyDataOperation publishes whole-intent undo/tail evidence before DATA IO.
// It cannot replay pending work or accept any ordinary private-control action.
func (g *Guard) BeginCopyDataOperation(sequence uint64, action string, id ID) (*CopyOperationObligation, error) {
	if !copyDataAction(action) {
		return nil, ErrInvalid
	}
	return g.beginCopyOperation(sequence, action, id, true)
}

func (g *Guard) beginCopyOperation(sequence uint64, action string, id ID, data bool) (*CopyOperationObligation, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err = g.copyGuardLocked(!data); err != nil {
		return nil, err
	}
	if sequence == 0 {
		return nil, ErrInvalid
	}
	if a.dataIO != nil || a.copyIO != nil {
		return nil, ErrBusy
	}
	before := a.s.Copy.Intents[g.token.binding.Volume]
	if data {
		before, err = g.copyDataIntentLocked()
		if err != nil {
			return nil, err
		}
		if !validID(id) || before.ID != id {
			return nil, ErrUnauthorized
		}
	} else if action == CopyOperationBegin {
		if id != "" {
			return nil, ErrInvalid
		}
		if before != (CopyIntent{}) && (before.Phase != CopyCompleted || a.copyReplayPending(g.token.binding.Volume)) && (before.Owner != g.token.binding || before.Epoch != g.token.epoch) {
			return nil, ErrBlocked
		}
	} else {
		before, err = g.ownedCopyLocked(id)
		if err != nil {
			return nil, err
		}
	}
	allowed := false
	switch action {
	case CopyOperationBegin:
		allowed = true
	case CopyOperationProvision:
		allowed = before.Phase == CopyBegun || before.Phase == CopyBound || before.Phase == CopySealed
	case CopyOperationSeal:
		allowed = before.Phase == CopyBound || before.Phase == CopySealed
	case CopyOperationCleanup:
		allowed = before.Phase == CopyBound || before.Phase == CopySealed || before.Phase == CopyCleaning
	case CopyOperationFinish:
		allowed = before.Phase == CopyCleaning || (before.Phase == CopyBegun && !before.InitialCaptured)
	case CopyOperationRollback:
		allowed = before.Phase == CopySealed || (!data && before.Phase == CopyCleaning)
	case CopyOperationDirectoryTail:
		allowed = before.Phase == CopySealed || before.Phase == CopyCleaning || before.Phase == CopyCompleted
	}
	if !data && copyDataAction(action) && !(action == CopyOperationRollback && before.Phase == CopySealed && !a.copyReplayPending(g.token.binding.Volume)) && (!a.copyReplayPending(g.token.binding.Volume) || a.s.CopyReplay[g.token.binding.Volume].Action != action) {
		return nil, ErrBlocked
	}
	if !allowed {
		return nil, ErrConflict
	}
	if replay, ok := a.s.CopyReplay[g.token.binding.Volume]; ok && a.copyReplayPending(g.token.binding.Volume) {
		// Begin only returns the already-owned intent; CLEANING preflight is read-only.
		if action != replay.Action && action != CopyOperationBegin && !(!copyDataAction(replay.Action) && action == CopyOperationCleanup && before.Phase == CopyCleaning) {
			return nil, ErrBlocked
		}
	}
	root, err := identity(a.roots[g.token.binding.Volume])
	if err != nil {
		return nil, a.poison(err)
	}
	controller, version := a.s.Controller, 1
	if a.s.Lifecycle != nil {
		version = 2
		// DATA belongs to its PREPARE, which survives a live controller takeover.
		// Pin that bounded durable owner context, not an unrelated newer caller.
		var ok bool
		controller, ok = a.lifecycleCopyController(g.token.binding, a.s.Epoch)
		if !ok {
			return nil, ErrConflict
		}
	}
	rec := copyOperationRecord{Version: version, Epoch: a.s.Epoch, Controller: controller, Binding: g.token.binding, Root: root, Sequence: sequence, Action: action, Intent: id, Before: before}
	if pending, ok := a.s.CopyReplay[g.token.binding.Volume]; ok && a.copyReplayPending(g.token.binding.Volume) && pending.Action != action {
		rec.Prior = &pending
	}
	// Use the same reservation as subsequent commits: a new marker needs one
	// startup and one clear; a reconstructed replay already owns its clear.
	// Do not invent a ledger entry AND increment Revision (double charging).
	// Further restarts/ownership replacements need their own revision headroom;
	// replay itself must not re-admit the already-funded operation as new work.
	token := &copyOperationToken{guard: g.token, record: rec, reusesReplay: a.copyReplayPending(rec.Binding.Volume)}
	probe := &Authority{limits: a.limits, copyIO: token}
	encoded, err := json.Marshal(a.s)
	if err != nil {
		return nil, err
	}
	if err = probe.capacity(a.s, int64(len(encoded))); err != nil {
		return nil, err
	}
	write := func() error { return a.j.writeCopyOperation(rec) }
	// The closed copy-operation cases mean the FIRST owned BEGIN marker,
	// never a caller-selected provision/seal/cleanup/finish marker.
	if action == CopyOperationBegin {
		err = a.withPrepareIO("copy-operation", g.token.binding, sequence, "", write)
	} else {
		err = write()
	}
	if err != nil {
		return nil, a.poison(err)
	}
	a.copyIO = token
	return &CopyOperationObligation{token}, nil
}

func (o *CopyOperationObligation) Complete(cause error) error { return o.CompleteRequest(cause, true) }

// CompleteRequest distinguishes an ordinary rejected request from successful replay.
func (o *CopyOperationObligation) CompleteRequest(cause error, succeeded bool) error {
	if o == nil || o.token == nil || o.token.guard == nil {
		return ErrUnauthorized
	}
	t := o.token
	a := t.guard.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if t.completed || t.guard.released || a.copyIO != t {
		return ErrClosed
	}
	if err := a.available(); err != nil {
		return err
	}
	// Returned IO failure is NOT the process-crash case. Quarantine persists the
	// existing generic uncertainty marker before anything can erase this record.
	if cause != nil {
		return a.poison(cause)
	}
	if !a.matchCopyOperation(t.record) {
		return a.poison(ErrRepairRequired)
	}
	if replay, ok := a.s.CopyReplay[t.record.Binding.Volume]; ok && succeeded && replay.Action == t.record.Action {
		next := a.clone()
		delete(next.CopyReplay, t.record.Binding.Volume)
		// This commit consumes the existing clear reservation. The still-live
		// marker is not new growth; retain it on any failure for fail-closed IO.
		t.clearingReplay = true
		err := a.commit(next)
		t.clearingReplay = false
		if err != nil {
			return err
		}
	}
	if err := a.j.removeCopyOperation(); err != nil {
		return a.poison(err)
	}
	t.completed = true
	a.copyIO = nil
	a.wakeCopyFence(t.record.Binding.Volume)
	if succeeded && t.record.Action == CopyOperationProvision && a.s.Copy.Intents[t.record.Binding.Volume].Phase == CopyBound {
		t.guard.boundSequence = t.record.Sequence
	}
	return nil
}

// matchCopyOperation accepts only the exact idempotent transitions, never an
// arbitrary newer ledger, foreign root, owner, transaction, digest or cleanup.
func (a *Authority) matchCopyOperation(r copyOperationRecord) bool {
	controller, version := a.s.Controller, 1
	if a.s.Lifecycle != nil {
		version = 2
		var ok bool
		controller, ok = a.lifecycleCopyController(r.Binding, r.Epoch)
		if !ok {
			return false
		}
	}
	if r.Version != version || r.Sequence == 0 || !validID(r.Epoch) || r.Controller != controller || r.Binding.Role != PrepareRole || r.Binding.Mode != ReadWrite {
		return false
	}
	attachment, ok := a.s.Attachments[r.Binding.Attachment]
	if !ok || attachment.Binding != r.Binding || a.s.Volumes[r.Binding.Volume].Root != r.Root {
		return false
	}
	if r.Epoch != a.s.Epoch {
		previous, ok := a.s.CopyReplay[r.Binding.Volume]
		if !ok || !reflect.DeepEqual(previous, r) && (r.Prior == nil || !reflect.DeepEqual(previous, *r.Prior)) {
			return false
		}
	}
	current := a.s.Copy.Intents[r.Binding.Volume]
	old := r.Before
	if r.Action == CopyOperationBegin {
		if r.Intent != "" {
			return false
		}
		if current == old {
			return true
		}
		return (old == (CopyIntent{}) || old.Phase == CopyCompleted) && current.ID != old.ID && validID(current.ID) && current.Owner == r.Binding && current.Epoch == r.Epoch && a.validCopyRoot(current.Root, r.Binding) && current == (CopyIntent{ID: current.ID, Owner: r.Binding, Epoch: r.Epoch, Root: current.Root, Phase: CopyBegun})
	}
	if !validID(r.Intent) || old.ID != r.Intent || old.Owner != r.Binding || old.Epoch != r.Epoch || !a.validCopyRoot(old.Root, r.Binding) {
		return false
	}
	switch r.Action {
	case CopyOperationProvision:
		if old.Phase != CopyBegun && old.Phase != CopyBound && old.Phase != CopySealed {
			return false
		}
		if old.Phase == CopyBegun {
			if current.Phase != CopyBegun && current.Phase != CopyBound {
				return false
			}
			if old.InitialCaptured && (current.Initial != old.Initial || !current.InitialCaptured) {
				return false
			}
			if current.Phase == CopyBound && (!current.InitialCaptured || !validCopyDirectory(current.Transaction)) {
				return false
			}
			current.Phase, current.Transaction = old.Phase, old.Transaction
			current.Initial, current.InitialCaptured = old.Initial, old.InitialCaptured
		}
	case CopyOperationSeal:
		if old.Phase != CopyBound && old.Phase != CopySealed {
			return false
		}
		if old.Phase == CopyBound && current.Phase == CopySealed {
			current.Phase, current.ManifestDigest, current.ManifestSize = old.Phase, old.ManifestDigest, old.ManifestSize
		}
	case CopyOperationCleanup:
		if old.Phase != CopyBound && old.Phase != CopySealed && old.Phase != CopyCleaning {
			return false
		}
		if old.Phase != CopyCleaning && current.Phase == CopyCleaning {
			current.Phase, current.Cleanup = old.Phase, old.Cleanup
		}
	case CopyOperationRollback:
		if old.Phase != CopySealed && old.Phase != CopyCleaning {
			return false
		}
		if old.Phase == CopyCleaning && (old.ManifestSize == 0 || !validCopyCleanup(old, old.Cleanup)) {
			return false
		}
		if old.Phase == CopySealed && current.Phase == CopyCleaning {
			if !validCopyCleanup(current, current.Cleanup) {
				return false
			}
			current.Phase, current.Cleanup = old.Phase, old.Cleanup
		}
	case CopyOperationDirectoryTail:
		if old.Phase != CopySealed && old.Phase != CopyCleaning && old.Phase != CopyCompleted {
			return false
		}
	case CopyOperationFinish:
		if old.Phase != CopyCleaning && !(old.Phase == CopyBegun && !old.InitialCaptured) {
			return false
		}
		if current.Phase == CopyCompleted {
			current.Phase = old.Phase
		}
	default:
		return false
	}
	return current == old
}

func (j *journal) writeCopyOperation(r copyOperationRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > maxCopyOperationBytes {
		return ErrLimit
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	// Inert until publication. The private registry's lifetime flock excludes
	// other writers; a no-follow absence check prevents replacing any evidence.
	temp := "copy-op-" + string(id) + ".tmp"
	var f *os.File
	if err = j.step("copy-op-open", func() (e error) {
		f, e = child(j.dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
		return
	}); err != nil {
		return err
	}
	defer f.Close()
	if err = j.step("copy-op-write", func() error { return writeFull(f, data) }); err != nil {
		return err
	}
	if err = j.step("copy-op-sync", f.Sync); err != nil {
		return err
	}
	if err = j.step("copy-op-close", f.Close); err != nil {
		return err
	}
	if err = j.step("copy-op-publish", func() error {
		var st unix.Stat_t
		err := unix.Fstatat(int(j.dir.Fd()), copyOperationName, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return ErrConflict
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		return unix.Renameat(int(j.dir.Fd()), temp, int(j.dir.Fd()), copyOperationName)
	}); err != nil {
		return err
	}
	return j.step("copy-op-parent-sync", j.dir.Sync)
}
func (j *journal) removeCopyOperation() error {
	if err := j.step("copy-op-unlink", func() error { return unix.Unlinkat(int(j.dir.Fd()), copyOperationName, 0) }); err != nil {
		return err
	}
	return j.step("copy-op-clear-sync", j.dir.Sync)
}

// Exclusive startup ownership validates both the journal and descriptor-bound
// roots first. Persist reconstruction before removing the operation slot. An
// interrupted authority commit still leaves generic uncertainty and fails closed.
func (a *Authority) loadCopyOperation() error {
	f, err := child(a.j.dir, copyOperationName, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return ErrRepairRequired
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxCopyOperationBytes {
		return ErrRepairRequired
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCopyOperationBytes+1))
	if err != nil {
		return ErrRepairRequired
	}
	r, err := a.decodeCopyOperation(data)
	if err != nil {
		return err
	}
	if a.s.CopyReplay == nil {
		a.s.CopyReplay = map[ID]copyOperationRecord{}
	}
	if r.Prior == nil {
		a.s.CopyReplay[r.Binding.Volume] = r
	}
	return nil
}

// Read-only validation shared by the published obligation and a complete but
// unpublished candidate. Neither parsing nor matching grants DATA authority.
func (a *Authority) decodeCopyOperation(data []byte) (copyOperationRecord, error) {
	var r copyOperationRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, ErrRepairRequired
	}
	canonical, canonicalErr := json.Marshal(r)
	var extra any
	if canonicalErr != nil || !bytes.Equal(canonical, data) || dec.Decode(&extra) != io.EOF || !a.matchCopyOperation(r) {
		return r, ErrRepairRequired
	}
	if r.Prior != nil {
		pending, ok := a.s.CopyReplay[r.Binding.Volume]
		if !ok || !reflect.DeepEqual(pending, *r.Prior) || (r.Action != CopyOperationBegin && !(!copyDataAction(pending.Action) && r.Action == CopyOperationCleanup && a.s.Copy.Intents[r.Binding.Volume].Phase == CopyCleaning)) {
			return r, ErrRepairRequired
		}
	}
	return r, nil
}
func (a *Authority) clearStartupCopyOperation() error {
	// No-follow open also handles the ordinary marker-absent startup.
	f, err := child(a.j.dir, copyOperationName, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	f.Close()
	return a.j.removeCopyOperation()
}

// Lifecycle keeps no unbounded controller-key history. The exact original
// PREPARE is the durable witness for this obligation's E/C/key; the ordinary
// binding and drained-successor checks still apply independently.
func (a *Authority) lifecycleCopyController(binding Binding, epoch ID) (Controller, bool) {
	p, ok := a.s.Prepares[binding.Prepare]
	if !ok || p.Context == nil || p.Context.ServiceEpoch != epoch || p.Context.ControllerEpoch == 0 ||
		p.Context.ControllerEpoch > a.s.Controller.Epoch || !validKey(p.Context.ControllerKey) ||
		p.Context.ControllerKey == a.s.Bootstrap ||
		(p.Context.ControllerEpoch == a.s.Controller.Epoch && p.Context.ControllerKey != a.s.Controller.Key) {
		return Controller{}, false
	}
	return Controller{p.Context.ControllerEpoch, p.Context.ControllerKey}, true
}

// Persisted reconstruction survives later startups and drained ownership transfers.
// Its owner may change only along the journal's explicit all-drained PREPARE chain.
func (a *Authority) validateCopyReplays() error {
	if len(a.s.CopyReplay) > len(a.s.Volumes) {
		return ErrInvalid
	}
	for volume, r := range a.s.CopyReplay {
		controller, ok := a.lifecycleCopyController(r.Binding, r.Epoch)
		knownController := ok && controller == r.Controller
		if volume != r.Binding.Volume || r.Controller.Epoch == 0 || r.Controller.Epoch > a.s.Controller.Epoch || !knownController {
			return ErrInvalid
		}
		current, exists := a.s.Copy.Intents[volume]
		// A fresh Begin may crash before replacing a predecessor's COMPLETED
		// intent. That unchanged Before is not a backwards ownership transfer.
		unchangedBegin := r.Action == CopyOperationBegin && current == r.Before && current.Phase == CopyCompleted
		if exists && current.Owner != r.Binding && !unchangedBegin {
			owner := r.Binding.Prepare
			for steps := 0; owner != current.Owner.Prepare; steps++ {
				if steps >= len(a.s.Prepares) {
					return ErrInvalid
				}
				p, ok := a.s.Prepares[owner]
				if !ok || p.Phase != Replaced || !validID(p.Successor) {
					return ErrInvalid
				}
				for _, b := range p.Attachments {
					if a.s.Attachments[b.Attachment].Phase != Drained {
						return ErrInvalid
					}
				}
				owner = p.Successor
			}
			current.Owner, current.Epoch = r.Binding, r.Epoch
		}
		state := *a.s
		state.Epoch, state.Controller = r.Epoch, r.Controller
		copyState := *a.s.Copy
		copyState.Intents = map[ID]CopyIntent{}
		for id, intent := range a.s.Copy.Intents {
			copyState.Intents[id] = intent
		}
		if exists {
			copyState.Intents[volume] = current
		}
		state.Copy = &copyState
		probe := Authority{s: &state}
		if !probe.matchCopyOperation(r) {
			return ErrInvalid
		}
	}
	return nil
}
