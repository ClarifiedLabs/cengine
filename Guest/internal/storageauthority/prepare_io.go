package storageauthority

import (
	"strings"

	"golang.org/x/sys/unix"
)

// PrepareCompatibilityIO is evidence from an actual, owned IO boundary.
// Occurrence is fixed to FIRST (1 when fired), never a caller-selected ordinal.
// Operation/Sequence are captured from production retirement/request ownership.
// A fired IO fault is not a successful operation, receipt, or recovery claim.
type PrepareCompatibilityIO struct {
	Point      string
	Errno      string
	Fired      bool
	Occurrence uint32
	Sequence   uint64
	Operation  ID
}

type prepareIOCase struct {
	point, scope, boundary, errnoName string
	errno                             unix.Errno
}

// This closed catalog is independent of journal names accepted by test hooks.
// There is no path, operation, sequence, errno number, or "next fsync" input.
func prepareIOCaseFor(stage string) (prepareIOCase, bool) {
	var c prepareIOCase
	switch {
	case strings.HasPrefix(stage, "io-eio-"):
		c.point, c.errnoName, c.errno = strings.TrimPrefix(stage, "io-eio-"), "EIO", unix.EIO
	case strings.HasPrefix(stage, "io-enospc-"):
		c.point, c.errnoName, c.errno = strings.TrimPrefix(stage, "io-enospc-"), "ENOSPC", unix.ENOSPC
	default:
		return c, false
	}
	c.scope = c.point
	switch c.point {
	case "copy-operation-write":
		c.scope, c.boundary = "copy-operation", "copy-op-write"
	case "copy-operation-sync":
		c.scope, c.boundary = "copy-operation", "copy-op-sync"
	case "provision-rename":
		c.scope, c.boundary = "provision", "copy-private-publish"
	case "provision-parent-sync":
		c.scope, c.boundary = "provision", "copy-public-parent-sync"
	case "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs":
		c.scope, c.boundary = "finish-cleanup", c.point
	case "seal-persist", "cleaning-persist", "finish-persist", "retire-intent-persist", "retire-receipt-persist":
		c.boundary = "state-sync"
	case "retire-barrier-persist":
		c.boundary = "marker-sync"
	case "retire-barrier-clear-persist":
		c.boundary = "barrier-clear-sync"
	default:
		return prepareIOCase{}, false
	}
	return c, true
}

// Called only with authority.mu held, around the exact operation below. The
// hook is private and separate from j.fault; neither existing test hook is
// replaced. No scope survives a return or spans the unlocked filesystem barrier.
func (a *Authority) withPrepareIO(scope string, binding Binding, sequence uint64, operation ID, fn func() error) error {
	w := a.prepareCompatibility.Load()
	if !prepareCompatibilityEnabled() || w == nil {
		return fn()
	}
	c, ok := prepareIOCaseFor(w.plan.Stage)
	if !ok || c.scope != scope || w.owner != a || w.plan.Target != binding || w.plan.Epoch != a.s.Epoch || w.plan.Controller != a.s.Controller || binding.Store != a.s.Store.ID || a.available() != nil || a.s.Prepares[binding.Prepare].Phase != Pending {
		return fn()
	}
	rec := a.s.Attachments[binding.Attachment]
	rt := a.runtime[binding.Attachment]
	if rec.Binding != binding || rt == nil {
		return fn()
	}
	if strings.HasPrefix(scope, "retire-") {
		phase := Retiring
		if scope == "retire-barrier-clear-persist" {
			phase = Drained
		}
		if rec.Phase != phase || !validID(operation) || rec.Retirement != operation || (scope != "retire-intent-persist" && (rt.count != 0 || rt.done == nil)) {
			return fn()
		}
	} else if rec.Phase != Active || sequence == 0 || rt.count <= 0 {
		return fn()
	}
	if a.j.prepareIOFault != nil {
		return ErrConflict // never overwrite another scope
	}
	a.j.prepareIOFault = func(boundary string) error {
		if boundary != c.boundary || a.available() != nil {
			return nil
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.snapshot.State != "armed" || w.snapshot.IO == nil || w.snapshot.IO.Fired {
			return nil
		}
		w.snapshot.IO.Fired, w.snapshot.IO.Occurrence = true, 1
		w.snapshot.IO.Sequence, w.snapshot.IO.Operation = sequence, operation
		w.snapshot.State, w.snapshot.Sequence = "observed", sequence
		w.snapshot.Admitted = sequence != 0
		w.snapshot.RetireOperation = operation
		return c.errno
	}
	defer func() { a.j.prepareIOFault = nil }()
	return fn()
}

// Only the exact live obligation for this guard/action/intent may fault a copy
// commit. Direct legacy calls and unrelated state-sync commits cannot consume it.
func (g *Guard) commitPrepareCopyIO(point string, next *diskState) error {
	a := g.token.owner
	t := a.copyIO
	action := ""
	switch point {
	case "seal-persist":
		action = CopyOperationSeal
	case "cleaning-persist":
		action = CopyOperationCleanup
	case "finish-persist":
		action = CopyOperationFinish
	}
	if action == "" || t == nil || t.completed || t.guard != g.token || g.token.released || t.record.Epoch != a.s.Epoch || t.record.Controller != a.s.Controller || t.record.Binding != g.token.binding || t.record.Action != action || t.record.Intent != next.Copy.Intents[g.token.binding.Volume].ID {
		return a.commit(next)
	}
	return a.withPrepareIO(point, g.token.binding, t.record.Sequence, "", func() error { return a.commit(next) })
}

// Called with authority.mu held. Neither a legacy direct operation nor another
// admitted guard sharing the binding owns this request's durable obligation.
func (g *Guard) withPrepareFilesystemIO(scope, action string, id ID, fn func() error) error {
	a := g.token.owner
	t := a.copyIO
	if t == nil || t.completed || t.guard != g.token || g.token.released || g.token.epoch != a.s.Epoch || t.record.Epoch != a.s.Epoch || t.record.Controller != a.s.Controller || t.record.Binding != g.token.binding || t.record.Action != action || t.record.Intent != id || a.s.Copy.Intents[g.token.binding.Volume].ID != id {
		return fn()
	}
	return a.withPrepareIO(scope, g.token.binding, t.record.Sequence, "", fn)
}

// PrepareCompatibilityCleanupIO is the trusted server's narrow pre-sync hook
// after an owned FINISH unlink or root restoration. It accepts only the four
// closed cleanup points, no path, errno, ordinal, sequence or operation selector.
// The live BeginCopyOperation token supplies the request provenance. The caller
// must propagate the error through normal registry latching and obligation
// completion; observation never completes an operation or clears its fence.
func (g *Guard) PrepareCompatibilityCleanupIO(id ID, point string) error {
	if !prepareCompatibilityEnabled() {
		return nil
	}
	switch point {
	case "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs":
	default:
		return nil
	}
	a, err := g.copyAuthority()
	if err != nil || a.prepareCompatibility.Load() == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil || intent.Phase != CopyCleaning {
		return nil
	}
	return g.withPrepareFilesystemIO("finish-cleanup", CopyOperationFinish, id, func() error {
		if a.j.prepareIOFault != nil {
			return a.j.prepareIOFault(point)
		}
		return nil
	})
}

func (a *Authority) prepareRetireIO(point string, rec Attachment, fn func() error) error {
	return a.withPrepareIO(point, rec.Binding, 0, rec.Retirement, fn)
}
