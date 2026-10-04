package storageauthority

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func copyCleaningBudgetFixture(t *testing.T) (*fixture, Volume, Binding, *Guard, CopyIntent) {
	t.Helper()
	f := newFixture(t, nil)
	v := f.volume("copy-budget")
	b, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	i, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
	must(t, err)
	return f, v, b, g, i
}

func TestCopyOperationNewMarkerExactRevisionAdmission(t *testing.T) {
	f, _, _, g, i := copyCleaningBudgetFixture(t)
	// Two lifecycle revisions remain reserved throughout.
	// Four workload revisions: finish, retirement intent/receipt, terminal P.
	// A new marker needs exactly two more: reconstruction startup and clear.
	f.a.s.Revision = ^uint64(0) - 7
	_, err := g.BeginCopyOperation(1, CopyOperationFinish, i.ID)
	wantErr(t, err, ErrLimit)
	if _, err = os.Stat(filepath.Join(f.path, registryName, copyOperationName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unfunded admission exposed marker", err)
	}
	must(t, f.a.available())
	f.a.s.Revision--
	must(t, f.a.j.persist(f.a.s))
	o := copyObligation(t, g, CopyOperationFinish, i.ID)
	must(t, o.CompleteRequest(nil, false))
	if f.a.s.Revision != ^uint64(0)-8 {
		t.Fatal("admission/rejected request consumed revision")
	}
}

func TestCopyOperationExactBudgetCrashRestartReplayClear(t *testing.T) {
	f, v, b, g, i := copyCleaningBudgetFixture(t)
	// Ten actual commits, with no slack at replay:
	// startup(1), old retirement(2), replacement(1), registration(1),
	// finish(1), replay clear(1), new retirement(2), terminal PREPARE(1).
	// Replacement's fresh attachment needs four more revisions than the six
	// reserved for the original operation and its original terminal ownership.
	f.a.s.Revision = ^uint64(0) - 12
	must(t, f.a.j.persist(f.a.s))
	copyObligation(t, g, CopyOperationFinish, i.ID)
	restartCopyOperation(t, f, g)
	if f.a.s.Revision != ^uint64(0)-11 || f.a.s.CopyReplay[v.ID].Action != CopyOperationFinish {
		t.Fatal("startup did not reconstruct with exactly one revision")
	}
	g = copySuccessor(t, f, b)
	b = g.token.binding
	if f.a.s.Revision != ^uint64(0)-7 {
		t.Fatal("ownership transfer revision accounting")
	}
	pending, err := g.PendingCopyOperation(i.ID)
	must(t, err)
	if pending != CopyOperationFinish {
		t.Fatal("wrong actionable replay", pending)
	}
	// Both read-only auxiliary and rejected exact replay reuse the reservation.
	o := copyObligation(t, g, CopyOperationBegin, "")
	_, err = g.BeginCopy(copyRoot(f, v))
	must(t, err)
	must(t, o.Complete(nil))
	o = copyObligation(t, g, CopyOperationFinish, i.ID)
	must(t, o.CompleteRequest(nil, false))
	wantErr(t, g.CheckCopyReplay(), ErrBlocked)
	o = copyObligation(t, g, CopyOperationFinish, i.ID)
	i = f.a.s.Copy.Intents[v.ID]
	cleanupHostCopy(t, f, g, i)
	must(t, o.Complete(nil))
	if len(f.a.s.CopyReplay) != 0 || f.a.copyIO != nil || f.a.s.Revision != ^uint64(0)-5 {
		t.Fatal("clear re-reserved instead of discharging")
	}
	if _, err = os.Stat(filepath.Join(f.path, registryName, copyOperationName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed marker remains", err)
	}
	must(t, g.CheckCopyReplay())
	_, err = g.PendingCopyOperation(i.ID)
	wantErr(t, err, ErrUnauthorized) // completed intents are not actionable
	g.Release()
	r := f.retire(b)
	must(t, f.a.CompletePrepare(f.control, CompleteRequest{mustID(t), b.Prepare, []Receipt{r}, Attestation{b.Prepare, true, true}}))
	if f.a.s.Revision != ^uint64(0)-2 {
		t.Fatal("did not use exactly the admitted revision budget")
	}
	must(t, f.a.validate())
	must(t, f.a.available())
}

func TestPendingCopyOperationExactScopeAndActions(t *testing.T) {
	for _, action := range []string{CopyOperationBegin, CopyOperationProvision, CopyOperationSeal, CopyOperationCleanup, CopyOperationFinish} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("pending")
			b, g := copyPrepare(t, f, v, ReadWrite)
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			if action == CopyOperationSeal || action == CopyOperationCleanup {
				i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
				must(t, err)
			}
			pending, err := g.PendingCopyOperation(i.ID)
			must(t, err)
			if pending != "" {
				t.Fatal("invented replay")
			}
			id := i.ID
			if action == CopyOperationBegin {
				id = ""
			}
			copyObligation(t, g, action, id)
			restartCopyOperation(t, f, g)
			g = copySuccessor(t, f, b)
			pending, err = g.PendingCopyOperation(i.ID)
			must(t, err)
			if pending != action {
				t.Fatal("lost exact action", pending)
			}
			_, err = g.PendingCopyOperation(mustID(t))
			wantErr(t, err, ErrUnauthorized)
			_, err = g.PendingCopyOperation("")
			wantErr(t, err, ErrUnauthorized)
			current := f.a.s.Copy.Intents[v.ID]
			bad := current
			bad.Root.Volume = mustID(t)
			f.a.s.Copy.Intents[v.ID] = bad
			_, err = g.PendingCopyOperation(i.ID)
			wantErr(t, err, ErrConflict)
			bad = current
			bad.Owner.Attachment = mustID(t)
			f.a.s.Copy.Intents[v.ID] = bad
			_, err = g.PendingCopyOperation(i.ID)
			wantErr(t, err, ErrUnauthorized)
			f.a.s.Copy.Intents[v.ID] = current
			runtimeVolume := f.volume("runtime")
			_, peer := f.runtime(runtimeVolume, ReadWrite)
			runtimeGuard, err := f.a.Admit(peer, runtimeVolume.ID, false)
			must(t, err)
			_, err = runtimeGuard.PendingCopyOperation(i.ID)
			wantErr(t, err, ErrUnauthorized)
			runtimeGuard.Release()
			_, ro := copyPrepare(t, f, f.volume("read-only"), ReadOnly)
			_, err = ro.PendingCopyOperation(i.ID)
			wantErr(t, err, ErrUnauthorized)
			for _, invalid := range []*Guard{nil, {}, {token: &guardToken{}}} {
				_, err = invalid.PendingCopyOperation(i.ID)
				wantErr(t, err, ErrUnauthorized)
			}
			g.Release()
			_, err = g.PendingCopyOperation(i.ID)
			wantErr(t, err, ErrClosed)
		})
	}
}

func TestCopyFreshBeginPrecommitPreservesCompletedOwnerAcrossTwoOpens(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("completed-owner")
	original, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	copyObligation(t, g, CopyOperationFinish, i.ID)
	must(t, g.FinishCopy(i.ID))
	completed := f.a.s.Copy.Intents[v.ID]
	restartCopyOperation(t, f, g)
	g = copySuccessor(t, f, original)
	successor := g.token.binding
	copyObligation(t, g, CopyOperationBegin, "")
	// No BeginCopy call: the marker belongs to successor but Before still
	// belongs to the completed predecessor. This is not reverse lineage.
	restartCopyOperation(t, f, g)
	for open := 0; open < 2; open++ {
		r := f.a.s.CopyReplay[v.ID]
		if r.Binding != successor || r.Before != completed || f.a.s.Copy.Intents[v.ID] != completed || completed.Owner != original || f.a.copyReplayPending(v.ID) {
			t.Fatal("precommit begin changed completed ownership or revived fence")
		}
		must(t, f.a.validate())
		if open == 0 {
			must(t, f.a.Close())
			f.a, err = f.openCurrent()
			must(t, err)
			f.control = f.authControl(f.controllerKey, f.a.s.Controller.Epoch)
		}
	}
	g = copySuccessor(t, f, successor)
	o := copyObligation(t, g, CopyOperationBegin, "")
	fresh, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	must(t, o.Complete(nil))
	if fresh.ID == completed.ID || fresh.Owner != g.token.binding || fresh.Epoch != f.a.s.Epoch || !reflect.DeepEqual(fresh.Root, completed.Root) || len(f.a.s.CopyReplay) != 0 {
		t.Fatal("fresh begin did not establish exact successor ownership")
	}
	must(t, f.a.validate())
}
