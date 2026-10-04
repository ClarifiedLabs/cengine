//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import (
	"errors"
	"testing"
)

func TestVMCheckpointRejectsInactiveAdmission(t *testing.T) {
	for _, stage := range []string{"vm-private-bound", "vm-cleaning-transaction-removed"} {
		t.Run(stage, func(t *testing.T) {
			f, v, b, p, w := fullCompatibilityFixture(t, stage)
			g, err := f.a.Admit(p, v.ID, true)
			must(t, err)
			defer g.Release()
			begin := copyObligation(t, g, CopyOperationBegin, "")
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			must(t, begin.Complete(nil))
			// Obtain a real durable intent without entering the intentional hold.
			f.a.prepareCompatibility.Store(nil)
			op := copyObligation(t, g, CopyOperationProvision, i.ID)
			i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
			must(t, err)
			must(t, op.Complete(nil))
			action := CopyOperationProvision
			if stage == "vm-cleaning-transaction-removed" {
				op = copyObligation(t, g, CopyOperationCleanup, i.ID)
				i, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
				must(t, err)
				must(t, op.Complete(nil))
				action = CopyOperationFinish
			}
			f.a.prepareCompatibility.Store(w)
			op = copyObligation(t, g, action, i.ID)
			for _, kind := range []string{"missing-runtime", "zero-count", "negative-count", "retiring", "retirement-id", "wrong-binding", "retired-snapshot"} {
				t.Run(kind, func(t *testing.T) {
					f.a.mu.Lock()
					rt, rec := f.a.runtime[b.Attachment], f.a.s.Attachments[b.Attachment]
					count := rt.count
					bad := rec
					switch kind {
					case "missing-runtime":
						delete(f.a.runtime, b.Attachment)
					case "zero-count":
						rt.count = 0
					case "negative-count":
						rt.count = -1
					case "retiring":
						bad.Phase = Retiring
					case "retirement-id":
						bad.Retirement = mustID(t)
					case "wrong-binding":
						bad.Binding.Key = "wrong"
					case "retired-snapshot":
						w.snapshot.RetirementStarted = true
					}
					f.a.s.Attachments[b.Attachment] = bad
					err := g.prepareVMCheckpointLocked(stage, i, action)
					f.a.runtime[b.Attachment], rt.count = rt, count
					f.a.s.Attachments[b.Attachment] = rec
					w.snapshot.RetirementStarted = false
					f.a.mu.Unlock()
					wantErr(t, err, ErrConflict)
					if snap := w.Snapshot(); snap.State != "armed" || snap.Bound != nil || snap.AcceptedInFlight != 0 {
						t.Fatal("inactive admission observed", snap)
					}
				})
			}
			// Replay fsync belongs exclusively to the selected cleanup witness.
			calls := 0
			failure := errors.New("replay parent sync failed")
			syncParent := func() error { calls++; return failure }
			err = g.PrepareCompatibilityTransactionRemoved(i.ID, syncParent)
			if stage == "vm-cleaning-transaction-removed" {
				if !errors.Is(err, failure) || calls != 1 || w.Snapshot().State != "armed" {
					t.Fatal("sync failure observed or ignored", err, calls)
				}
			} else if err != nil || calls != 0 {
				t.Fatal("unselected stage synced", err, calls)
			}
			f.a.prepareCompatibility.Store(nil)
			calls = 0
			must(t, g.PrepareCompatibilityTransactionRemoved(i.ID, syncParent))
			if calls != 0 {
				t.Fatal("unarmed replay synced")
			}
			must(t, op.CompleteRequest(nil, false))
		})
	}
}

func TestVMCheckpointRejectsMissingOrWrongLiveObligation(t *testing.T) {
	for _, stage := range []string{"vm-private-bound", "vm-cleaning-transaction-removed"} {
		f, v, _, p, w := fullCompatibilityFixture(t, stage)
		g, err := f.a.Admit(p, v.ID, true)
		must(t, err)
		defer g.Release()
		op := copyObligation(t, g, CopyOperationBegin, "")
		intent, err := g.BeginCopy(copyRoot(f, v))
		must(t, err)
		must(t, op.Complete(nil))
		f.a.mu.Lock()
		err = g.prepareVMCheckpointLocked(stage, intent, CopyOperationProvision)
		f.a.mu.Unlock()
		wantErr(t, err, ErrConflict)
		op, err = g.BeginCopyOperation(41, CopyOperationProvision, intent.ID)
		must(t, err)
		f.a.mu.Lock()
		err = g.prepareVMCheckpointLocked(stage, intent, CopyOperationFinish)
		f.a.mu.Unlock()
		wantErr(t, err, ErrConflict)
		must(t, op.Complete(nil))
		if w.Snapshot().State != "armed" || w.Snapshot().Bound != nil {
			t.Fatal("early observation")
		}
		if w.Release(stage, w.Snapshot().ReleaseToken) == nil {
			t.Fatal("VM release")
		}
	}
}
