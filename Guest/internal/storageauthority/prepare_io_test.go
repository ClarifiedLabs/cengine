//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

var prepareIOPoints = []string{
	"copy-operation-write", "copy-operation-sync", "seal-persist", "cleaning-persist", "finish-persist",
	"retire-intent-persist", "retire-barrier-persist", "retire-receipt-persist", "retire-barrier-clear-persist",
}

func prepareIOBound(t *testing.T, f *fixture, v Volume, g *Guard) CopyIntent {
	t.Helper()
	o := copyObligation(t, g, CopyOperationBegin, "")
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	must(t, o.Complete(nil))
	o = copyObligation(t, g, CopyOperationProvision, i.ID)
	i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	must(t, o.Complete(nil))
	return i
}

func TestPrepareIOActualBoundariesStickyAndReopen(t *testing.T) {
	for _, point := range prepareIOPoints {
		for _, errnoName := range []string{"eio", "enospc"} {
			t.Run(errnoName+"/"+point, func(t *testing.T) {
				stage := "io-" + errnoName + "-" + point
				f, v, b, p, w := fullCompatibilityFixture(t, stage)
				want := error(unix.EIO)
				if errnoName == "enospc" {
					want = unix.ENOSPC
				}
				g, err := f.a.Admit(p, v.ID, true)
				must(t, err)
				defer g.Release()
				var i CopyIntent
				var obligation *CopyOperationObligation
				if point == "seal-persist" || point == "cleaning-persist" || point == "finish-persist" {
					i = prepareIOBound(t, f, v, g)
					if point == "finish-persist" {
						o := copyObligation(t, g, CopyOperationCleanup, i.ID)
						i, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
						must(t, err)
						must(t, o.Complete(nil))
						// Real transaction deletion/root synchronization precedes Finish.
						must(t, os.Remove(filepath.Join(f.path, "volumes", v.Name, copyTransactionName)))
						must(t, f.a.roots[v.ID].Sync())
					}
					action := map[string]string{"seal-persist": CopyOperationSeal, "cleaning-persist": CopyOperationCleanup, "finish-persist": CopyOperationFinish}[point]
					obligation, err = g.BeginCopyOperation(17, action, i.ID)
					must(t, err)
				}
				if w.Snapshot().IO.Fired {
					t.Fatal("unrelated earlier journal boundary consumed fault")
				}
				var attempted, completed []string
				// Existing hooks survive installation/scope and retain their ordering.
				f.a.j.fault = func(name string) error { attempted = append(attempted, name); return nil }
				f.a.j.afterStep = func(name string) { completed = append(completed, name) }
				barriers := 0
				f.a.barrier = func(actual Binding, root *os.File) error {
					if actual != b {
						t.Error("foreign barrier")
					}
					barriers++
					return root.Sync()
				}
				var receipt Receipt
				var operation ID
				switch point {
				case "copy-operation-write", "copy-operation-sync":
					_, err = g.BeginCopyOperation(17, CopyOperationBegin, "")
				case "seal-persist":
					manifest := []byte("actual synchronized manifest")
					fd, e := os.OpenFile(filepath.Join(f.path, "volumes", v.Name, copyTransactionName, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					must(t, e)
					_, e = fd.Write(manifest)
					must(t, e)
					must(t, fd.Sync())
					must(t, fd.Close())
					err = g.SealCopyManifest(i.ID, i.Transaction, manifest)
				case "cleaning-persist":
					_, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
				case "finish-persist":
					err = g.FinishCopy(i.ID)
				default:
					g.Release()
					operation = mustID(t)
					receipt, err = f.a.Retire(context.Background(), f.control, RetireRequest{operation, b.Store, b.Volume, b.Attachment, b.Launch})
				}
				wantErr(t, err, want)
				wantErr(t, err, ErrBlocked)
				if obligation != nil {
					wantErr(t, obligation.Complete(err), want)
				}
				s := w.Snapshot()
				if s.IO == nil || !s.IO.Fired || s.IO.Point != point || s.IO.Errno != strings.ToUpper(errnoName) || s.IO.Occurrence != 1 || s.State != "observed" || s.Receipt != nil || receipt != (Receipt{}) {
					t.Fatal("not exact failure evidence", s)
				}
				if strings.HasPrefix(point, "retire-") {
					if s.IO.Operation != operation || s.IO.Sequence != 0 {
						t.Fatal("wrong retirement owner", s.IO)
					}
				} else if s.IO.Sequence != 17 || s.IO.Operation != "" {
					t.Fatal("wrong request owner", s.IO)
				}
				c, _ := prepareIOCaseFor(stage)
				found := false
				for _, name := range attempted {
					if name == c.boundary {
						found = true
					}
				}
				if !found {
					t.Fatal("existing fault hook overwritten")
				}
				// Receipt injection follows one successful intent state-sync.
				// Metadata intents use a separate certificate. Barrier injection
				// is followed by the two real poison-marker syncs (permanent
				// known-IO quarantine and legacy uncertainty).
				completedBoundary, wantCompleted := 0, 0
				for _, name := range completed {
					if name == c.boundary {
						completedBoundary++
					}
				}
				if point == "retire-receipt-persist" {
					wantCompleted = 1
				}
				if point == "retire-barrier-persist" {
					wantCompleted = 2
				}
				if completedBoundary != wantCompleted {
					t.Fatal("wrong actual boundary completions", completedBoundary, wantCompleted)
				}
				if f.a.j.prepareIOFault != nil || f.a.j.fault == nil || f.a.j.afterStep == nil {
					t.Fatal("scope leaked or replaced hook")
				}
				wantBarriers := 0
				if point == "retire-receipt-persist" || point == "retire-barrier-clear-persist" {
					wantBarriers = 1
				}
				if barriers != wantBarriers {
					t.Fatal("wrong actual barrier count", barriers)
				}
				if point == "retire-barrier-clear-persist" && f.a.s.Attachments[b.Attachment].Phase != Drained {
					t.Fatal("receipt commit did not precede clear")
				}
				_, err = f.a.Query(f.control)
				wantErr(t, err, ErrBlocked)
				_, err = f.a.Admit(p, v.ID, true)
				wantErr(t, err, want)
				copy := w.Snapshot()
				copy.IO.Fired = false
				if !w.Snapshot().IO.Fired || w.Snapshot().IO.Occurrence != 1 {
					t.Fatal("mutable snapshot or repeated injection")
				}
				f.a.j.fault, f.a.j.afterStep = nil, nil
				g.Release()
				must(t, f.a.Close())
				reopened, err := f.openCurrent()
				if reopened != nil {
					reopened.Close()
					t.Fatal("returned-error fault reopened")
				}
				wantErr(t, err, ErrRepairRequired)
			})
		}
	}
}

func TestPrepareIOCopyMarkerRequiresBeginAction(t *testing.T) {
	for _, point := range []string{"copy-operation-write", "copy-operation-sync"} {
		f, v, _, p, w := fullCompatibilityFixture(t, "io-eio-"+point)
		g, err := f.a.Admit(p, v.ID, true)
		must(t, err)
		defer g.Release()
		// Legacy setup creates a real BEGUN intent without a BEGIN marker.
		i, err := g.BeginCopy(copyRoot(f, v))
		must(t, err)
		o := copyObligation(t, g, CopyOperationProvision, i.ID)
		i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
		must(t, err)
		must(t, o.Complete(nil))
		o = copyObligation(t, g, CopyOperationSeal, i.ID)
		must(t, g.SealCopyManifest(i.ID, i.Transaction, []byte("other action")))
		must(t, o.Complete(nil))
		if w.Snapshot().IO.Fired {
			t.Fatal("non-BEGIN marker consumed FIRST")
		}
		_, err = g.BeginCopyOperation(77, CopyOperationBegin, "")
		wantErr(t, err, unix.EIO)
		if !w.Snapshot().IO.Fired || w.Snapshot().IO.Sequence != 77 {
			t.Fatal("first BEGIN not observed")
		}
	}
}

func TestPrepareIOExistingFailureDoesNotClaimInjection(t *testing.T) {
	f, v, _, p, w := fullCompatibilityFixture(t, "io-eio-copy-operation-sync")
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	defer g.Release()
	f.a.j.fault = func(name string) error {
		if name == "copy-op-sync" {
			return unix.ENOSPC
		}
		return nil
	}
	_, err = g.BeginCopyOperation(1, CopyOperationBegin, "")
	wantErr(t, err, unix.ENOSPC)
	if errors.Is(err, unix.EIO) || w.Snapshot().IO.Fired || f.a.j.prepareIOFault != nil || f.a.j.fault == nil {
		t.Fatal("existing hook replaced or failure misattributed", err)
	}
}

func TestPrepareIOObligationBelongsToExactGuard(t *testing.T) {
	f, v, _, p, w := fullCompatibilityFixture(t, "io-eio-seal-persist")
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	defer g.Release()
	other, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	defer other.Release()
	i := prepareIOBound(t, f, v, g)
	o := copyObligation(t, g, CopyOperationSeal, i.ID)
	must(t, other.SealCopyManifest(i.ID, i.Transaction, []byte("other accepted guard")))
	must(t, o.Complete(nil))
	if w.Snapshot().IO.Fired {
		t.Fatal("same binding but different guard consumed fault")
	}
}

func TestPrepareIOClosedCatalogAndScope(t *testing.T) {
	for _, stage := range []string{"io-eio-nextfsync", "io-eio-state-sync", "io-eio-seal-persist-2", "io-enospc-../state.json", "io-EIO-seal-persist", "io-eperm-seal-persist"} {
		f := newFixture(t, nil)
		_, err := f.a.InstallPrepareCompatibility(PrepareCompatibilityPlan{Stage: stage})
		wantErr(t, err, ErrInvalid)
	}
	for _, mismatch := range []string{"store", "epoch", "controller", "prepare", "volume", "attachment", "container", "launch", "key", "foreign-owner"} {
		t.Run(mismatch, func(t *testing.T) {
			f, v, _, p, w := fullCompatibilityFixture(t, "io-eio-copy-operation-sync")
			// Corrupt only private installed provenance to prove every component
			// is rechecked at use, even after privileged installation succeeded.
			switch mismatch {
			case "store":
				w.plan.Target.Store = mustID(t)
			case "epoch":
				w.plan.Epoch = mustID(t)
			case "controller":
				w.plan.Controller.Epoch++
			case "prepare":
				w.plan.Target.Prepare = mustID(t)
			case "volume":
				w.plan.Target.Volume = mustID(t)
			case "attachment":
				w.plan.Target.Attachment = mustID(t)
			case "container":
				w.plan.Target.Container = mustContainerID(t)
			case "launch":
				w.plan.Target.Launch = mustID(t)
			case "key":
				w.plan.Target.Key = fp(t, newKey(t))
			case "foreign-owner":
				w.owner = &Authority{}
			}
			g, err := f.a.Admit(p, v.ID, true)
			must(t, err)
			defer g.Release()
			o, err := g.BeginCopyOperation(9, CopyOperationBegin, "")
			must(t, err)
			must(t, o.Complete(nil))
			if w.Snapshot().IO.Fired {
				t.Fatal("foreign provenance consumed fault")
			}
		})
	}
}

func TestPrepareIOUnrelatedGuardCommitAndSnapshotRace(t *testing.T) {
	f, v, _, p, w := fullCompatibilityFixture(t, "io-eio-seal-persist")
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	defer g.Release()
	i := prepareIOBound(t, f, v, g)
	// A valid legacy direct call is not an owned copy-operation seal.
	must(t, g.SealCopyManifest(i.ID, i.Transaction, []byte("legacy")))
	if w.Snapshot().IO.Fired {
		t.Fatal("unowned commit consumed fault")
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				s := w.Snapshot()
				s.IO.Fired = true
			}
		}()
	}
	wg.Wait()
	if w.Snapshot().IO.Fired {
		t.Fatal("snapshot aliases witness")
	}
	// No actual transition means an idempotent seal cannot consume FIRST.
	o := copyObligation(t, g, CopyOperationSeal, i.ID)
	must(t, g.SealCopyManifest(i.ID, i.Transaction, []byte("legacy")))
	must(t, o.Complete(nil))
	if w.Snapshot().IO.Fired || !errors.Is(w.Release(w.plan.Stage, w.Snapshot().ReleaseToken), ErrConflict) {
		t.Fatal("IO case became release facility")
	}
}
