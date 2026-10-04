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

var prepareIOPhase2Points = []string{"provision-rename", "provision-parent-sync", "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs"}

// Provision executes the real publication. Cleanup exercises the exact authority
// hook and returned-error obligation contract; real Linux cleanup has separate
// storagemanaged coverage, not a claim that Darwin executes syncfs/ext4.
func TestPrepareIOPhase2StickyAndReopen(t *testing.T) {
	for _, point := range prepareIOPhase2Points {
		for _, errnoName := range []string{"eio", "enospc"} {
			t.Run(errnoName+"/"+point, func(t *testing.T) {
				f, v, b, p, w := fullCompatibilityFixture(t, "io-"+errnoName+"-"+point)
				g, err := f.a.Admit(p, v.ID, true)
				must(t, err)
				defer g.Release()
				o := copyObligation(t, g, CopyOperationBegin, "")
				i, err := g.BeginCopy(copyRoot(f, v))
				must(t, err)
				must(t, o.Complete(nil))
				provision := strings.HasPrefix(point, "provision-")
				action := CopyOperationProvision
				if !provision {
					o = copyObligation(t, g, CopyOperationProvision, i.ID)
					i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
					must(t, err)
					must(t, o.Complete(nil))
					o = copyObligation(t, g, CopyOperationCleanup, i.ID)
					i, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
					must(t, err)
					must(t, o.Complete(nil))
					action = CopyOperationFinish
				}
				if w.Snapshot().IO.Fired {
					t.Fatal("earlier operation consumed point")
				}
				o, err = g.BeginCopyOperation(41, action, i.ID)
				must(t, err)
				attempted, completed := map[string]int{}, map[string]int{}
				f.a.j.fault = func(n string) error { attempted[n]++; return nil }
				f.a.j.afterStep = func(n string) { completed[n]++ }
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for n := 0; n < 100; n++ {
						snapshot := w.Snapshot()
						snapshot.IO.Fired = false
					}
				}()
				if provision {
					_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
				} else {
					err = g.PrepareCompatibilityCleanupIO(i.ID, point)
				}
				wg.Wait()
				want := unix.EIO
				if errnoName == "enospc" {
					want = unix.ENOSPC
				}
				wantErr(t, err, want)
				if provision {
					wantErr(t, err, ErrBlocked)
					c, _ := prepareIOCaseFor(w.plan.Stage)
					if attempted[c.boundary] != 1 || completed[c.boundary] != 0 {
						t.Fatal("wrong real boundary", attempted, completed)
					}
					_, publicErr := os.Stat(filepath.Join(f.path, "volumes", v.Name, copyTransactionName))
					_, privateErr := os.Stat(filepath.Join(f.path, ".cengine-storage-authority", "copy-"+string(i.ID)))
					if point == "provision-rename" {
						if !os.IsNotExist(publicErr) || privateErr != nil {
							t.Fatal("rename fault did not preserve private object", publicErr, privateErr)
						}
					} else if publicErr != nil || !os.IsNotExist(privateErr) || completed["copy-private-publish"] != 1 {
						t.Fatal("parent sync fault did not follow rename", publicErr, privateErr)
					}
				} else {
					// Fixed FIRST, even before the normal dispatcher poisons on completion.
					must(t, g.PrepareCompatibilityCleanupIO(i.ID, point))
				}
				wantErr(t, o.Complete(err), want)
				s := w.Snapshot()
				if s.IO == nil || !s.IO.Fired || s.IO.Point != point || s.IO.Errno != strings.ToUpper(errnoName) || s.IO.Occurrence != 1 || s.IO.Sequence != 41 || s.IO.Operation != "" || s.State != "observed" || !s.Admitted || s.Receipt != nil {
					t.Fatal("wrong owned failure evidence", s)
				}
				if f.a.j.prepareIOFault != nil || f.a.j.fault == nil || f.a.j.afterStep == nil {
					t.Fatal("hook leaked/overwritten")
				}
				if f.a.s.Copy.Intents[v.ID].Phase == CopyCompleted || f.a.s.Attachments[b.Attachment].Phase == Drained {
					t.Fatal("false completion/drain")
				}
				_, err = f.a.Query(f.control)
				wantErr(t, err, ErrBlocked)
				_, err = f.a.Admit(p, v.ID, true)
				wantErr(t, err, ErrBlocked)
				g.Release()
				receipt, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
				wantErr(t, err, ErrBlocked)
				if receipt != (Receipt{}) {
					t.Fatal("poisoned authority returned drain receipt")
				}
				f.a.j.fault, f.a.j.afterStep = nil, nil
				must(t, f.a.Close())
				reopened, err := f.openCurrent()
				if reopened != nil {
					reopened.Close()
					t.Fatal("sticky fault reopened")
				}
				wantErr(t, err, ErrRepairRequired)
			})
		}
	}
}

func TestPrepareIOPhase2CleanupOwnership(t *testing.T) {
	for _, point := range prepareIOPhase2Points[2:] {
		t.Run(point, func(t *testing.T) {
			f, v, _, p, w := fullCompatibilityFixture(t, "io-eio-"+point)
			g, err := f.a.Admit(p, v.ID, true)
			must(t, err)
			defer g.Release()
			other, err := f.a.Admit(p, v.ID, true)
			must(t, err)
			defer other.Release()
			i := prepareIOBound(t, f, v, g)
			o := copyObligation(t, g, CopyOperationCleanup, i.ID)
			i, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
			must(t, err)
			must(t, g.PrepareCompatibilityCleanupIO(i.ID, point)) // wrong action
			must(t, o.Complete(nil))
			must(t, g.PrepareCompatibilityCleanupIO(i.ID, point)) // no live obligation
			o = copyObligation(t, g, CopyOperationFinish, i.ID)
			must(t, other.PrepareCompatibilityCleanupIO(i.ID, point))
			must(t, g.PrepareCompatibilityCleanupIO(mustID(t), point))
			must(t, g.PrepareCompatibilityCleanupIO(i.ID, "state-sync"))
			original := w.plan
			w.plan.Controller.Epoch++
			must(t, g.PrepareCompatibilityCleanupIO(i.ID, point))
			w.plan = original
			w.plan.Epoch = mustID(t)
			must(t, g.PrepareCompatibilityCleanupIO(i.ID, point))
			w.plan = original
			w.plan.Target.Key = fp(t, newKey(t))
			must(t, g.PrepareCompatibilityCleanupIO(i.ID, point))
			w.plan = original
			if w.Snapshot().IO.Fired {
				t.Fatal("unowned cleanup consumed FIRST")
			}
			err = g.PrepareCompatibilityCleanupIO(i.ID, point)
			wantErr(t, err, unix.EIO)
			wantErr(t, o.Complete(err), ErrBlocked)
		})
	}
}

func TestPrepareIOPhase2ProvisionOwnershipAndEarlierError(t *testing.T) {
	for _, point := range prepareIOPhase2Points[:2] {
		for _, mode := range []string{"legacy", "other-guard", "earlier-error"} {
			t.Run(point+"/"+mode, func(t *testing.T) {
				f, v, _, p, w := fullCompatibilityFixture(t, "io-eio-"+point)
				g, err := f.a.Admit(p, v.ID, true)
				must(t, err)
				defer g.Release()
				other, err := f.a.Admit(p, v.ID, true)
				must(t, err)
				defer other.Release()
				i, err := g.BeginCopy(copyRoot(f, v))
				must(t, err)
				var o *CopyOperationObligation
				caller := g
				if mode != "legacy" {
					o = copyObligation(t, g, CopyOperationProvision, i.ID)
				}
				if mode == "other-guard" {
					caller = other
				}
				if mode == "earlier-error" {
					c, _ := prepareIOCaseFor(w.plan.Stage)
					f.a.j.fault = func(n string) error {
						if n == c.boundary {
							return unix.ENOSPC
						}
						return nil
					}
				}
				_, err = caller.ProvisionCopyTransaction(i.ID, hostCopyObject)
				if mode == "earlier-error" {
					wantErr(t, err, unix.ENOSPC)
					if errors.Is(err, unix.EIO) {
						t.Fatal("misattributed error")
					}
				} else {
					must(t, err)
				}
				if o != nil && mode != "earlier-error" {
					must(t, o.Complete(nil))
				}
				if w.Snapshot().IO.Fired || f.a.j.prepareIOFault != nil {
					t.Fatal("unowned/earlier failure claimed injection")
				}
			})
		}
	}
}

func TestPrepareIOPhase2ClosedCatalog(t *testing.T) {
	for _, point := range prepareIOPhase2Points {
		for _, suffix := range []string{"-2", "/../", "-next"} {
			if _, ok := prepareIOCaseFor("io-eio-" + point + suffix); ok {
				t.Fatal("open catalog", point, suffix)
			}
		}
	}
}
