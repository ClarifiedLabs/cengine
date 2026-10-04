//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storagemanaged

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

var prepareCleanupIOPoints = []string{"child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs"}

// Host dispatch regression: real codec, BeginCopyOperation, obligation poison,
// sticky registry and reopen. Only the Linux filesystem body is substituted.
func TestPrepareIOPhase2DispatchSticky(t *testing.T) {
	for _, point := range prepareCleanupIOPoints {
		for _, errnoName := range []string{"eio", "enospc"} {
			t.Run(errnoName+"/"+point, func(t *testing.T) {
				h := newCopyObligationHostWithPlan(t, t.TempDir(), "io-"+errnoName+"-"+point)
				i, err := h.guard.BeginCopy(h.root)
				copyHostMust(t, err)
				i, err = h.guard.ProvisionCopyTransaction(i.ID, copyHostObject)
				copyHostMust(t, err)
				i, err = h.guard.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
				copyHostMust(t, err)
				h.session.registry.prepareOperation = func(g *a.Guard, p w.PrepareRequest) (w.ReplyBody, error) {
					if p.Action != w.FinishCopy || p.Intent != i.ID {
						t.Fatal("wrong actual dispatch", p)
					}
					return nil, g.PrepareCompatibilityCleanupIO(i.ID, point)
				}
				result, err := h.dispatch(w.FinishCopy, i.ID)
				want := unix.EIO
				if errnoName == "enospc" {
					want = unix.ENOSPC
				}
				if !errors.Is(err, ErrVolumeFault) || !errors.Is(err, want) || result.Reply.Body != nil {
					t.Fatal("lost failure/no-success contract", result, err)
				}
				snapshot := h.prepareWitness.Snapshot()
				if snapshot.State != "observed" || !snapshot.IO.Fired || snapshot.IO.Occurrence != 1 || snapshot.IO.Sequence != 1 || snapshot.IO.Point != point || snapshot.IO.Errno != strings.ToUpper(errnoName) || snapshot.Receipt != nil {
					t.Fatal("wrong request evidence", snapshot)
				}
				if _, err := os.Stat(filepath.Join(h.path, ".cengine-storage-authority", "copy-operation")); err != nil {
					t.Fatal("obligation erased", err)
				}
				if !errors.Is(h.session.registry.faults[h.root.Volume], want) {
					t.Fatal("registry did not latch")
				}
				copyHostMust(t, h.session.root.Sync()) // a successful later sync cannot clear uncertainty
				_, err = h.guard.InspectCopy(i.ID, h.root)
				if !errors.Is(err, a.ErrBlocked) {
					t.Fatal("authority failed open", err)
				}
				h.guard.Release()
				copyHostMust(t, h.authority.Close())
				reopened, err := h.lifecycle.Open(h.config)
				if reopened != nil {
					reopened.Close()
					t.Fatal("fault reopened")
				}
				if !errors.Is(err, a.ErrRepairRequired) {
					t.Fatal("not sticky", err)
				}
			})
		}
	}
}
