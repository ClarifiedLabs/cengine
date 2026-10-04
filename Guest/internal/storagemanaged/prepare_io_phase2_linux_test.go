//go:build linux && (amd64 || arm64) && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storagemanaged

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Real ext4 identities, recursive deletion, metadata restoration and syncs.
// Only the root-handle bootstrap is bypassed; Dispatch still owns the actual
// FINISH BeginCopyOperation and completion. Cross-compilation is not execution.
func TestPrepareIOPhase2ActualLinuxCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root with ext4 handle capabilities")
	}
	for index, point := range prepareCleanupIOPoints {
		for _, errnoName := range []string{"eio", "enospc"} {
			t.Run(errnoName+"/"+point, func(t *testing.T) {
				path := t.TempDir()
				var fs unix.Statfs_t
				copyHostMust(t, unix.Statfs(path, &fs))
				if fs.Type != unix.EXT4_SUPER_MAGIC {
					t.Fatal("TMPDIR must be real ext4")
				}
				h := newCopyObligationHostWithPlan(t, path, "io-"+errnoName+"-"+point)
				i, err := h.guard.BeginCopy(h.root)
				copyHostMust(t, err)
				o, err := h.guard.BeginCopyOperation(10, a.CopyOperationProvision, i.ID)
				copyHostMust(t, err)
				i, err = h.guard.ProvisionCopyTransaction(i.ID, ext4Identity)
				copyHostMust(t, err)
				copyHostMust(t, o.Complete(nil))
				transaction := filepath.Join(path, "volumes", "data", copyTransactionPath)
				copyHostMust(t, os.Mkdir(filepath.Join(transaction, "staging"), 0700))
				copyHostMust(t, os.WriteFile(filepath.Join(transaction, "staging", "child"), []byte("owned child"), 0600))
				copyHostMust(t, os.WriteFile(filepath.Join(transaction, "manifest.json"), []byte("unsealed manifest"), 0600))
				o, err = h.guard.BeginCopyOperation(11, a.CopyOperationCleanup, i.ID)
				copyHostMust(t, err)
				i, err = h.session.startCopyCleanup(h.guard, i)
				copyHostMust(t, err)
				copyHostMust(t, o.Complete(nil))
				if h.prepareWitness.Snapshot().IO.Fired {
					t.Fatal("preflight consumed FINISH fault")
				}
				syncs, syncfs := 0, 0
				h.session.registry.syncOps.fsync = func(fd int) error { syncs++; return unix.Fsync(fd) }
				h.session.registry.syncOps.syncfs = func(fd int) error { syncfs++; return unix.Syncfs(fd) }
				h.session.registry.prepareOperation = func(g *a.Guard, request w.PrepareRequest) (w.ReplyBody, error) {
					if request.Action != w.FinishCopy || request.Intent != i.ID {
						t.Fatal("wrong actual operation")
					}
					return nil, h.session.finishCopyCleanup(g, i)
				}
				result, err := h.dispatch(w.FinishCopy, i.ID)
				want := unix.EIO
				if errnoName == "enospc" {
					want = unix.ENOSPC
				}
				if !errors.Is(err, ErrVolumeFault) || !errors.Is(err, want) || result.Reply.Body != nil {
					t.Fatal("cleanup did not fail closed", result, err)
				}
				expectedSyncs := []int{0, 2, 3, 4}[index]
				if syncs != expectedSyncs || syncfs != 0 {
					t.Fatal("wrong actual sync boundary", point, syncs, syncfs)
				}
				// Each fault follows its unlink (or restoration), not merely its request.
				removed := filepath.Join(transaction, "staging", "child")
				if index == 1 {
					removed = filepath.Join(transaction, "manifest.json")
				}
				if index >= 2 {
					removed = transaction
				}
				if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("injection preceded actual unlink", removed, err)
				}
				if index == 0 {
					if _, err := os.Stat(filepath.Join(transaction, "manifest.json")); err != nil {
						t.Fatal("child failure deleted manifest", err)
					}
				}
				if index < 2 {
					if _, err := os.Stat(transaction); err != nil {
						t.Fatal("early failure removed transaction", err)
					}
				}
				if index == 3 {
					got, err := copyRootCleanup(int(h.session.root.Fd()))
					copyHostMust(t, err)
					expected := i.Cleanup
					expected.Manifest, expected.Staging = a.Ext4ObjectV1{}, a.Ext4ObjectV1{}
					if got != expected {
						t.Fatal("syncfs fault preceded exact root restoration", got, expected)
					}
				}
				snapshot := h.prepareWitness.Snapshot()
				if !snapshot.IO.Fired || snapshot.IO.Occurrence != 1 || snapshot.IO.Sequence != 1 || snapshot.Receipt != nil || snapshot.State != "observed" {
					t.Fatal("wrong failure evidence", snapshot)
				}
				if _, err := os.Stat(filepath.Join(path, ".cengine-storage-authority", "copy-operation")); err != nil {
					t.Fatal("FINISH obligation cleared", err)
				}
				_, err = h.guard.InspectCopy(i.ID, h.root)
				if !errors.Is(err, a.ErrBlocked) {
					t.Fatal("failure allowed completion", err)
				}
				h.guard.Release()
				copyHostMust(t, h.authority.Close())
				reopened, err := h.lifecycle.Open(h.config)
				if reopened != nil {
					reopened.Close()
					t.Fatal("cleanup uncertainty reopened")
				}
				if !errors.Is(err, a.ErrRepairRequired) {
					t.Fatal("not sticky", err)
				}
			})
		}
	}
}
