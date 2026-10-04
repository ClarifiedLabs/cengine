//go:build linux && (amd64 || arm64) && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storagemanaged

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Real FINISH implementation, ext4 identity, unlink/fsync and durable obligation.
// This test needs a pre-existing authorized ext4 TMPDIR; it never mounts anything.
func TestVMCleanupPhysicalHook(t *testing.T) {
	kind := os.Getenv("CENGINE_VM_CLEANUP_COMPONENT")
	if kind == "" {
		if os.Geteuid() != 0 {
			t.Skip("requires Linux ext4 handle capabilities")
		}
		for _, kind := range []string{"present", "manifest-absent", "transaction-absent", "ordinary-manifest-absent", "ordinary-transaction-absent", "replay-sync-error"} {
			t.Run(kind, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestVMCleanupPhysicalHook$", "-test.count=1")
				cmd.Env = append(os.Environ(), "CENGINE_VM_CLEANUP_COMPONENT="+kind)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("worker: %v\n%s", err, out)
				}
			})
		}
		return
	}
	defer os.Exit(1) // no test-only release and no Close behind the held authority lock
	path := t.TempDir()
	var fs unix.Statfs_t
	copyHostMust(t, unix.Statfs(path, &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("TMPDIR must be existing real ext4")
	}
	stage := "vm-cleaning-transaction-removed"
	if kind == "ordinary-manifest-absent" || kind == "ordinary-transaction-absent" {
		stage = ""
	}
	h := newCopyObligationHostWithPlan(t, path, stage)
	i, err := h.guard.BeginCopy(h.root)
	copyHostMust(t, err)
	op, err := h.guard.BeginCopyOperation(10, a.CopyOperationProvision, i.ID)
	copyHostMust(t, err)
	i, err = h.guard.ProvisionCopyTransaction(i.ID, ext4Identity)
	copyHostMust(t, err)
	copyHostMust(t, op.Complete(nil))
	root := filepath.Join(path, "volumes", "data")
	tx := filepath.Join(root, copyTransactionPath)
	copyHostMust(t, os.Mkdir(filepath.Join(tx, "staging"), 0700))
	entries := []map[string]any{}
	for _, name := range []string{"a", "z"} {
		copyHostMust(t, os.WriteFile(filepath.Join(root, name), []byte("data-"+name), 0600))
		identity, err := copyIdentityAt(int(h.session.root.Fd()), name)
		copyHostMust(t, err)
		entries = append(entries, map[string]any{"path": name, "identity": identity})
	}
	raw, err := json.Marshal(map[string]any{"version": 4, "intent": i.ID, "physical": i.Root, "entries": entries})
	copyHostMust(t, err)
	copyHostMust(t, os.WriteFile(filepath.Join(tx, "manifest.json"), raw, 0600))
	op, err = h.guard.BeginCopyOperation(11, a.CopyOperationSeal, i.ID)
	copyHostMust(t, err)
	i, err = h.session.authenticateCopyManifest(h.guard, i, true)
	copyHostMust(t, err)
	copyHostMust(t, op.Complete(nil))
	copyHostMust(t, unix.UtimesNanoAt(int(h.session.root.Fd()), "", []unix.Timespec{{Sec: 123, Nsec: 456}, {Sec: 789, Nsec: 123}}, unix.AT_EMPTY_PATH))
	op, err = h.guard.BeginCopyOperation(12, a.CopyOperationCleanup, i.ID)
	copyHostMust(t, err)
	i, err = h.session.startCopyCleanup(h.guard, i)
	copyHostMust(t, err)
	copyHostMust(t, op.Complete(nil))
	// Construct the legal replay suffix left after manifest-last deletion. Saved
	// CLEANING identities stay intact even when their objects are already absent.
	if kind != "present" {
		copyHostMust(t, os.Remove(filepath.Join(tx, "staging")))
		copyHostMust(t, os.Remove(filepath.Join(tx, "manifest.json")))
		if kind == "transaction-absent" || kind == "ordinary-transaction-absent" || kind == "replay-sync-error" {
			copyHostMust(t, os.Remove(tx))
		}
	}
	syncs := 0
	h.session.registry.syncOps.fsync = func(fd int) error {
		syncs++
		if kind == "ordinary-transaction-absent" || kind == "replay-sync-error" {
			return unix.EIO
		}
		return unix.Fsync(fd)
	}
	h.session.registry.prepareOperation = func(g *a.Guard, request w.PrepareRequest) (w.ReplyBody, error) {
		return nil, h.session.finishCopyCleanup(g, i)
	}
	returned := make(chan error, 1)
	go func() { _, err := h.dispatch(w.FinishCopy, i.ID); returned <- err }()
	if kind == "replay-sync-error" {
		select {
		case err := <-returned:
			if !errors.Is(err, unix.EIO) || syncs != 1 || h.prepareWitness.Snapshot().State != "armed" {
				t.Fatal("replay sync failure observed or ignored", err, syncs)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("failed replay sync held")
		}
		os.Exit(0)
	}
	if stage == "" {
		select {
		case err := <-returned:
			copyHostMust(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("ordinary replay held")
		}
		if kind == "ordinary-transaction-absent" && syncs != 0 {
			t.Fatal("ordinary replay acquired witness-only fsync", syncs)
		}
		got, err := copyRootCleanup(int(h.session.root.Fd()))
		copyHostMust(t, err)
		expected := i.Cleanup
		expected.Manifest, expected.Staging = a.Ext4ObjectV1{}, a.Ext4ObjectV1{}
		if got != expected {
			t.Fatal("manifest-absent replay lost saved metadata", got, expected)
		}
		if _, err := os.Stat(filepath.Join(path, ".cengine-storage-authority", "copy-operation")); !os.IsNotExist(err) {
			t.Fatal("successful replay retained pending operation", err)
		}
	} else {
		deadline := time.After(5 * time.Second)
		for h.prepareWitness.Snapshot().State != "observed" {
			select {
			case err := <-returned:
				t.Fatal("FINISH returned before hold", err)
			case <-deadline:
				t.Fatal("cleanup checkpoint missing")
			case <-time.After(time.Millisecond):
			}
		}
		snap := h.prepareWitness.Snapshot()
		if snap.AcceptedInFlight != 1 || snap.RetirementStarted || !snap.Admitted || snap.Bound == nil || *snap.Bound != i || snap.Sequence != 1 || syncs == 0 {
			t.Fatal("not actual synchronized CLEANING intent", snap, syncs)
		}
		got, err := copyRootCleanup(int(h.session.root.Fd()))
		copyHostMust(t, err)
		if got.MTimeSeconds == i.Cleanup.MTimeSeconds && got.MTimeNanos == i.Cleanup.MTimeNanos {
			t.Fatal("restored root before checkpoint")
		}
		raw, err := os.ReadFile(filepath.Join(path, ".cengine-storage-authority", "copy-operation"))
		copyHostMust(t, err)
		var pending struct {
			Sequence uint64
			Action   string
			Intent   a.ID
			Binding  a.Binding
			Before   a.CopyIntent
		}
		copyHostMust(t, json.Unmarshal(raw, &pending))
		if pending.Sequence != 1 || pending.Action != a.CopyOperationFinish || pending.Intent != i.ID || pending.Binding != i.Owner || pending.Before != i {
			t.Fatal("wrong pending FINISH", pending)
		}
		if h.prepareWitness.Release(stage, snap.ReleaseToken) == nil {
			t.Fatal("VM Release allowed")
		}
		select {
		case err := <-returned:
			t.Fatal("hold returned", err)
		default:
		}
	}
	if _, err := os.Lstat(tx); !os.IsNotExist(err) {
		t.Fatal("transaction not actually removed", err)
	}
	for _, name := range []string{"a", "z"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(data) != "data-"+name {
			t.Fatal("complete tree changed", err)
		}
	}
	os.Exit(0)
}
