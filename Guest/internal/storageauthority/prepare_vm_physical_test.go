//go:build (linux || darwin) && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The worker exits itself: no signal, cancellation or test-only release of the
// production hold. Real journal, directory fsync and pending operation bytes;
// hostCopyObject substitutes only ext4 generation/handle acquisition on Darwin.
func TestVMPrivatePhysicalPending(t *testing.T) {
	if os.Getenv("CENGINE_VM_PRIVATE_COMPONENT") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestVMPrivatePhysicalPending$", "-test.count=1")
		cmd.Env = append(os.Environ(), "CENGINE_VM_PRIVATE_COMPONENT=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("worker: %v\n%s", err, out)
		}
		return
	}
	defer os.Exit(1) // fatal assertions must not enter Close behind the parked lock
	f, v, b, p, w := fullCompatibilityFixture(t, "vm-private-bound")
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	// A second accepted request must be counted, not a synthetic constant one.
	queued, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	defer queued.Release() // the worker exits itself while both admissions remain held
	begin, err := g.BeginCopyOperation(17, CopyOperationBegin, "")
	must(t, err)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	must(t, begin.CompleteRequest(nil, true))
	op, err := g.BeginCopyOperation(437, CopyOperationProvision, i.ID)
	must(t, err)
	steps := make(map[string]bool)
	f.a.j.afterStep = func(step string) { steps[step] = true }
	returned := make(chan error, 1)
	go func() { _, err := g.ProvisionCopyTransaction(i.ID, hostCopyObject); returned <- err }()
	deadline := time.After(5 * time.Second)
	for w.Snapshot().State != "observed" {
		select {
		case err := <-returned:
			t.Fatal("provision returned before hold", err)
		case <-deadline:
			t.Fatal("missing physical hold")
		case <-time.After(time.Millisecond):
		}
	}
	snapshot := w.Snapshot()
	if snapshot.AcceptedInFlight != 2 || snapshot.RetirementStarted || !snapshot.Admitted || snapshot.Bound == nil || snapshot.Sequence != 437 || snapshot.Bound.Phase != CopyBound || snapshot.Bound.Owner != b || !snapshot.Bound.InitialCaptured {
		t.Fatal("wrong checkpoint", snapshot)
	}
	if !steps["copy-bound-durable"] || !steps["copy-private-sync"] || !steps["copy-private-parent-sync"] || steps["copy-private-publish"] {
		t.Fatal("wrong physical position", steps)
	}
	disk, err := f.a.j.load()
	must(t, err)
	if disk.Copy.Intents[v.ID] != *snapshot.Bound {
		t.Fatal("checkpoint is not durable BOUND")
	}
	raw, err := os.ReadFile(filepath.Join(f.path, registryName, copyOperationName))
	must(t, err)
	var pending copyOperationRecord
	must(t, json.Unmarshal(raw, &pending))
	if pending != op.token.record || pending.Sequence != 437 || pending.Action != CopyOperationProvision || pending.Intent != i.ID || pending.Binding != b || op.token.completed {
		t.Fatal("not exact live pending obligation")
	}
	private, err := os.Open(filepath.Join(f.path, registryName, "copy-"+string(i.ID)))
	must(t, err)
	object, err := hostCopyObject(int(private.Fd()))
	must(t, err)
	must(t, private.Close())
	if object != snapshot.Bound.Transaction {
		t.Fatal("private identity differs")
	}
	if _, err := os.Lstat(filepath.Join(f.path, "volumes", v.Name, copyTransactionName)); !os.IsNotExist(err) {
		t.Fatal("published before hold", err)
	}
	if w.Release("vm-private-bound", snapshot.ReleaseToken) == nil {
		t.Fatal("VM release allowed")
	}
	select {
	case err := <-returned:
		t.Fatal("hold returned", err)
	default:
	}
	os.Exit(0)
}
