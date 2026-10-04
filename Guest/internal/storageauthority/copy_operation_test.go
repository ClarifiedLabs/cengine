package storageauthority

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func copyObligation(t *testing.T, g *Guard, action string, id ID) *CopyOperationObligation {
	t.Helper()
	o, err := g.BeginCopyOperation(1, action, id)
	must(t, err)
	return o
}
func TestCopyOperationCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_COPY_OPERATION_ROOT")
	if path == "" {
		return
	}
	boundary := os.Getenv("CENGINE_COPY_OPERATION_BOUNDARY")
	f := newFixtureAt(t, nil, path)
	v := f.volume("crash")
	_, g := copyPrepare(t, f, v, ReadWrite)
	m := crashManifest{Current: f.signedCurrent(), Bootstrap: f.c.BootstrapKey, ControllerKey: f.controllerKey, CAKey: f.caKey, CACertificate: f.ca.Raw, Before: *f.a.clone()}
	data, err := json.Marshal(m)
	must(t, err)
	writeCrashWitness(t, path, crashManifestName, data)
	f.a.j.afterStep = func(step string) {
		if step == boundary {
			os.Exit(crashExit)
		}
	}
	o := copyObligation(t, g, CopyOperationBegin, "")
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	if boundary == "begin-durable" {
		os.Exit(crashExit)
	}
	must(t, o.Complete(nil))
	o = copyObligation(t, g, CopyOperationProvision, i.ID)
	i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	must(t, o.Complete(nil))
	o = copyObligation(t, g, CopyOperationCleanup, i.ID)
	i, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
	must(t, err)
	if boundary == "cleaning-durable" {
		os.Exit(crashExit)
	}
	must(t, o.Complete(nil))
	o = copyObligation(t, g, CopyOperationFinish, i.ID)
	cleanupHostCopy(t, f, g, i)
	must(t, o.Complete(nil))
	t.Fatal("boundary not reached", boundary)
}

func TestCopyOperationProcessCrashReplay(t *testing.T) {
	for _, boundary := range []string{"copy-op-parent-sync", "begin-durable", "copy-initial-durable", "copy-private-mkdir", "copy-bound-durable", "copy-private-publish", "copy-public-parent-sync", "copy-source-parent-sync", "cleaning-durable", "test-cleanup-transaction", "test-cleanup-root-sync", "test-cleanup-finished", "state-sync"} {
		t.Run(boundary, func(t *testing.T) {
			path := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyOperationCrashWorker$", "-test.count=1")
			cmd.Env = append(os.Environ(), "CENGINE_COPY_OPERATION_ROOT="+path, "CENGINE_COPY_OPERATION_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
				t.Fatalf("worker: %v\n%s", err, out)
			}
			data, err := os.ReadFile(filepath.Join(path, crashManifestName))
			must(t, err)
			var m crashManifest
			must(t, json.Unmarshal(data, &m))
			root, err := os.Open(path)
			must(t, err)
			defer root.Close()
			c := Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { return nil }}
			open := func() (*Authority, error) {
				return OpenLifecycleExpected(c, m.Current, ExpectedLifecycleStartup{ExpectedStartup{m.Before.Store.ID, m.Before.Epoch, m.Before.Controller}, m.Before.Lifecycle.OpenRevision})
			}
			// A pre-bind private directory has no durable transaction identity.
			if boundary == "copy-private-mkdir" {
				lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
				return
			}
			a, err := open()
			// At state-sync the metadata certificate proves the unchanged
			// predecessor; BEGIN's independently validated operation record
			// reconstructs its replay obligation below, without inventing data IO.
			must(t, err)
			// Reconstruction itself must survive a second service restart.
			expected := ExpectedLifecycleStartup{ExpectedStartup{a.s.Store.ID, a.s.Epoch, a.s.Controller}, a.s.Lifecycle.OpenRevision}
			must(t, a.Close())
			a, err = OpenLifecycleExpected(c, m.Current, expected)
			must(t, err)
			defer a.Close()
			f := &fixture{t: t, a: a, c: c, path: path, controllerKey: m.ControllerKey, caKey: m.CAKey}
			f.ca, err = x509.ParseCertificate(m.CACertificate)
			must(t, err)
			f.pool = x509.NewCertPool()
			f.pool.AddCert(f.ca)
			f.server = f.cert(newKey(t))
			f.control = f.authControl(m.ControllerKey, m.Before.Controller.Epoch)
			var b Binding
			for _, at := range m.Before.Attachments {
				b = at.Binding
			}
			i, exists := a.s.Copy.Intents[b.Volume]
			if exists && i.Phase == CopyCompleted {
				if a.copyFences[b.Volume] != nil || a.copyReplayPending(b.Volume) {
					t.Fatal("completed replay revived fence")
				}
				return
			}
			if exists && a.copyFences[b.Volume] == nil {
				t.Fatal("missing replay fence")
			}
			g := copySuccessor(t, f, b)
			i = a.s.Copy.Intents[b.Volume]
			pending := a.s.CopyReplay[b.Volume]
			if pending.Action == CopyOperationBegin {
				o := copyObligation(t, g, CopyOperationBegin, "")
				i, err = g.BeginCopy(copyRoot(f, a.s.Volumes[b.Volume]))
				must(t, err)
				must(t, o.Complete(nil))
			} else {
				_, err = g.BeginDurability(99)
				wantErr(t, err, ErrBlocked)
			}
			if i.Phase != CopyCleaning {
				o := copyObligation(t, g, CopyOperationProvision, i.ID)
				i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
				must(t, err)
				must(t, o.Complete(nil))
			}
			o := copyObligation(t, g, CopyOperationCleanup, i.ID)
			cleanup := i.Initial
			if i.Phase == CopyCleaning {
				cleanup = i.Cleanup
			}
			i, err = g.StartCopyCleanup(i.ID, i.Transaction, cleanup)
			must(t, err)
			must(t, o.Complete(nil))
			o = copyObligation(t, g, CopyOperationFinish, i.ID)
			cleanupHostCopy(t, f, g, i)
			must(t, o.Complete(nil))
			if a.copyFences[b.Volume] != nil {
				t.Fatal("completed fence remains")
			}
			must(t, a.validate())
		})
	}
}

func TestCopyOperationReturnedFaultAndTamperingFailClosed(t *testing.T) {
	for _, fault := range []error{unix.EIO, unix.ENOSPC} {
		f := newFixture(t, nil)
		v := f.volume("fault")
		_, g := copyPrepare(t, f, v, ReadWrite)
		o := copyObligation(t, g, CopyOperationBegin, "")
		_, err := g.BeginCopy(copyRoot(f, v))
		must(t, err)
		wantErr(t, o.Complete(fault), ErrBlocked)
		g.Release()
		must(t, f.a.Close())
		_, err = f.openCurrent()
		wantErr(t, err, ErrRepairRequired)
	}
	for _, field := range []string{"action", "owner", "epoch", "root", "intent", "phase", "duplicate"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("tamper")
			_, g := copyPrepare(t, f, v, ReadWrite)
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			o := copyObligation(t, g, CopyOperationProvision, i.ID)
			r := o.token.record
			switch field {
			case "action":
				r.Action = "data"
			case "owner":
				r.Binding.Attachment = mustID(t)
			case "epoch":
				r.Epoch = mustID(t)
			case "root":
				r.Root.Inode++
			case "intent":
				r.Intent = mustID(t)
			case "phase":
				r.Before.Phase = CopyCompleted
			}
			data, err := json.Marshal(r)
			must(t, err)
			if field == "duplicate" {
				data = append([]byte(`{"Version":1,`), data[1:]...)
			}
			must(t, os.WriteFile(filepath.Join(f.path, registryName, copyOperationName), data, 0600))
			// Simulated descriptor teardown, intentionally without guard abandonment.
			f.a.copyIO = nil
			g.Release()
			must(t, f.a.Close())
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
		})
	}
}

// Abrupt descriptor teardown models only a process death between durable steps;
// no orderly Guard.Release may quarantine the outstanding operation first.
func restartCopyOperation(t *testing.T, f *fixture, g *Guard) {
	t.Helper()
	f.a.copyIO = nil
	g.Release()
	must(t, f.a.Close())
	var err error
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, f.a.s.Controller.Epoch)
}

func TestCopyOperationAuxiliaryBeginCrashAfterReplacement(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("auxiliary")
	b, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	copyObligation(t, g, CopyOperationProvision, i.ID)
	_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	restartCopyOperation(t, f, g)
	pending := f.a.s.CopyReplay[v.ID]
	g = copySuccessor(t, f, b)
	copyObligation(t, g, CopyOperationBegin, "")
	_, err = g.BeginCopy(copyRoot(f, v))
	must(t, err)
	// Crash with Prior pointing to the old owner's exact pending operation.
	b = g.token.binding
	restartCopyOperation(t, f, g)
	if !reflect.DeepEqual(f.a.s.CopyReplay[v.ID], pending) {
		t.Fatal("auxiliary Begin replaced pending replay")
	}
	g = copySuccessor(t, f, b)
	o := copyObligation(t, g, CopyOperationProvision, i.ID)
	_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	must(t, o.Complete(nil))
	must(t, g.CheckCopyReplay())
	must(t, f.a.validate())
}

func TestCopyOperationRejectedReplayPreservesPending(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("rejected")
	b, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	copyObligation(t, g, CopyOperationProvision, i.ID)
	restartCopyOperation(t, f, g)
	g = copySuccessor(t, f, b)
	pending := f.a.s.CopyReplay[v.ID]
	o := copyObligation(t, g, CopyOperationProvision, i.ID)
	must(t, o.CompleteRequest(nil, false))
	if !reflect.DeepEqual(f.a.s.CopyReplay[v.ID], pending) {
		t.Fatal("rejected replay erased pending record")
	}
	wantErr(t, g.CheckCopyReplay(), ErrBlocked)
	_, err = g.BeginCopyOperation(2, CopyOperationFinish, i.ID)
	wantErr(t, err, ErrBlocked)
	must(t, f.a.available())
	o = copyObligation(t, g, CopyOperationProvision, i.ID)
	_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	must(t, o.Complete(nil))
	must(t, g.CheckCopyReplay())
}

func TestCopyOperationFreshCopyAfterCompletedRecovery(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("fresh")
	b, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	copyObligation(t, g, CopyOperationFinish, i.ID)
	must(t, g.FinishCopy(i.ID))
	restartCopyOperation(t, f, g)
	g = copySuccessor(t, f, b)
	copyObligation(t, g, CopyOperationBegin, "")
	b = g.token.binding
	restartCopyOperation(t, f, g)
	// The pre-commit Begin record must remain valid on the next startup too.
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, f.a.s.Controller.Epoch)
	g = copySuccessor(t, f, b)
	o := copyObligation(t, g, CopyOperationBegin, "")
	fresh, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	must(t, o.Complete(nil))
	if fresh.ID == i.ID || f.a.copyReplayPending(v.ID) {
		t.Fatal("fresh copy inherited completed replay")
	}
	must(t, g.CheckCopyReplay())
	must(t, f.a.validate())
}

func TestCopyOperationCapacityReservesReplayBeforeExposure(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("capacity")
	_, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	limits := exactCapacity(t, f.a.s)
	f.a.limits.JournalBytes = limits.JournalBytes
	f.c.Limits = f.a.limits
	copyObligation(t, g, CopyOperationProvision, i.ID)
	_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	restartCopyOperation(t, f, g)
	must(t, f.a.validate())
	// The reconstructed ledger fits the original pre-exposure logical budget.
	if f.a.limits.JournalBytes != limits.JournalBytes {
		t.Fatal("recovery changed capacity")
	}
}

func TestCopyOperationRevisionAdmissionDoesNotWriteMarker(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("revision")
	_, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	original := f.a.s.Revision
	// Find the final revision at which ordinary terminal work still fits.
	for delta := uint64(0); ; delta++ {
		f.a.s.Revision = ^uint64(0) - delta
		encoded, err := json.Marshal(f.a.s)
		must(t, err)
		if f.a.capacity(f.a.s, int64(len(encoded))) == nil {
			break
		}
	}
	_, err = g.BeginCopyOperation(1, CopyOperationProvision, i.ID)
	wantErr(t, err, ErrLimit)
	if _, err = os.Stat(filepath.Join(f.path, registryName, copyOperationName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("limit rejection exposed marker", err)
	}
	must(t, f.a.available())
	f.a.s.Revision = original
}
