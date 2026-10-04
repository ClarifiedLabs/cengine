package storageauthority

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type prepareCrashManifest struct {
	Bootstrap ed25519.PublicKey
	Device    string
	Complete  CompleteRequest
	Replace   ReplaceRequest
	Current   SignedLifecycleGrant
	Expected  ExpectedLifecycleStartup
}

func TestPrepareCompletionCrashWorker(t *testing.T) {
	if os.Getenv("CENGINE_PREPARE_CRASH_WORKER") != "1" {
		return
	}
	root := os.Getenv("CENGINE_AUTHORITY_CRASH_ROOT")
	f := newFixtureAt(t, nil, root)
	v := f.volume("crash")
	r := plannedPrepare(t, f, v)
	must(t, f.a.ReservePrepare(f.control, r))
	c := drainedPrepare(t, f, r)
	replace := ReplaceRequest{mustID(t), r.Prepare, c.Receipts, plannedPrepare(t, f, v)}
	manifest := prepareCrashManifest{f.c.BootstrapKey, f.c.DeviceID, c, replace, f.signedCurrent(), expectedLifecycleStartup(f)}
	data, err := json.Marshal(manifest)
	must(t, err)
	writeCrashWitness(t, root, crashManifestName, data)
	defer func() { _ = os.WriteFile(filepath.Join(root, "cleanup-ran"), []byte("unexpected"), 0600) }()
	checkpoint := func(edge, stage string) {
		if edge == os.Getenv("CENGINE_AUTHORITY_CRASH_EDGE") && stage == os.Getenv("CENGINE_AUTHORITY_CRASH_BOUNDARY") {
			os.Exit(crashExit)
		}
	}
	f.a.j.fault = func(stage string) error { checkpoint("before", stage); return nil }
	f.a.j.afterStep = func(stage string) { checkpoint("after", stage) }
	if os.Getenv("CENGINE_AUTHORITY_CRASH_MODE") == "replace" {
		err = f.a.ReplacePrepare(f.control, replace)
	} else {
		err = f.a.CompletePrepare(f.control, c)
	}
	t.Fatalf("did not exit at crash checkpoint: %v", err)
}

func TestPrepareCompletionAbruptExit(t *testing.T) {
	for _, mode := range []string{"complete", "replace"} {
		for _, boundary := range persistBoundaries {
			for _, edge := range []string{"before", "after"} {
				t.Run(mode+"/"+boundary+"/"+edge, func(t *testing.T) {
					root := t.TempDir()
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPrepareCompletionCrashWorker$", "-test.count=1")
					cmd.Env = append(os.Environ(), "CENGINE_PREPARE_CRASH_WORKER=1", "CENGINE_AUTHORITY_CRASH_ROOT="+root, "CENGINE_AUTHORITY_CRASH_MODE="+mode, "CENGINE_AUTHORITY_CRASH_EDGE="+edge, "CENGINE_AUTHORITY_CRASH_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
					output, err := cmd.CombinedOutput()
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
						t.Fatalf("crash not reached: %v\n%s", err, output)
					}
					if _, err = os.Stat(filepath.Join(root, "cleanup-ran")); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("deferred cleanup ran")
					}
					data, err := os.ReadFile(filepath.Join(root, crashManifestName))
					must(t, err)
					var m prepareCrashManifest
					must(t, json.Unmarshal(data, &m))
					data, err = os.ReadFile(filepath.Join(root, registryName, stateName))
					must(t, err)
					var disk diskState
					must(t, json.Unmarshal(data, &disk))
					prep := disk.Prepares[m.Complete.Prepare]
					operation := m.Complete.Operation
					phase := Completed
					if mode == "replace" {
						operation, phase = m.Replace.Operation, Replaced
					}
					_, recorded := disk.Operations[operation]
					if recorded != (prep.Phase == phase) {
						t.Fatal("partial prepare resolution")
					}
					if mode == "replace" {
						_, successor := disk.Prepares[m.Replace.Successor.Prepare]
						_, reserved := disk.Operations[m.Replace.Successor.Operation]
						if successor != recorded || reserved != recorded {
							t.Fatal("partial successor reservation")
						}
					}
					for _, receipt := range m.Complete.Receipts {
						rec := disk.Attachments[receipt.Attachment]
						if rec.Receipt == nil || *rec.Receipt != receipt {
							t.Fatal("crash changed drain evidence")
						}
					}
					fd, err := os.Open(root)
					must(t, err)
					defer fd.Close()
					open := func() (*Authority, error) {
						return OpenLifecycleExpected(Config{Root: fd, DeviceID: m.Device, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { return nil }}, m.Current, m.Expected)
					}
					// RTM099: Open succeeds only where the commit proof (or the
					// absence of any mutation) makes the interrupted transaction
					// provable; every other boundary stays an offline-repair fence.
					clean := !lifecycleMetadataCrashRefuses(edge, boundary, false)
					if !clean {
						lifecycleCrashRefusesUnchanged(t, root, open, ErrRepairRequired)
						return
					}
					a, err := open()
					must(t, err)
					defer func() { must(t, a.Close()) }()
					p := &ControllerPrincipal{owner: a, key: a.s.Controller.Key, epoch: a.s.Controller.Epoch}
					revision := a.s.Revision
					if mode == "replace" {
						must(t, a.ReplacePrepare(p, m.Replace))
						changed := m.Replace
						changed.Successor.Operation = mustID(t)
						wantErr(t, a.ReplacePrepare(p, changed), ErrConflict)
					} else {
						must(t, a.CompletePrepare(p, m.Complete))
						changed := m.Complete
						changed.Attestation.Succeeded = false
						wantErr(t, a.CompletePrepare(p, changed), ErrConflict)
					}
					if recorded && a.s.Revision != revision {
						t.Fatal("durable replay rewrote completion")
					}
					must(t, a.validate())
				})
			}
		}
	}
}
