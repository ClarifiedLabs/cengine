package storageauthority

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLifecycleHandoffPersistenceFailuresPoison(t *testing.T) {
	for _, applied := range []bool{false, true} {
		outcome := map[bool]string{false: "unapplied", true: "applied"}[applied]
		for _, errno := range []error{unix.EIO, unix.ENOSPC} {
			for _, boundary := range persistBoundaries {
				t.Run(outcome+"/"+errno.Error()+"/"+boundary, func(t *testing.T) {
					f, _ := newLifecycleFixture(t)
					v := f.volume("data")
					_, data := f.runtime(v, ReadWrite)
					signed, pending, principal := handoffRequest(t, f)
					if applied {
						_, err := f.a.TakeoverLifecycle(principal, pending)
						must(t, err)
					}
					before := f.a.clone()
					fired := false
					f.a.j.fault = func(step string) error {
						if step == boundary && !fired {
							fired = true
							return errno
						}
						return nil
					}
					result, err := f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
					wantErr(t, err, ErrBlocked)
					wantErr(t, err, errno)
					if !fired || !reflect.DeepEqual(result, LifecycleHandoffResult{}) || !reflect.DeepEqual(before, f.a.s) {
						t.Fatal("failed fence returned a receipt or published in-memory state")
					}
					f.a.j.fault = nil
					files := lifecycleFiles(t, f)
					_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
					wantErr(t, err, ErrBlocked)
					_, err = f.a.TakeoverLifecycle(principal, pending)
					wantErr(t, err, ErrBlocked)
					guard, err := f.a.Admit(data, v.ID, true)
					if guard != nil {
						guard.Release()
						t.Fatal("poisoned authority admitted DATA")
					}
					wantErr(t, err, ErrBlocked)
					if !reflect.DeepEqual(files, lifecycleFiles(t, f)) {
						t.Fatal("poison retry changed evidence")
					}
					must(t, f.a.Close())
					lifecycleCrashRefusesUnchanged(t, f.path, f.openCurrent, ErrRepairRequired)
				})
			}
		}
	}
}

type handoffCrashManifest struct {
	Current   SignedLifecycleGrant
	Handoff   SignedLifecycleHandoff
	Before    diskState
	Bootstrap []byte
	Stable    Receipt
}

// Real subprocess exits use the existing journal before/after hooks. These prove
// local process-crash behavior, not VM/device or physical power-loss durability.
func TestLifecycleHandoffCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_HANDOFF_CRASH_ROOT")
	if path == "" {
		return
	}
	f := newFixtureAt(t, nil, path)
	stable, _ := f.runtime(f.volume("stable"), ReadOnly)
	receipt := f.retire(stable)
	f.runtime(f.volume("active"), ReadWrite)
	signed, pending, principal := handoffRequest(t, f)
	if os.Getenv("CENGINE_HANDOFF_CRASH_APPLIED") == "true" {
		_, err := f.a.TakeoverLifecycle(principal, pending)
		must(t, err)
	}
	m := handoffCrashManifest{f.signedCurrent(), signed, *f.a.clone(), f.c.BootstrapKey, receipt}
	raw, err := json.Marshal(m)
	must(t, err)
	writeCrashWitness(t, path, crashManifestName, raw)
	defer func() { _ = os.WriteFile(filepath.Join(path, "cleanup-ran"), nil, 0600) }()
	boundary, edge := os.Getenv("CENGINE_HANDOFF_CRASH_BOUNDARY"), os.Getenv("CENGINE_HANDOFF_CRASH_EDGE")
	checkpoint := func(when, step string) {
		if when == edge && step == boundary {
			os.Exit(crashExit)
		}
	}
	f.a.j.fault = func(step string) error { checkpoint("before", step); return nil }
	f.a.j.afterStep = func(step string) { checkpoint("after", step) }
	_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
	t.Fatalf("handoff crash checkpoint not reached: %v", err)
}

func TestLifecycleHandoffCrashPublicationCuts(t *testing.T) {
	cuts := []struct{ edge, boundary string }{
		{"before", "proof-open"},
		{"after", "proof-open"}, // incomplete candidate must remain untouched
		{"after", "proof-parent-sync"},
		{"after", "state-open"}, // incomplete state candidate
		{"after", "proof-ready-parent-sync"},
		{"after", "state-rename"},
		{"after", "state-parent-sync"},
		{"after", "proof-clear-sync"}, // durable commit, reply never delivered
	}
	for _, applied := range []string{"false", "true"} {
		for _, cut := range cuts {
			t.Run(applied+"/"+cut.edge+"/"+cut.boundary, func(t *testing.T) {
				path := t.TempDir()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleHandoffCrashWorker$", "-test.count=1")
				cmd.Env = append(os.Environ(), "CENGINE_HANDOFF_CRASH_ROOT="+path,
					"CENGINE_HANDOFF_CRASH_APPLIED="+applied, "CENGINE_HANDOFF_CRASH_BOUNDARY="+cut.boundary,
					"CENGINE_HANDOFF_CRASH_EDGE="+cut.edge, "GORACE=atexit_sleep_ms=0")
				output, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
					t.Fatalf("worker: %v\n%s", err, output)
				}
				if _, err := os.Stat(filepath.Join(path, "cleanup-ran")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("crash ran cleanup: %v", err)
				}
				raw, err := os.ReadFile(filepath.Join(path, crashManifestName))
				must(t, err)
				var m handoffCrashManifest
				must(t, json.Unmarshal(raw, &m))
				raw, err = os.ReadFile(filepath.Join(path, registryName, stateName))
				must(t, err)
				var disk diskState
				must(t, json.Unmarshal(raw, &disk))
				want := m.Before
				landed := abruptRecoveryOutcome(cut.edge, cut.boundary) == "landed"
				if landed {
					want.Revision++
					want.Lifecycle.HandoffFence = &lifecycleHandoffFence{m.Handoff.Request, m.Before.Lifecycle.Latest, want.Revision}
				}
				if !reflect.DeepEqual(want, disk) {
					t.Fatal("crash changed more than the atomic fence/revision")
				}
				root, err := os.Open(path)
				must(t, err)
				defer root.Close()
				config := Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap,
					Barrier: func(Binding, *os.File) error { t.Fatal("reopen manufactured DATA barrier"); return nil }}
				open := func() (*Authority, error) {
					return OpenLifecycleExpected(config, m.Current, ExpectedLifecycleStartup{
						ExpectedStartup{m.Before.Store.ID, m.Before.Epoch, m.Before.Controller}, m.Before.Lifecycle.OpenRevision})
				}
				// An unpublished lifecycle change is not ordinary same-E workload
				// recovery: preserve the complete fence candidate for offline repair.
				if lifecycleMetadataCrashRefuses(cut.edge, cut.boundary, false) || cut.boundary == "proof-ready-parent-sync" {
					lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
					return
				}
				a, err := open()
				must(t, err)
				defer a.Close()
				must(t, a.validate())
				recovered := (&Authority{s: &disk}).clone()
				recovered.Epoch = a.Epoch()
				recovered.Revision++
				recovered.Lifecycle.OpenRevision = recovered.Revision
				for id, rec := range recovered.Attachments {
					if rec.Phase == Active {
						rec.Phase = Retiring
						recovered.Attachments[id] = rec
					}
				}
				if a.Epoch() == m.Before.Epoch || !reflect.DeepEqual(recovered, a.s) {
					t.Fatal("reopen changed more than E/revision/open revision and ACTIVE fencing")
				}
				if !reflect.DeepEqual(a.s.Lifecycle.HandoffFence, disk.Lifecycle.HandoffFence) || a.s.Lifecycle.Latest != m.Before.Lifecycle.Latest {
					t.Fatal("reopen rewrote immutable handoff outcome")
				}
				for id, prior := range m.Before.Attachments {
					current := a.s.Attachments[id]
					if current.Binding != prior.Binding || !reflect.DeepEqual(current.Receipt, prior.Receipt) || (current.Phase != Retiring && current.Phase != Drained) {
						t.Fatal("reopen changed DATA identity/receipt or failed to fence DATA")
					}
				}
				if a.s.Attachments[m.Stable.Attachment].Receipt == nil || *a.s.Attachments[m.Stable.Attachment].Receipt != m.Stable {
					t.Fatal("crash lost acknowledged DATA receipt")
				}
				before := lifecycleCrashCensus(t, filepath.Join(path, registryName))
				_, err = a.FenceLifecycleHandoff(m.Handoff, make([]byte, 32))
				wantErr(t, err, ErrConflict) // same-live-open authorization cannot cross reopen
				if !reflect.DeepEqual(before, lifecycleCrashCensus(t, filepath.Join(path, registryName))) {
					t.Fatal("stale handoff replay changed recovered disk")
				}
			})
		}
	}
}

func TestLifecycleHandoffReopenRejectsPendingWithFreshAuthentication(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "unapplied", true: "applied"}[applied], func(t *testing.T) {
			f, _ := newLifecycleFixture(t)
			v := f.volume("data")
			binding, data := f.runtime(v, ReadWrite)
			key := newKey(t)
			pending := signLifecycle(t, f.bootstrap, f.takeoverGrant(f.a.s.Controller.Epoch, fp(t, key)))
			principal, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
			must(t, err)
			signed := signHandoff(t, f.bootstrap, LifecycleHandoffRequest{mustID(t), f.a.s.Lifecycle.Latest.Grant, pending.Grant, f.a.Epoch(), f.a.s.Lifecycle.OpenRevision})
			if applied {
				_, err = f.a.TakeoverLifecycle(principal, pending)
				must(t, err)
			}
			_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
			must(t, err)
			fence := *f.a.s.Lifecycle.HandoffFence
			must(t, f.a.Close())
			f.a, err = f.openCurrent()
			must(t, err)
			principal, err = f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
			must(t, err)
			before := lifecycleFiles(t, f)
			_, err = f.a.TakeoverLifecycle(principal, pending)
			wantErr(t, err, ErrUnauthorized)
			_, err = f.a.FenceLifecycleHandoff(signed, make([]byte, 32))
			wantErr(t, err, ErrConflict)
			guard, err := f.a.Admit(data, v.ID, true)
			if guard != nil {
				guard.Release()
				t.Fatal("reopen accepted an old DATA principal")
			}
			wantErr(t, err, ErrUnauthorized)
			if !reflect.DeepEqual(before, lifecycleFiles(t, f)) || *f.a.s.Lifecycle.HandoffFence != fence || f.a.s.Attachments[binding.Attachment].Binding != binding {
				t.Fatal("replays changed fence, DATA identity, or disk")
			}
		})
	}
}
