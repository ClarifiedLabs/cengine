//go:build linux || darwin

package storageauthority

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type lifecycleCopyTemporaryCrashInput struct {
	Root, Boundary, Temporary string
	Bootstrap                 []byte
	Record                    copyOperationRecord
}

// This drives the real journal writer and exits without Go cleanup. The record
// comes from a real BeginCopyOperation, but the subprocess uses a journal seam:
// these are not native/nonexporting-key or physical ext4 recovery tests.
func TestLifecycleCopyTemporaryCrashHelper(t *testing.T) {
	raw := os.Getenv("CENGINE_LIFECYCLE_COPY_TEMP_CRASH")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	var input lifecycleCopyTemporaryCrashInput
	must(t, json.Unmarshal([]byte(raw), &input))
	root, err := os.Open(input.Root)
	must(t, err)
	c, err := configured(Config{Root: root, DeviceID: "test-device-uuid", BootstrapKey: input.Bootstrap,
		Barrier: func(Binding, *os.File) error { return nil }})
	must(t, err)
	j, err := openJournal(c, false)
	must(t, err)
	j.afterStep = func(step string) {
		if step == input.Boundary {
			os.Exit(crashExit)
		}
	}
	if input.Temporary == "" {
		err = j.writeCopyOperation(input.Record)
	} else {
		err = j.clearLifecycleTemporaries([]string{input.Temporary})
	}
	t.Fatalf("cut not reached: %v", err)
}

func lifecycleCopyTemporaryCrash(t *testing.T, f *fixture, record copyOperationRecord, boundary, temporary string) {
	t.Helper()
	input := lifecycleCopyTemporaryCrashInput{f.path, boundary, temporary, f.c.BootstrapKey, record}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleCopyTemporaryCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CENGINE_LIFECYCLE_COPY_TEMP_CRASH="+string(retirementJSON(t, input)), "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != crashExit {
		t.Fatalf("not abrupt exit: %v\n%s", err, out)
	}
}

func lifecycleCopyTemporaryName(t *testing.T, f *fixture) string {
	t.Helper()
	files := lifecycleFiles(t, f)
	if len(files) != 3 {
		t.Fatalf("wanted base pair plus one temporary, got %d entries", len(files))
	}
	for name := range files {
		if lifecycleTemporary(name, "copy-op-") {
			return name
		}
	}
	t.Fatal("missing complete unpublished candidate")
	return ""
}

func assertLifecycleCopyTemporaryRecovered(t *testing.T, f *fixture, before *diskState, b Binding) {
	t.Helper()
	if f.a.s.Epoch == before.Epoch || f.a.s.Revision != before.Revision+1 {
		t.Fatal("startup did not publish exactly one fresh service epoch")
	}
	if !reflect.DeepEqual(f.a.s.Copy, before.Copy) || !reflect.DeepEqual(f.a.s.CopyReplay, before.CopyReplay) {
		t.Fatal("temporary changed intent or acquired/replaced replay authority")
	}
	if !reflect.DeepEqual(f.a.s.Prepares, before.Prepares) {
		t.Fatal("startup changed original PREPARE/context")
	}
	at := f.a.s.Attachments[b.Attachment]
	if at.Phase != Retiring || at.Receipt != nil || at.Retirement != "" {
		t.Fatal("startup invented attachment completion or a drain receipt")
	}
	must(t, f.a.validate())
	files := lifecycleFiles(t, f)
	if len(files) != 2 {
		t.Fatal("startup did not leave the clean base pair")
	}
	if _, ok := files["lock"]; !ok {
		t.Fatal("missing lock")
	}
	var persisted diskState
	must(t, json.Unmarshal([]byte(files[stateName]), &persisted))
	if !reflect.DeepEqual(&persisted, f.a.s) {
		t.Fatal("returned state differs from durable state")
	}
}

func TestLifecycleCopyTemporaryProcessCloseRecovery(t *testing.T) {
	for _, cold := range []bool{false, true} {
		mode := "expected"
		if cold {
			mode = "cold"
		}
		for _, tc := range []struct{ action, phase string }{
			{CopyOperationBegin, ""}, {CopyOperationBegin, CopyBegun},
			{CopyOperationProvision, CopyBegun}, {CopyOperationSeal, CopyBound},
			{CopyOperationCleanup, CopySealed}, {CopyOperationFinish, CopyCleaning},
			{CopyOperationRollback, CopySealed}, {CopyOperationDirectoryTail, CopySealed},
			{CopyOperationDirectoryTail, CopyCompleted},
		} {
			t.Run(mode+"/"+tc.action+"/"+tc.phase, func(t *testing.T) {
				f, current := newLifecycleFixture(t)
				_, b, g, record := lifecycleCopyMarker(t, f, tc.action, tc.phase)
				before := f.a.clone()
				origin := before.Prepares[b.Prepare].Context
				if record.Version != 2 || record.Epoch != origin.ServiceEpoch || record.Controller != (Controller{origin.ControllerEpoch, origin.ControllerKey}) {
					t.Fatal("new marker lost original PREPARE E/C/key")
				}
				expected := expectedLifecycleStartup(f)
				r := coldRequest(t, f, current, expected, fp(t, newKey(t)))
				closeLifecycleCopyCrash(t, f, g)
				// Re-run the writer with the exact admitted prestate record. Only
				// the subprocess's real copy-op-close cut supplies the candidate.
				must(t, os.Remove(filepath.Join(f.path, registryName, copyOperationName)))
				lifecycleCopyTemporaryCrash(t, f, record, "copy-op-close", "")
				name := lifecycleCopyTemporaryName(t, f)
				if lifecycleFiles(t, f)[name] != string(retirementJSON(t, record)) {
					t.Fatal("close cut did not preserve exact canonical record")
				}
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("temporary startup drained DATA"); return nil }
				f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
					t.Fatal("unpublished candidate acquired DATA preflight/replay authority")
					return nil
				}
				var err error
				if cold {
					f.a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
					current = r.Takeover
				} else {
					f.a, err = OpenLifecycleExpected(f.c, current, expected)
				}
				must(t, err)
				assertLifecycleCopyTemporaryRecovered(t, f, before, b)
				if len(f.a.s.CopyReplay) != 0 {
					t.Fatal("temporary invented replay")
				}
				wantController := before.Controller
				if cold {
					wantController = Controller{before.Controller.Epoch + 1, r.Takeover.Grant.NewKey}
				}
				if f.a.s.Controller != wantController {
					t.Fatal("wrong startup controller")
				}
				before, expected = f.a.clone(), expectedLifecycleStartup(f)
				must(t, f.a.Close())
				f.a, err = OpenLifecycleExpected(f.c, current, expected)
				must(t, err)
				assertLifecycleCopyTemporaryRecovered(t, f, before, b)
			})
		}
	}
}

func TestLifecycleCopyTemporaryRefusesWithoutMutation(t *testing.T) {
	for _, cold := range []bool{false, true} {
		mode := "expected"
		if cold {
			mode = "cold"
		}
		for _, kind := range []string{
			"empty", "partial", "garbage", "noncanonical", "unknown-field", "duplicate-field", "version", "future-version",
			"action", "sequence", "intent", "root", "binding", "epoch", "controller-epoch", "controller-key", "before",
			"mode", "hardlink", "symlink", "directory", "fifo", "oversize", "invalid-uuid", "wrong-prefix",
			"mixed-temp", "state-temp", "proof-temp", "published", "uncertain", "barrier", "unrelated-root", "device",
			"grant", "anchor-epoch", "anchor-controller", "open-revision",
		} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				f, current := newLifecycleFixture(t)
				f.volume("unrelated")
				_, _, g, record := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
				expected := expectedLifecycleStartup(f)
				closeLifecycleCopyCrash(t, f, g)
				path := filepath.Join(f.path, registryName)
				name := "copy-op-" + string(mustID(t)) + ".tmp"
				marker := filepath.Join(path, name)
				must(t, os.Rename(filepath.Join(path, copyOperationName), marker))
				raw := retirementJSON(t, record)
				switch kind {
				case "empty":
					raw = nil
				case "partial":
					raw = raw[:len(raw)/2]
				case "garbage":
					raw = []byte("not json")
				case "noncanonical":
					raw = append(raw, '\n')
				case "unknown-field":
					raw = append([]byte(`{"unknown":1,`), raw[1:]...)
				case "duplicate-field":
					raw = append([]byte(`{"Version":2,`), raw[1:]...)
				case "version":
					record.Version = 1
				case "future-version":
					record.Version = 3
				case "action":
					record.Action = "ordinary-data"
				case "sequence":
					record.Sequence = 0
				case "intent":
					record.Intent = mustID(t)
				case "root":
					record.Root.Inode++
				case "binding":
					record.Binding.Attachment = mustID(t)
				case "epoch":
					record.Epoch = mustID(t)
				case "controller-epoch":
					record.Controller.Epoch++
				case "controller-key":
					record.Controller.Key = fp(t, newKey(t))
				case "before":
					record.Before.ManifestSize++
				}
				switch kind {
				case "version", "future-version", "action", "sequence", "intent", "root", "binding", "epoch", "controller-epoch", "controller-key", "before":
					raw = retirementJSON(t, record)
				}
				must(t, os.WriteFile(marker, raw, 0600))
				switch kind {
				case "mode":
					must(t, os.Chmod(marker, 0644))
				case "hardlink":
					must(t, os.Link(marker, filepath.Join(t.TempDir(), "alias")))
				case "symlink", "directory", "fifo":
					must(t, os.Remove(marker))
					if kind == "symlink" {
						target := filepath.Join(t.TempDir(), "record")
						must(t, os.WriteFile(target, raw, 0600))
						must(t, os.Symlink(target, marker))
					} else if kind == "directory" {
						must(t, os.Mkdir(marker, 0700))
					} else {
						must(t, unix.Mkfifo(marker, 0600))
					}
				case "oversize":
					must(t, os.WriteFile(marker, make([]byte, maxCopyOperationBytes+1), 0600))
				case "invalid-uuid":
					must(t, os.Rename(marker, filepath.Join(path, "copy-op-not-a-uuid.tmp")))
				case "wrong-prefix":
					must(t, os.Rename(marker, filepath.Join(path, "copy-other-"+string(mustID(t))+".tmp")))
				case "mixed-temp", "state-temp", "proof-temp":
					prefix := map[string]string{"mixed-temp": "copy-op-", "state-temp": "state-", "proof-temp": "proof-"}[kind]
					must(t, os.WriteFile(filepath.Join(path, prefix+string(mustID(t))+".tmp"), raw, 0600))
				case "published":
					must(t, os.WriteFile(filepath.Join(path, copyOperationName), raw, 0600))
				case "uncertain", "barrier":
					name := pendingName
					if kind == "barrier" {
						name = barrierName
					}
					must(t, os.WriteFile(filepath.Join(path, name), []byte(uncertainMarkerText), 0600))
				case "unrelated-root":
					root := filepath.Join(f.path, "volumes", "unrelated")
					must(t, os.Rename(root, root+"-hidden"))
				case "device":
					f.c.DeviceID += "-foreign"
				case "grant":
					current.Grant.ID = mustID(t)
					current = signLifecycle(t, f.bootstrap, current.Grant)
				case "anchor-epoch":
					expected.Epoch = mustID(t)
				case "anchor-controller":
					expected.Controller.Key = fp(t, newKey(t))
				case "open-revision":
					expected.OpenRevision++
				}
				before := retirementJournalCensus(t, path)
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("refusal ran barrier"); return nil }
				f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
					t.Fatal("invalid temporary reached preflight")
					return nil
				}
				var a *Authority
				var err error
				if cold {
					r := coldRequest(t, f, current, expected, fp(t, newKey(t)))
					if kind == "anchor-controller" {
						// Keep the request structurally signable while presenting a
						// coherent but false predecessor controller/grant anchor.
						r.Predecessor.CurrentGrant.NewKey = expected.Controller.Key
					}
					a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
				} else {
					a, err = OpenLifecycleExpected(f.c, current, expected)
				}
				if a != nil {
					a.Close()
					t.Fatal("invalid temporary returned authority")
				}
				if err == nil {
					t.Fatal("invalid temporary accepted")
				}
				assertRetirementJournalCensus(t, path, before)
			})
		}
	}
}

func TestLifecycleCopyTemporaryPendingDataReplay(t *testing.T) {
	for _, cold := range []bool{false, true} {
		mode := "expected"
		if cold {
			mode = "cold"
		}
		for _, kind := range []string{"auxiliary", "same-action", "prior-mismatch", "missing-preflight", "failing-preflight"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				f, current := newLifecycleFixture(t)
				v, b, g, pending := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
				expected := expectedLifecycleStartup(f)
				closeLifecycleCopyCrash(t, f, g)
				f.c.CopyRecoveryPreflight = copyDataPreflight
				var err error
				f.a, err = OpenLifecycleExpected(f.c, current, expected)
				must(t, err)
				f.control = f.authControl(f.controllerKey, f.a.s.Controller.Epoch)
				g = copySuccessor(t, f, b)
				_, err = g.BeginCopy(copyRoot(f, v))
				must(t, err)
				b = g.token.binding
				action, id := CopyOperationBegin, ID("")
				if kind == "same-action" {
					action, id = CopyOperationRollback, pending.Intent
				}
				o, err := g.BeginCopyOperation(51, action, id)
				must(t, err)
				record := o.token.record
				if kind != "same-action" && (record.Prior == nil || !reflect.DeepEqual(*record.Prior, pending)) {
					t.Fatal("fresh auxiliary marker lost exact prior DATA replay")
				}
				beforeState := f.a.clone()
				expected = expectedLifecycleStartup(f)
				r := coldRequest(t, f, current, expected, fp(t, newKey(t)))
				closeLifecycleCopyCrash(t, f, g)
				path := filepath.Join(f.path, registryName)
				must(t, os.Remove(filepath.Join(path, copyOperationName)))
				lifecycleCopyTemporaryCrash(t, f, record, "copy-op-close", "")
				name := lifecycleCopyTemporaryName(t, f)
				if kind == "prior-mismatch" {
					record.Prior.Sequence++
					must(t, os.WriteFile(filepath.Join(path, name), retirementJSON(t, record), 0600))
				}
				before := retirementJournalCensus(t, path)
				calls := 0
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("startup drained successor"); return nil }
				f.c.CopyRecoveryPreflight = nil
				if kind != "missing-preflight" {
					f.c.CopyRecoveryPreflight = func(root *os.File, device, action string, intent CopyIntent) error {
						calls++
						assertRetirementJournalCensus(t, path, before)
						rootID, err := identity(root)
						must(t, err)
						if rootID != v.Root || device != beforeState.Store.DeviceID || action != pending.Action || intent != beforeState.Copy.Intents[v.ID] {
							t.Fatal("temporary replaced existing DATA preflight inputs")
						}
						if kind == "failing-preflight" {
							return ErrConflict
						}
						return nil
					}
				}
				var a *Authority
				if cold {
					a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
				} else {
					a, err = OpenLifecycleExpected(f.c, current, expected)
				}
				if kind == "auxiliary" || kind == "same-action" {
					must(t, err)
					f.a = a
					assertLifecycleCopyTemporaryRecovered(t, f, beforeState, b)
					if !reflect.DeepEqual(f.a.s.CopyReplay[v.ID], pending) || !f.a.copyReplayPending(v.ID) || f.a.copyFences[v.ID] == nil {
						t.Fatal("temporary lost the exact old replay/fence")
					}
				} else {
					if a != nil {
						a.Close()
						t.Fatal("invalid pending-replay candidate returned authority")
					}
					wantErr(t, err, ErrRepairRequired)
					assertRetirementJournalCensus(t, path, before)
				}
				wantCalls := 0
				if kind == "auxiliary" || kind == "same-action" || kind == "failing-preflight" {
					wantCalls = 1
				}
				if calls != wantCalls {
					t.Fatalf("preflight calls = %d, want %d", calls, wantCalls)
				}
			})
		}
	}
}

func TestLifecycleCopyTemporaryRejectsHistoricalReplay(t *testing.T) {
	for _, cold := range []bool{false, true} {
		mode := "expected"
		if cold {
			mode = "cold"
		}
		t.Run(mode, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			_, _, g, record := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
			expected := expectedLifecycleStartup(f)
			closeLifecycleCopyCrash(t, f, g)
			f.c.CopyRecoveryPreflight = copyDataPreflight
			var err error
			f.a, err = OpenLifecycleExpected(f.c, current, expected)
			must(t, err)
			// Isolate the temporary's extra epoch guard: canonical matching and
			// exact Before both succeed for this still-valid historical replay.
			_, err = f.a.decodeCopyOperation(retirementJSON(t, record))
			must(t, err)
			if record.Before != f.a.s.Copy.Intents[record.Binding.Volume] || record.Epoch == f.a.s.Epoch {
				t.Fatal("historical test did not isolate the current-epoch requirement")
			}
			expected = expectedLifecycleStartup(f)
			r := coldRequest(t, f, current, expected, fp(t, newKey(t)))
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName)
			must(t, os.WriteFile(filepath.Join(path, "copy-op-"+string(mustID(t))+".tmp"), retirementJSON(t, record), 0600))
			before := retirementJournalCensus(t, path)
			f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
				t.Fatal("historical temporary reached DATA preflight")
				return nil
			}
			var a *Authority
			if cold {
				a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
			} else {
				a, err = OpenLifecycleExpected(f.c, current, expected)
			}
			if a != nil {
				a.Close()
				t.Fatal("historical temporary returned authority")
			}
			wantErr(t, err, ErrRepairRequired)
			assertRetirementJournalCensus(t, path, before)
		})
	}
}

func TestLifecycleCopyTemporaryRejectsAdvancedPrestate(t *testing.T) {
	f, current := newLifecycleFixture(t)
	v, _, g, record := lifecycleCopyMarker(t, f, CopyOperationSeal, CopyBound)
	must(t, g.SealCopyManifest(record.Intent, copyObject(v.Root.Inode+1), []byte("sealed whole-intent undo")))
	// The published replay matcher permits this transition. A temporary cannot:
	// caller IO was not allowed to begin before publication.
	_, err := f.a.decodeCopyOperation(retirementJSON(t, record))
	must(t, err)
	expected := expectedLifecycleStartup(f)
	closeLifecycleCopyCrash(t, f, g)
	path := filepath.Join(f.path, registryName)
	must(t, os.Rename(filepath.Join(path, copyOperationName), filepath.Join(path, "copy-op-"+string(mustID(t))+".tmp")))
	before := retirementJournalCensus(t, path)
	a, err := OpenLifecycleExpected(f.c, current, expected)
	if a != nil {
		a.Close()
		t.Fatal("advanced temporary returned authority")
	}
	wantErr(t, err, ErrRepairRequired)
	assertRetirementJournalCensus(t, path, before)
}

func TestLifecycleCopyTemporaryCleanupProcessCuts(t *testing.T) {
	for _, cut := range []string{"recover-lifecycle-temporary-unlink", "recover-lifecycle-temporary-sync"} {
		t.Run(cut, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			_, b, g, record := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
			before, expected := f.a.clone(), expectedLifecycleStartup(f)
			closeLifecycleCopyCrash(t, f, g)
			path := filepath.Join(f.path, registryName)
			must(t, os.Remove(filepath.Join(path, copyOperationName)))
			lifecycleCopyTemporaryCrash(t, f, record, "copy-op-close", "")
			name := lifecycleCopyTemporaryName(t, f)
			stateBytes := lifecycleFiles(t, f)[stateName]
			// Direct cleanup seam: the cut proves unlink/fsync retry behavior,
			// not the ordering of the full startup (covered by preflight tests).
			lifecycleCopyTemporaryCrash(t, f, record, cut, name)
			if lifecycleFiles(t, f)[stateName] != stateBytes || len(lifecycleFiles(t, f)) != 2 {
				t.Fatal("cleanup cut mutated state or retained candidate")
			}
			f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error { t.Fatal("cleanup invented replay"); return nil }
			var err error
			f.a, err = OpenLifecycleExpected(f.c, current, expected)
			must(t, err)
			assertLifecycleCopyTemporaryRecovered(t, f, before, b)
		})
	}
}
