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

func lifecycleInitialTemporary(t *testing.T, f *fixture, prefix string) string {
	t.Helper()
	for name := range lifecycleFiles(t, f) {
		if lifecycleTemporary(name, prefix) {
			return name
		}
	}
	t.Fatal("missing real initial proof temporary")
	return ""
}

func TestLifecycleInitialTemporaryRefusesWithoutMutation(t *testing.T) {
	for _, mode := range []string{"checkpoint", "root-only"} {
		kinds := []string{"empty", "partial", "noncanonical", "unknown-field", "version", "prior", "epoch", "store", "revision", "mode", "hardlink", "symlink", "directory", "fifo", "oversize", "filename", "duplicate", "state-candidate", "copy-overlap", "root", "anchor"}
		if mode == "checkpoint" {
			kinds = append(kinds, "ready", "same-next", "invalid-next", "overflow")
		} else {
			kinds = append(kinds, "attempt", "binding", "operation", "controller", "bootstrap", "volume", "ineligible", "metadata-overlap")
		}
		for _, kind := range kinds {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				boundary, prefix := "proof-close", "proof-"
				if mode == "root-only" {
					boundary, prefix = "prepare-retire-proof-close", "prepare-retire-proof-"
				}
				f, current, expected, b := lifecycleRecoveryCrash(t, mode, boundary)
				path := filepath.Join(f.path, registryName)
				name := lifecycleInitialTemporary(t, f, prefix)
				file := filepath.Join(path, name)
				raw, err := os.ReadFile(file)
				must(t, err)
				if mode == "checkpoint" {
					p, err := decodeCommitProof(raw)
					must(t, err)
					switch kind {
					case "version":
						p.Version++
					case "prior":
						p.Prior = contentDigest([]byte("foreign"))
					case "epoch":
						p.Epoch = mustID(t)
					case "store":
						p.Store = mustID(t)
					case "revision":
						p.Revision++
					case "ready":
						p.Ready = true
					case "same-next":
						p.Next = p.Prior
					case "invalid-next":
						p.Next = "invalid"
					case "overflow":
						var s diskState
						state, err := os.ReadFile(filepath.Join(path, stateName))
						must(t, err)
						must(t, json.Unmarshal(state, &s))
						s.Revision = ^uint64(0)
						state = retirementJSON(t, s)
						must(t, os.WriteFile(filepath.Join(path, stateName), state, 0600))
						p.Prior, p.Revision = contentDigest(state), 1
					}
					raw = retirementJSON(t, p)
				} else {
					p, err := decodePrepareRetirementProof(raw)
					must(t, err)
					switch kind {
					case "version":
						p.Version++
					case "prior":
						p.Prior = contentDigest([]byte("foreign"))
					case "epoch":
						p.Epoch = mustID(t)
					case "store":
						p.Store.ID = mustID(t)
					case "revision":
						p.Revision++
					case "attempt":
						p.Attempt = mustID(t)
					case "binding":
						p.Binding.Launch = mustID(t)
					case "operation":
						p.Operation = mustID(t)
					case "controller":
						p.Controller.Key = fp(t, newKey(t))
					case "bootstrap":
						p.Bootstrap = fp(t, newKey(t))
					case "volume":
						p.Volume.Root.Inode++
					case "ineligible":
						var s diskState
						state, err := os.ReadFile(filepath.Join(path, stateName))
						must(t, err)
						must(t, json.Unmarshal(state, &s))
						rec := s.Attachments[b.Attachment]
						rec.Phase = Active
						s.Attachments[b.Attachment] = rec
						state = retirementJSON(t, s)
						must(t, os.WriteFile(filepath.Join(path, stateName), state, 0600))
						p.Prior = contentDigest(state)
					}
					raw = retirementJSON(t, p)
				}
				switch kind {
				case "empty":
					raw = nil
				case "partial":
					raw = raw[:len(raw)/2]
				case "noncanonical":
					raw = append(raw, '\n')
				case "unknown-field":
					raw = append([]byte(`{"unknown":1,`), raw[1:]...)
				case "oversize":
					raw = make([]byte, maxRetirementProofBytes+maxCommitProofBytes+1)
				}
				must(t, os.WriteFile(file, raw, 0600))
				switch kind {
				case "mode":
					must(t, os.Chmod(file, 0644))
				case "hardlink":
					must(t, os.Link(file, filepath.Join(t.TempDir(), "alias")))
				case "symlink", "directory", "fifo":
					must(t, os.Remove(file))
					if kind == "symlink" {
						target := filepath.Join(t.TempDir(), "proof")
						must(t, os.WriteFile(target, raw, 0600))
						must(t, os.Symlink(target, file))
					} else if kind == "directory" {
						must(t, os.Mkdir(file, 0700))
					} else {
						must(t, unix.Mkfifo(file, 0600))
					}
				case "filename":
					must(t, os.Rename(file, filepath.Join(path, prefix+"invalid.tmp")))
				case "duplicate":
					must(t, os.WriteFile(filepath.Join(path, prefix+string(mustID(t))+".tmp"), raw, 0600))
				case "state-candidate":
					must(t, os.WriteFile(filepath.Join(path, "state-"+string(mustID(t))+".tmp"), raw, 0600))
				case "copy-overlap":
					must(t, os.WriteFile(filepath.Join(path, copyOperationName), raw, 0600))
				case "metadata-overlap":
					must(t, os.WriteFile(filepath.Join(path, "proof-"+string(mustID(t))+".tmp"), raw, 0600))
				case "root":
					root := filepath.Join(f.path, "volumes", "prepare-target")
					must(t, os.Rename(root, root+"-retained"))
					must(t, os.Mkdir(root, 0700))
				case "anchor":
					expected.OpenRevision++
				}
				before := retirementJournalCensus(t, path)
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("refusal ran barrier"); return nil }
				for range 2 {
					a, err := OpenLifecycleExpected(f.c, current, expected)
					if a != nil {
						a.Close()
						t.Fatal("invalid candidate returned authority")
					}
					if err == nil {
						t.Fatal("invalid candidate admitted")
					}
					assertRetirementJournalCensus(t, path, before)
				}
			})
		}
	}
}

func TestLifecycleInitialTemporaryCleanupProcessCuts(t *testing.T) {
	for _, mode := range []string{"checkpoint", "root-only"} {
		for _, cut := range []string{"recover-lifecycle-temporary-unlink", "recover-lifecycle-temporary-sync"} {
			t.Run(mode+"/"+cut, func(t *testing.T) {
				boundary, prefix := "proof-close", "proof-"
				if mode == "root-only" {
					boundary, prefix = "prepare-retire-proof-close", "prepare-retire-proof-"
				}
				f, current, expected, _ := lifecycleRecoveryCrash(t, mode, boundary)
				name := lifecycleInitialTemporary(t, f, prefix)
				before := lifecycleFiles(t, f)[stateName]
				// Real cleanup writer seam: no fabricated publication or barrier.
				lifecycleCopyTemporaryCrash(t, f, copyOperationRecord{}, cut, name)
				if lifecycleFiles(t, f)[stateName] != before {
					t.Fatal("cleanup changed state")
				}
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("cleanup ran barrier"); return nil }
				for range 2 {
					var err error
					f.a, err = OpenLifecycleExpected(f.c, current, expected)
					must(t, err)
					expected = expectedLifecycleStartup(f)
					must(t, f.a.Close())
				}
			})
		}
	}
}

type lifecycleMixedCrashInput struct {
	Root, Boundary string
	Bootstrap      []byte
	Cleanup        []string
	Recover        bool
}

// Journal seam with a genuinely published copy record and real metadata IO.
// This is host authority coverage, not native DATA/preflight qualification.
func TestLifecycleMixedMetadataCrashHelper(t *testing.T) {
	raw := os.Getenv("CENGINE_LIFECYCLE_MIXED_CRASH")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	var input lifecycleMixedCrashInput
	must(t, json.Unmarshal([]byte(raw), &input))
	root, err := os.Open(input.Root)
	must(t, err)
	c, err := configured(Config{Root: root, DeviceID: "test-device-uuid", BootstrapKey: input.Bootstrap, Barrier: func(Binding, *os.File) error { return nil }})
	must(t, err)
	j, err := openJournal(c, false)
	must(t, err)
	j.afterStep = func(step string) {
		if step == input.Boundary {
			os.Exit(crashExit)
		}
	}
	if input.Recover {
		must(t, j.clearLifecycleTemporaries(input.Cleanup))
		err = j.recoverUncertainty()
	} else {
		s, err := j.load()
		must(t, err)
		s.Revision++
		err = j.persist(s)
	}
	t.Fatalf("cut not reached: %v", err)
}

func lifecycleMixedMetadataCrash(t *testing.T, f *fixture, boundary string, cleanup []string, recover bool) {
	t.Helper()
	input := lifecycleMixedCrashInput{f.path, boundary, f.c.BootstrapKey, cleanup, recover}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleMixedMetadataCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CENGINE_LIFECYCLE_MIXED_CRASH="+string(retirementJSON(t, input)), "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != crashExit {
		t.Fatalf("not abrupt exit: %v\n%s", err, out)
	}
}

func TestLifecycleCopyMixedMetadataProcessRecovery(t *testing.T) {
	for _, boundary := range []string{"proof-parent-sync", "state-write", "state-sync", "state-close", "proof-ready-write", "proof-ready-sync", "proof-ready-close", "proof-ready-parent-sync", "state-rename", "state-parent-sync"} {
		for _, action := range []string{CopyOperationBegin, CopyOperationRollback} {
			t.Run(action+"/"+boundary, func(t *testing.T) {
				f, current := newLifecycleFixture(t)
				phase := ""
				if copyDataAction(action) {
					phase = CopySealed
				}
				v, b, g, replay := lifecycleCopyMarker(t, f, action, phase)
				expected := expectedLifecycleStartup(f)
				closeLifecycleCopyCrash(t, f, g)
				lifecycleMixedMetadataCrash(t, f, boundary, nil, false)
				path := filepath.Join(f.path, registryName)
				census := retirementJournalCensus(t, path)
				var before diskState
				must(t, json.Unmarshal([]byte(lifecycleFiles(t, f)[stateName]), &before))
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("metadata recovery ran barrier"); return nil }
				calls := 0
				if copyDataAction(action) {
					f.c.CopyRecoveryPreflight = nil
					_, err := OpenLifecycleExpected(f.c, current, expected)
					wantErr(t, err, ErrRepairRequired)
					assertRetirementJournalCensus(t, path, census)
					f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
						calls++
						assertRetirementJournalCensus(t, path, census)
						return ErrConflict
					}
					_, err = OpenLifecycleExpected(f.c, current, expected)
					wantErr(t, err, ErrRepairRequired)
					assertRetirementJournalCensus(t, path, census)
					if calls != 1 {
						t.Fatal("missing failing preflight")
					}
				}
				f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
					calls++
					assertRetirementJournalCensus(t, path, census)
					return nil
				}
				for range 2 {
					var err error
					f.a, err = OpenLifecycleExpected(f.c, current, expected)
					must(t, err)
					assertLifecycleCopyRecovered(t, f, &before, b, replay)
					if copyDataAction(action) && (!f.a.copyReplayPending(v.ID) || f.a.copyFences[v.ID] == nil) {
						t.Fatal("lost DATA fence")
					}
					before, expected = *f.a.clone(), expectedLifecycleStartup(f)
					must(t, f.a.Close())
					census = retirementJournalCensus(t, path)
				}
				wantCalls := 0
				if copyDataAction(action) {
					wantCalls = 3
				}
				if calls != wantCalls {
					t.Fatalf("preflight calls = %d, want %d", calls, wantCalls)
				}
			})
		}
	}
}

func TestLifecycleCopyMixedMetadataRefusesBeforeMutation(t *testing.T) {
	for _, kind := range []string{"copy-malformed", "copy-binding", "copy-mode", "copy-hardlink", "copy-symlink", "metadata-prior", "metadata-epoch", "metadata-store", "metadata-version", "candidate-digest", "unpublished-copy", "root-only-overlap"} {
		t.Run(kind, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			_, _, g, replay := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
			expected := expectedLifecycleStartup(f)
			closeLifecycleCopyCrash(t, f, g)
			lifecycleMixedMetadataCrash(t, f, "state-sync", nil, false)
			path := filepath.Join(f.path, registryName)
			marker := filepath.Join(path, copyOperationName)
			proofPath := filepath.Join(path, commitProofName)
			raw, err := os.ReadFile(proofPath)
			must(t, err)
			p, err := decodeCommitProof(raw)
			must(t, err)
			switch kind {
			case "copy-malformed":
				must(t, os.WriteFile(marker, []byte("{"), 0600))
			case "copy-binding":
				replay.Binding.Launch = mustID(t)
				must(t, os.WriteFile(marker, retirementJSON(t, replay), 0600))
			case "copy-mode":
				must(t, os.Chmod(marker, 0644))
			case "copy-hardlink":
				must(t, os.Link(marker, filepath.Join(t.TempDir(), "alias")))
			case "copy-symlink":
				must(t, os.Remove(marker))
				target := filepath.Join(t.TempDir(), "copy")
				must(t, os.WriteFile(target, retirementJSON(t, replay), 0600))
				must(t, os.Symlink(target, marker))
			case "metadata-prior":
				p.Prior = contentDigest([]byte("foreign"))
			case "metadata-epoch":
				p.Epoch = mustID(t)
			case "metadata-store":
				p.Store = mustID(t)
			case "metadata-version":
				p.Version++
			case "candidate-digest":
				name := lifecycleInitialTemporary(t, f, "state-")
				must(t, os.WriteFile(filepath.Join(path, name), []byte("{}"), 0600))
			case "unpublished-copy":
				must(t, os.Rename(marker, filepath.Join(path, "copy-op-"+string(mustID(t))+".tmp")))
			case "root-only-overlap":
				must(t, os.WriteFile(filepath.Join(path, "prepare-retire-proof-"+string(mustID(t))+".tmp"), raw, 0600))
			}
			must(t, os.WriteFile(proofPath, retirementJSON(t, p), 0600))
			census := retirementJournalCensus(t, path)
			f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
				t.Fatal("invalid pair reached preflight")
				return nil
			}
			for range 2 {
				a, err := OpenLifecycleExpected(f.c, current, expected)
				if a != nil {
					a.Close()
					t.Fatal("invalid pair returned authority")
				}
				if err == nil {
					t.Fatal("invalid pair admitted")
				}
				assertRetirementJournalCensus(t, path, census)
			}
		})
	}
}

func TestLifecycleCopyMixedMetadataCleanupProcessCuts(t *testing.T) {
	for _, cut := range []string{"recover-lifecycle-temporary-unlink", "recover-lifecycle-temporary-sync", "recover-state-parent-sync", "recover-proof-unlink", "recover-proof-sync"} {
		t.Run(cut, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			_, b, g, replay := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
			before, expected := f.a.clone(), expectedLifecycleStartup(f)
			closeLifecycleCopyCrash(t, f, g)
			lifecycleMixedMetadataCrash(t, f, "proof-ready-close", nil, false)
			cleanup := []string{lifecycleInitialTemporary(t, f, "proof-"), lifecycleInitialTemporary(t, f, "state-")}
			lifecycleMixedMetadataCrash(t, f, cut, cleanup, true)
			var state diskState
			must(t, json.Unmarshal([]byte(lifecycleFiles(t, f)[stateName]), &state))
			if !reflect.DeepEqual(before, &state) {
				t.Fatal("cleanup changed predecessor")
			}
			f.c.CopyRecoveryPreflight = copyDataPreflight
			for range 2 {
				var err error
				f.a, err = OpenLifecycleExpected(f.c, current, expected)
				must(t, err)
				assertLifecycleCopyRecovered(t, f, before, b, replay)
				before, expected = f.a.clone(), expectedLifecycleStartup(f)
				must(t, f.a.Close())
			}
		})
	}
}
