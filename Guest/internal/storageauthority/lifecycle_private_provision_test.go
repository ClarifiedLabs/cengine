//go:build linux || darwin

package storageauthority

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// Exercise the real provision writer through the durable private BOUND edge.
// The panic models process teardown without an IO error/quarantine. Inode/type
// are real; hostCopyObject supplies synthetic ext4 generation/handle fields.
func lifecyclePrivateProvisionCut(t *testing.T) (*fixture, SignedLifecycleGrant, Binding, copyOperationRecord) {
	t.Helper()
	f, current := newLifecycleFixture(t)
	v := f.volume("private-provision")
	b, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	op := copyObligation(t, g, CopyOperationProvision, i.ID)
	cut := new(int)
	f.a.j.afterStep = func(step string) {
		if step == "copy-bound-durable" {
			panic(cut)
		}
	}
	func() {
		defer func() {
			if r := recover(); r != cut {
				t.Fatalf("did not stop at private BOUND: %v", r)
			}
		}()
		_, err := g.ProvisionCopyTransaction(i.ID, hostCopyObject)
		t.Fatalf("provision returned before cut: %v", err)
	}()
	f.a.j.afterStep = nil
	closeLifecycleCopyCrash(t, f, g)
	return f, current, b, op.token.record
}

func TestLifecyclePrivateProvisionRecovery(t *testing.T) {
	for _, cold := range []bool{false, true} {
		mode := "expected"
		if cold {
			mode = "cold"
		}
		t.Run(mode, func(t *testing.T) {
			f, current, b, replay := lifecyclePrivateProvisionCut(t)
			path := filepath.Join(f.path, registryName)
			name := "copy-" + string(replay.Intent)
			private := retirementJournalCensus(t, path)[name]
			transaction := f.a.s.Copy.Intents[b.Volume].Transaction
			for restart := 0; restart < 3; restart++ {
				before := f.a.clone()
				expected := expectedLifecycleStartup(f)
				var err error
				if cold {
					key := newKey(t)
					r := coldRequest(t, f, current, expected, fp(t, key))
					f.a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
					current, f.controllerKey = r.Takeover, key
				} else {
					f.a, err = OpenLifecycleExpected(f.c, current, expected)
				}
				must(t, err)
				if f.a.s.Epoch == before.Epoch || f.a.s.Revision != before.Revision+1 ||
					!reflect.DeepEqual(f.a.s.Copy, before.Copy) || !reflect.DeepEqual(f.a.s.CopyReplay[b.Volume], replay) ||
					!reflect.DeepEqual(f.a.s.Prepares, before.Prepares) || f.a.s.Attachments[b.Attachment].Receipt != nil {
					t.Fatal("startup changed intent, replay, PREPARE or receipt beyond startup fencing")
				}
				files := retirementJournalCensus(t, path)
				if len(files) != 3 || !reflect.DeepEqual(files[name], private) || files[copyOperationName] != nil {
					t.Fatal("startup removed/changed private directory or retained operation marker")
				}
				must(t, absent(f.a.roots[b.Volume], copyTransactionName))
				must(t, f.a.validate())
				must(t, f.a.Close())
			}
			// The retained directory remains actionable, not silently discarded.
			var err error
			f.a, err = OpenLifecycleExpected(f.c, current, expectedLifecycleStartup(f))
			must(t, err)
			f.control = f.authControl(f.controllerKey, f.a.s.Controller.Epoch)
			g := copySuccessor(t, f, b)
			op := copyObligation(t, g, CopyOperationProvision, replay.Intent)
			i, err := g.ProvisionCopyTransaction(replay.Intent, hostCopyObject)
			must(t, err)
			must(t, op.Complete(nil))
			if i.Transaction != transaction {
				t.Fatal("replay changed bound transaction")
			}
			must(t, absent(f.a.j.dir, name))
			g.Release()
		})
	}
}

func TestLifecyclePrivateProvisionRefusalPreservesEvidence(t *testing.T) {
	for _, kind := range []string{"name", "inode", "file", "symlink", "mode", "nonempty", "public", "intent", "binding", "epoch", "root", "prior", "action", "type", "uncaptured", "mixed", "extra-private", "missing-proof", "stale-anchor", "identity-only"} {
		t.Run(kind, func(t *testing.T) {
			f, current, b, replay := lifecyclePrivateProvisionCut(t)
			expected := expectedLifecycleStartup(f)
			path := filepath.Join(f.path, registryName)
			name := "copy-" + string(replay.Intent)
			private := filepath.Join(path, name)
			state := f.a.clone()
			i := state.Copy.Intents[b.Volume]
			switch kind {
			case "name":
				must(t, os.Rename(private, filepath.Join(path, "copy-"+string(mustID(t)))))
			case "inode":
				must(t, os.Rename(private, filepath.Join(f.path, "retained-original")))
				must(t, os.Mkdir(private, 0700))
			case "file", "symlink":
				must(t, os.Remove(private))
				if kind == "file" {
					must(t, os.WriteFile(private, []byte("not a directory"), 0600))
				} else {
					must(t, os.Symlink(filepath.Join(f.path, "volumes"), private))
				}
			case "mode":
				must(t, os.Chmod(private, 0755))
			case "nonempty":
				must(t, os.WriteFile(filepath.Join(private, "foreign"), []byte("retain me"), 0600))
			case "public":
				must(t, os.Mkdir(filepath.Join(f.path, "volumes", "private-provision", copyTransactionName), 0700))
			case "intent":
				replay.Intent = mustID(t)
			case "binding":
				replay.Binding.Attachment = mustID(t)
			case "epoch":
				replay.Epoch = mustID(t)
			case "root":
				replay.Root.Device++
			case "prior":
				prior := replay
				replay.Prior = &prior
			case "action":
				replay.Action = CopyOperationSeal
			case "type":
				i.Transaction.FileType = unix.S_IFREG
			case "uncaptured":
				i.InitialCaptured, i.Initial = false, CopyCleanupV1{}
			case "mixed":
				must(t, os.WriteFile(filepath.Join(path, "copy-op-"+string(mustID(t))+".tmp"), retirementJSON(t, replay), 0600))
			case "extra-private":
				must(t, os.Mkdir(filepath.Join(path, "copy-"+string(mustID(t))), 0700))
			case "stale-anchor":
				expected.OpenRevision++
			}
			state.Copy.Intents[b.Volume] = i
			must(t, os.WriteFile(filepath.Join(path, stateName), retirementJSON(t, state), 0600))
			must(t, os.WriteFile(filepath.Join(path, copyOperationName), retirementJSON(t, replay), 0600))
			if kind == "missing-proof" {
				must(t, os.Remove(filepath.Join(path, copyOperationName)))
			}
			before := retirementJournalCensus(t, path)
			for attempt := 0; attempt < 2; attempt++ {
				var a *Authority
				var err error
				if kind == "identity-only" {
					a, err = OpenLifecycle(f.c, current.Grant.Identity)
				} else {
					a, err = OpenLifecycleExpected(f.c, current, expected)
				}
				if a != nil || err == nil {
					if a != nil {
						a.Close()
					}
					t.Fatal("accepted invalid private provision evidence")
				}
				assertRetirementJournalCensus(t, path, before)
			}
			if kind != "identity-only" {
				r := coldRequest(t, f, current, expected, fp(t, newKey(t)))
				a, err := ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
				if a != nil || err == nil {
					if a != nil {
						a.Close()
					}
					t.Fatal("cold startup accepted invalid private provision evidence")
				}
				assertRetirementJournalCensus(t, path, before)
			}
		})
	}
}
