//go:build linux || darwin

package storageauthority

import (
	"context"
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

func copyDataFixture(t *testing.T, f *fixture, phase string) (Volume, Binding, *Guard, CopyIntent) {
	t.Helper()
	v := f.volume("data-recovery")
	b, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	if phase != CopyBegun {
		must(t, g.BindCopyTransaction(i.ID, copyObject(v.Root.Inode+1)))
	}
	if phase == CopySealed || phase == CopyCleaning || phase == CopyCompleted {
		must(t, g.SealCopyManifest(i.ID, copyObject(v.Root.Inode+1), []byte("sealed whole-intent undo")))
	}
	if phase == CopyCleaning || phase == CopyCompleted {
		c := CopyCleanupV1{Mode: 0755, Manifest: copyObject(v.Root.Inode + 2)}
		c.Manifest.FileType = 0100000
		_, err = g.StartCopyCleanup(i.ID, copyObject(v.Root.Inode+1), c)
		must(t, err)
	}
	if phase == CopyCompleted {
		must(t, g.FinishCopy(i.ID))
	}
	return v, b, g, f.a.s.Copy.Intents[v.ID]
}

func copyDataPreflight(*os.File, string, string, CopyIntent) error { return nil }

func TestCopyDataOperationClosedTransitions(t *testing.T) {
	for _, action := range []string{CopyOperationRollback, CopyOperationDirectoryTail} {
		for _, phase := range []string{CopyBegun, CopyBound, CopySealed, CopyCleaning, CopyCompleted} {
			t.Run(action+"/"+phase, func(t *testing.T) {
				f := newFixture(t, nil)
				v, _, g, i := copyDataFixture(t, f, phase)
				private, err := g.BeginCopyOperation(1, action, i.ID)
				if action == CopyOperationRollback && phase == CopySealed {
					must(t, err) // normal SEALED recovery uses the same server-owned undo
					must(t, private.Complete(nil))
				} else if err == nil {
					t.Fatal("private control created unrelated fresh DATA obligation")
				}
				o, err := g.BeginCopyDataOperation(1, action, i.ID)
				allowed := phase == CopySealed || (action == CopyOperationDirectoryTail && (phase == CopyCleaning || phase == CopyCompleted))
				if !allowed {
					wantErr(t, err, ErrConflict)
					return
				}
				must(t, err)
				r := o.token.record
				if r.Version != 2 || r.Before != i || !f.a.matchCopyOperation(r) {
					t.Fatal("wrong exact copy DATA operation record")
				}
				for _, next := range []string{CopyBegun, CopyBound, CopySealed, CopyCleaning, CopyCompleted} {
					candidate := i
					candidate.Phase = next
					if next == CopyCleaning && phase == CopySealed {
						candidate.Cleanup = CopyCleanupV1{Manifest: copyObject(v.Root.Inode + 2)}
						candidate.Cleanup.Manifest.FileType = 0100000
					}
					f.a.s.Copy.Intents[v.ID] = candidate
					want := next == phase || (action == CopyOperationRollback && next == CopyCleaning)
					if f.a.matchCopyOperation(r) != want {
						t.Fatalf("transition %s -> %s", phase, next)
					}
				}
				for _, mutate := range []func(*CopyIntent){
					func(c *CopyIntent) { c.ID = mustID(t) }, func(c *CopyIntent) { c.Owner.Attachment = mustID(t) },
					func(c *CopyIntent) { c.Epoch = mustID(t) }, func(c *CopyIntent) { c.Root.BackingUUID[0]++ },
					func(c *CopyIntent) { c.Transaction.Generation++ }, func(c *CopyIntent) { c.ManifestDigest[0]++ },
					func(c *CopyIntent) { c.ManifestSize++ }, func(c *CopyIntent) { c.Initial.Mode++ },
					func(c *CopyIntent) { c.InitialCaptured = !c.InitialCaptured }, func(c *CopyIntent) { c.Cleanup.Mode++ },
				} {
					bad := i
					mutate(&bad)
					f.a.s.Copy.Intents[v.ID] = bad
					if f.a.matchCopyOperation(r) {
						t.Fatal("accepted unrelated intent change")
					}
				}
				f.a.s.Copy.Intents[v.ID] = i
				if action == CopyOperationRollback {
					bad := i
					bad.Phase = CopyCleaning // sealed rollback must add valid manifest identity
					f.a.s.Copy.Intents[v.ID] = bad
					if f.a.matchCopyOperation(r) {
						t.Fatal("accepted invalid cleanup")
					}
					f.a.s.Copy.Intents[v.ID] = i
				}
				must(t, o.Complete(nil))
			})
		}
	}
}

func TestCopyDataIntentScopeAndAdmittedRetirement(t *testing.T) {
	f := newFixture(t, nil)
	v, b, g, i := copyDataFixture(t, f, CopySealed)
	got, err := g.CopyDataIntent(i.Root)
	must(t, err)
	if got != i {
		t.Fatal("classifier changed intent")
	}
	for _, action := range []string{CopyOperationBegin, CopyOperationProvision, CopyOperationSeal, CopyOperationCleanup, CopyOperationFinish, "data", ""} {
		_, err = g.BeginCopyDataOperation(1, action, i.ID)
		wantErr(t, err, ErrInvalid)
	}
	_, err = g.BeginCopyDataOperation(0, CopyOperationRollback, i.ID)
	wantErr(t, err, ErrInvalid)
	_, err = g.BeginCopyDataOperation(1, CopyOperationRollback, mustID(t))
	wantErr(t, err, ErrUnauthorized)
	wrong := i.Root
	wrong.BackingUUID[0]++
	_, err = g.CopyDataIntent(wrong)
	wantErr(t, err, ErrConflict)
	delete(f.a.s.Copy.Intents, v.ID)
	_, err = g.CopyDataIntent(i.Root)
	wantErr(t, err, ErrUnauthorized)
	foreign := i
	foreign.Owner.Attachment = mustID(t)
	f.a.s.Copy.Intents[v.ID] = foreign
	_, err = g.CopyDataIntent(i.Root)
	wantErr(t, err, ErrUnauthorized)
	foreign = i
	foreign.Epoch = mustID(t)
	f.a.s.Copy.Intents[v.ID] = foreign
	_, err = g.CopyDataIntent(i.Root)
	wantErr(t, err, ErrUnauthorized)
	f.a.s.Copy.Intents[v.ID] = i
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	_, err = f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	got, err = g.CopyDataIntent(i.Root)
	must(t, err)
	if got != i {
		t.Fatal("retiring classifier changed scope")
	}
	device, err := g.CopyDataDeviceID()
	must(t, err)
	if device != f.c.DeviceID {
		t.Fatal("retiring DATA lost backing identity")
	}
	_, err = g.CopyDeviceID()
	wantErr(t, err, ErrUnauthorized)
	_, err = g.BeginCopyOperation(1, CopyOperationBegin, "")
	wantErr(t, err, ErrUnauthorized)
	o, err := g.BeginCopyDataOperation(1, CopyOperationRollback, i.ID)
	must(t, err)
	must(t, o.Complete(nil))
	g.Release()
	_, err = f.a.Retire(context.Background(), f.control, req)
	must(t, err)
	_, err = g.CopyDataIntent(i.Root)
	wantErr(t, err, ErrClosed)
}

func TestCopyDataRecoveryOwnershipReplayAndCompletedFence(t *testing.T) {
	for _, tc := range []struct {
		action, phase string
		cleaning      bool
	}{
		{CopyOperationRollback, CopySealed, false}, {CopyOperationRollback, CopySealed, true},
		{CopyOperationDirectoryTail, CopySealed, false}, {CopyOperationDirectoryTail, CopyCleaning, false},
		{CopyOperationDirectoryTail, CopyCompleted, false},
	} {
		t.Run(tc.action+"/"+tc.phase+map[bool]string{true: "-cleaning"}[tc.cleaning], func(t *testing.T) {
			f := newFixture(t, nil)
			v, b, g, i := copyDataFixture(t, f, tc.phase)
			o, err := g.BeginCopyDataOperation(1, tc.action, i.ID)
			must(t, err)
			if tc.cleaning {
				c := CopyCleanupV1{Manifest: copyObject(v.Root.Inode + 2)}
				c.Manifest.FileType = 0100000
				i, err = g.StartCopyCleanup(i.ID, i.Transaction, c)
				must(t, err)
				if !f.a.matchCopyOperation(o.token.record) {
					t.Fatal("rollback cleanup not matched")
				}
			}
			calls := 0
			f.c.CopyRecoveryPreflight = func(root *os.File, device, action string, current CopyIntent) error {
				calls++
				identity, e := identity(root)
				must(t, e)
				if identity != v.Root || device != f.c.DeviceID || action != tc.action || current != i {
					t.Fatal("wrong preflight scope")
				}
				return nil
			}
			restartCopyOperation(t, f, g)
			must(t, f.a.Close())
			f.a, err = f.openCurrent()
			must(t, err)
			f.control = f.authControl(f.controllerKey, f.a.s.Controller.Epoch)
			if calls != 2 || !f.a.copyReplayPending(v.ID) || f.a.copyFences[v.ID] == nil {
				t.Fatal("lost replay fence")
			}
			g = copySuccessor(t, f, b)
			i = f.a.s.Copy.Intents[v.ID]
			if i.Owner != g.token.binding || i.Epoch != f.a.s.Epoch {
				t.Fatal("replacement failed to transfer ownership")
			}
			pending, err := g.PendingCopyOperation(i.ID)
			must(t, err)
			if pending != tc.action {
				t.Fatal("wrong pending action")
			}
			got, err := g.InspectCopy(i.ID, i.Root)
			must(t, err)
			if got != i {
				t.Fatal("inspect lost completed intent")
			}
			_, err = g.CopyDataIntent(i.Root)
			wantErr(t, err, ErrBlocked)
			_, err = g.BeginCopyDataOperation(2, tc.action, i.ID)
			wantErr(t, err, ErrBlocked)
			_, err = g.BeginDurability(2)
			wantErr(t, err, ErrBlocked)
			for _, action := range []string{CopyOperationProvision, CopyOperationSeal, CopyOperationCleanup, CopyOperationFinish} {
				_, err = g.BeginCopyOperation(2, action, i.ID)
				if err == nil {
					t.Fatal("unrelated private action bypassed replay", action)
				}
			}
			if i.Phase == CopyCompleted {
				wantErr(t, g.FinishCopy(i.ID), ErrUnauthorized)
			} else {
				wantErr(t, g.FinishCopy(i.ID), ErrBlocked)
				_, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Cleanup)
				wantErr(t, err, ErrBlocked)
			}
			prior := f.a.s.CopyReplay[v.ID]
			aux := copyObligation(t, g, CopyOperationBegin, "")
			got, err = g.BeginCopy(i.Root)
			must(t, err)
			if got != i {
				t.Fatal("Begin replaced pending completed intent")
			}
			if tc.phase == CopyCompleted {
				// Auxiliary Begin must survive a crash without replacing the tail.
				old := g.token.binding
				restartCopyOperation(t, f, g)
				g = copySuccessor(t, f, old)
				i = f.a.s.Copy.Intents[v.ID]
			} else {
				must(t, aux.Complete(nil))
			}
			if !reflect.DeepEqual(prior, f.a.s.CopyReplay[v.ID]) {
				t.Fatal("auxiliary Begin erased replay")
			}
			o = copyObligation(t, g, tc.action, i.ID)
			must(t, o.CompleteRequest(nil, false))
			wantErr(t, g.CheckCopyReplay(), ErrBlocked)
			waiting := f.a.copyFences[v.ID]
			o = copyObligation(t, g, tc.action, i.ID)
			if tc.cleaning {
				// CLEANING rollback replay is itself exact and restartable.
				old := g.token.binding
				restartCopyOperation(t, f, g)
				g = copySuccessor(t, f, old)
				i = f.a.s.Copy.Intents[v.ID]
				o = copyObligation(t, g, tc.action, i.ID)
				got, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Cleanup)
				must(t, err)
				if got != i {
					t.Fatal("CLEANING replay changed evidence")
				}
			}
			must(t, o.Complete(nil))
			must(t, g.CheckCopyReplay())
			select {
			case <-waiting:
			default:
				t.Fatal("successful replay did not wake fence")
			}
			if tc.phase == CopyCompleted && f.a.copyFences[v.ID] != nil {
				t.Fatal("completed fence remains after clear")
			}
			must(t, f.a.validate())
		})
	}
}

func TestCopyDataCompletedTailBlocksPrepareCompletionAndNonowner(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("completed-tail")
	_, peer := f.runtime(v, ReadWrite)
	other, err := f.a.Admit(peer, v.ID, false)
	must(t, err)
	defer other.Release()
	b, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	must(t, g.FinishCopy(i.ID))
	o, err := g.BeginCopyDataOperation(1, CopyOperationDirectoryTail, i.ID)
	must(t, err)
	f.a.s.CopyReplay = map[ID]copyOperationRecord{v.ID: o.token.record}
	f.a.wakeCopyFence(v.ID)
	waiting := copyWaiting(t, other)
	must(t, o.CompleteRequest(nil, false))
	g.Release()
	r := f.retire(b)
	wantErr(t, f.a.CompletePrepare(f.control, CompleteRequest{mustID(t), b.Prepare, []Receipt{r}, Attestation{b.Prepare, true, true}}), ErrBlocked)
	g = copySuccessor(t, f, b)
	o = copyObligation(t, g, CopyOperationDirectoryTail, i.ID)
	must(t, o.Complete(nil))
	select {
	case <-waiting:
	default:
		t.Fatal("nonowner fence not notified")
	}
	copyUnfenced(t, other)
}

func copyDataCensus(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	result := map[string]string{}
	entries, err := os.ReadDir(filepath.Join(f.path, registryName))
	must(t, err)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(f.path, registryName, e.Name()))
		must(t, err)
		result[e.Name()] = string(b)
	}
	return result
}

func TestCopyDataRecoveryPreflightRefusesBeforeMutation(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		t.Run(map[bool]string{false: "slot", true: "metadata"}[metadata], func(t *testing.T) {
			f := newFixture(t, nil)
			_, _, g, i := copyDataFixture(t, f, CopySealed)
			_, err := g.BeginCopyDataOperation(1, CopyOperationRollback, i.ID)
			must(t, err)
			if metadata {
				func() {
					defer func() {
						if recover() != "crash" {
							t.Fatal("missing crash")
						}
					}()
					f.a.j.afterStep = func(s string) {
						if s == "state-sync" {
							panic("crash")
						}
					}
					next := f.a.clone()
					next.Revision++
					must(t, f.a.j.persist(next))
				}()
				f.a.j.afterStep = nil
			}
			f.a.copyIO = nil
			g.Release()
			must(t, f.a.Close())
			before := copyDataCensus(t, f)
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
			if !reflect.DeepEqual(before, copyDataCensus(t, f)) {
				t.Fatal("missing callback mutated journal")
			}
			calls := 0
			f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
				calls++
				if !reflect.DeepEqual(before, copyDataCensus(t, f)) {
					t.Fatal("cleanup preceded callback")
				}
				return ErrConflict
			}
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
			if calls != 1 || !reflect.DeepEqual(before, copyDataCensus(t, f)) {
				t.Fatal("refusal mutated evidence")
			}
			f.c.CopyRecoveryPreflight = copyDataPreflight
			f.a, err = f.openCurrent()
			must(t, err)
			must(t, f.a.Close())
			before = copyDataCensus(t, f)
			f.c.CopyRecoveryPreflight = nil
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
			if !reflect.DeepEqual(before, copyDataCensus(t, f)) {
				t.Fatal("persisted replay refusal mutated journal")
			}
		})
	}
}

func TestCopyDataRecoveryKnownIOAndPublicationFaultsStaySticky(t *testing.T) {
	for _, action := range []string{CopyOperationRollback, CopyOperationDirectoryTail} {
		for _, boundary := range []string{"copy-op-open", "copy-op-write", "copy-op-sync", "copy-op-close", "copy-op-publish", "copy-op-parent-sync", "data"} {
			for _, fault := range []error{unix.EIO, unix.ENOSPC} {
				t.Run(action+"/"+boundary+"/"+fault.Error(), func(t *testing.T) {
					f := newFixture(t, nil)
					_, _, g, i := copyDataFixture(t, f, CopySealed)
					f.a.j.fault = func(s string) error {
						if s == boundary {
							return fault
						}
						return nil
					}
					o, err := g.BeginCopyDataOperation(1, action, i.ID)
					if boundary == "data" {
						must(t, err)
						err = o.Complete(fault)
					}
					wantErr(t, err, ErrBlocked)
					f.a.j.fault = nil
					g.Release()
					must(t, f.a.Close())
					f.c.CopyRecoveryPreflight = copyDataPreflight
					before := copyDataCensus(t, f)
					_, err = f.openCurrent()
					wantErr(t, err, ErrRepairRequired)
					if !reflect.DeepEqual(before, copyDataCensus(t, f)) {
						t.Fatal("known failure recovery mutated journal")
					}
				})
			}
		}
	}
}

func TestCopyDataPublicationCrashWorker(t *testing.T) {
	path := os.Getenv("CENGINE_COPY_DATA_ROOT")
	if path == "" {
		return
	}
	f := newFixtureAt(t, nil, path)
	_, _, g, i := copyDataFixture(t, f, CopySealed)
	m := crashManifest{Current: f.signedCurrent(), Bootstrap: f.c.BootstrapKey, Before: *f.a.clone()}
	data, err := json.Marshal(m)
	must(t, err)
	writeCrashWitness(t, path, crashManifestName, data)
	f.a.j.afterStep = func(s string) {
		if s == os.Getenv("CENGINE_COPY_DATA_CUT") {
			os.Exit(crashExit)
		}
	}
	_, err = g.BeginCopyDataOperation(1, os.Getenv("CENGINE_COPY_DATA_ACTION"), i.ID)
	must(t, err)
	t.Fatal("cut not reached")
}

func TestCopyDataAtomicPublicationProcessCuts(t *testing.T) {
	for _, action := range []string{CopyOperationRollback, CopyOperationDirectoryTail} {
		for _, cut := range []string{"copy-op-open", "copy-op-write", "copy-op-sync", "copy-op-close", "copy-op-publish", "copy-op-parent-sync"} {
			t.Run(action+"/"+cut, func(t *testing.T) {
				path := t.TempDir()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyDataPublicationCrashWorker$", "-test.count=1")
				cmd.Env = append(os.Environ(), "CENGINE_COPY_DATA_ROOT="+path, "CENGINE_COPY_DATA_CUT="+cut, "CENGINE_COPY_DATA_ACTION="+action)
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
				published := cut == "copy-op-publish" || cut == "copy-op-parent-sync"
				_, err = os.Stat(filepath.Join(path, registryName, copyOperationName))
				if published {
					must(t, err)
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("partial final marker", err)
				}
				calls := 0
				c := Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { return nil }, CopyRecoveryPreflight: func(*os.File, string, string, CopyIntent) error { calls++; return nil }}
				open := func() (*Authority, error) {
					return OpenLifecycleExpected(c, m.Current, ExpectedLifecycleStartup{ExpectedStartup{m.Before.Store.ID, m.Before.Epoch, m.Before.Controller}, m.Before.Lifecycle.OpenRevision})
				}
				// An empty unpublished copy marker cannot prove its exact prestate.
				if cut == "copy-op-open" {
					lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
					return
				}
				a, err := open()
				must(t, err)
				defer a.Close()
				if (len(a.s.CopyReplay) == 1) != published || (calls == 1) != published {
					t.Fatal("temporary acquired replay authority")
				}
				for volume, i := range m.Before.Copy.Intents {
					if a.s.Copy.Intents[volume] != i {
						t.Fatal("publication cut changed intent")
					}
				}
			})
		}
	}
}

func TestCopyDataPublicationNeverOverwritesAndLegacyPartialRefuses(t *testing.T) {
	f := newFixture(t, nil)
	_, _, g, i := copyDataFixture(t, f, CopySealed)
	o, err := g.BeginCopyDataOperation(1, CopyOperationRollback, i.ID)
	must(t, err)
	path := filepath.Join(f.path, registryName, copyOperationName)
	before, err := os.ReadFile(path)
	must(t, err)
	wantErr(t, f.a.j.writeCopyOperation(o.token.record), ErrConflict)
	after, err := os.ReadFile(path)
	must(t, err)
	if string(before) != string(after) {
		t.Fatal("overwrote existing operation")
	}
	must(t, o.Complete(nil))
	g.Release()
	must(t, f.a.Close())
	must(t, os.WriteFile(path, []byte(`{"Version":1`), 0600))
	f.c.CopyRecoveryPreflight = copyDataPreflight
	_, err = f.openCurrent()
	wantErr(t, err, ErrRepairRequired)
}

func TestCopyDataCapacityFundedReplay(t *testing.T) {
	for _, tc := range []struct {
		action, phase string
		remaining     uint64
	}{
		// Include the two reserved lifecycle retirement revisions.
		{CopyOperationRollback, CopySealed, 7}, {CopyOperationDirectoryTail, CopyCleaning, 6}, {CopyOperationDirectoryTail, CopyCompleted, 5},
	} {
		t.Run(tc.action+"/"+tc.phase, func(t *testing.T) {
			f := newFixture(t, nil)
			v, b, g, i := copyDataFixture(t, f, tc.phase)
			f.a.s.Revision = ^uint64(0) - tc.remaining - 1
			_, err := g.BeginCopyDataOperation(1, tc.action, i.ID)
			wantErr(t, err, ErrLimit)
			if _, err = os.Stat(filepath.Join(f.path, registryName, copyOperationName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unfunded marker")
			}
			f.a.s.Revision = ^uint64(0) - tc.remaining - 6 // two operation revisions plus four ownership-transfer revisions
			// Model a live open at this high revision as well, so the exact
			// byte budget does not also fund an unrelated anchor-width jump.
			f.a.s.Lifecycle.OpenRevision = f.a.s.Revision
			limits := exactCapacity(t, f.a.s)
			f.a.limits.JournalBytes = limits.JournalBytes
			f.c.Limits = f.a.limits
			must(t, f.a.j.persist(f.a.s))
			_, err = g.BeginCopyDataOperation(1, tc.action, i.ID)
			must(t, err)
			f.c.CopyRecoveryPreflight = copyDataPreflight
			restartCopyOperation(t, f, g)
			if f.a.limits.JournalBytes != limits.JournalBytes {
				t.Fatal("reconstruction changed fixed-size reservation")
			}
			// Fresh successor attachments require their own byte budget, unlike
			// the already-funded replay clear. Keep the exact revision budget.
			f.a.limits.JournalBytes = DefaultLimits().JournalBytes
			g = copySuccessor(t, f, b)
			o := copyObligation(t, g, tc.action, i.ID)
			must(t, o.Complete(nil))
			if f.a.s.Revision != ^uint64(0)-tc.remaining || len(f.a.s.CopyReplay) != 0 {
				t.Fatal("replay consumed unfunded revision")
			}
			if f.a.s.Copy.Intents[v.ID].ID != i.ID {
				t.Fatal("changed fixed-size reservation")
			}
		})
	}
}
