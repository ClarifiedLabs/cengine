//go:build linux || darwin

package storageauthority

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// These are authority unit seams: copyDataFixture supplies synthetic ext4
// identities, not proof of native manifest validation or physical undo.
func lifecycleCopyMarker(t *testing.T, f *fixture, action, phase string) (Volume, Binding, *Guard, copyOperationRecord) {
	t.Helper()
	var v Volume
	var b Binding
	var g *Guard
	var i CopyIntent
	if phase == "" {
		v = f.volume("copy-recovery")
		b, g = copyPrepare(t, f, v, ReadWrite)
	} else {
		v, b, g, i = copyDataFixture(t, f, phase)
	}
	var o *CopyOperationObligation
	var err error
	if copyDataAction(action) {
		o, err = g.BeginCopyDataOperation(37, action, i.ID)
	} else {
		id := i.ID
		if action == CopyOperationBegin {
			id = ""
		}
		o, err = g.BeginCopyOperation(37, action, id)
	}
	must(t, err)
	return v, b, g, o.token.record
}

func closeLifecycleCopyCrash(t *testing.T, f *fixture, g *Guard) {
	t.Helper()
	// Like restartCopyOperation: model abrupt process teardown, not an orderly
	// abandoned request (Release would correctly quarantine that case). Keep
	// the genuinely published operation file; discard only the volatile token.
	f.a.copyIO = nil
	g.Release()
	must(t, f.a.Close())
}

func assertLifecycleCopyRecovered(t *testing.T, f *fixture, before *diskState, b Binding, replay copyOperationRecord) {
	t.Helper()
	if f.a.s.Epoch == before.Epoch || f.a.s.Revision != before.Revision+1 {
		t.Fatal("recovery did not publish exactly one fresh service epoch")
	}
	p := f.a.s.Prepares[b.Prepare]
	at := f.a.s.Attachments[b.Attachment]
	if p.Phase != Pending || p.Attestation != nil || !reflect.DeepEqual(p, before.Prepares[b.Prepare]) ||
		at.Phase != Retiring || at.Receipt != nil || at.Retirement != "" {
		t.Fatal("recovery completed PREPARE, rewrote its context, or invented a drain receipt")
	}
	if !reflect.DeepEqual(f.a.s.Copy, before.Copy) || !reflect.DeepEqual(f.a.s.CopyReplay[b.Volume], replay) {
		t.Fatal("recovery changed copy intent or lost the exact replay")
	}
	if replay.Version != 2 {
		t.Fatal("lifecycle obligation lacks its context-bound version")
	}
	if f.a.s.ControllerKeys != nil {
		t.Fatal("lifecycle recovery introduced legacy controller-key history")
	}
	must(t, f.a.validate())
	files := lifecycleFiles(t, f)
	if len(files) != 2 || files[copyOperationName] != "" {
		t.Fatal("recovery retained operation marker or extra artifacts")
	}
	var persisted diskState
	must(t, json.Unmarshal([]byte(files[stateName]), &persisted))
	if !reflect.DeepEqual(persisted.CopyReplay[b.Volume], replay) {
		t.Fatal("marker removed without persisting replay")
	}
}

func TestLifecycleCopyRecoveryPublishedMarker(t *testing.T) {
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
				v, b, g, replay := lifecycleCopyMarker(t, f, tc.action, tc.phase)
				before := f.a.clone()
				expected := expectedLifecycleStartup(f)
				key := newKey(t)
				r := coldRequest(t, f, current, expected, fp(t, key))
				closeLifecycleCopyCrash(t, f, g)
				path := filepath.Join(f.path, registryName)
				census := retirementJournalCensus(t, path)
				calls := 0
				barrier := f.c.Barrier
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("startup drained attachment"); return nil }
				f.c.CopyRecoveryPreflight = func(root *os.File, device, action string, intent CopyIntent) error {
					calls++
					assertRetirementJournalCensus(t, path, census)
					got, err := identity(root)
					must(t, err)
					if got != v.Root || device != before.Store.DeviceID || action != tc.action || intent != before.Copy.Intents[v.ID] {
						t.Fatal("preflight lost root/device/action/intent correlation")
					}
					return nil
				}
				var a *Authority
				var err error
				if cold {
					a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
					current = r.Takeover
					f.controllerKey = key
				} else {
					a, err = OpenLifecycleExpected(f.c, current, expected)
				}
				must(t, err)
				f.a = a
				assertLifecycleCopyRecovered(t, f, before, b, replay)
				wantController := before.Controller
				if cold {
					wantController = Controller{before.Controller.Epoch + 1, fp(t, key)}
				}
				if f.a.s.Controller != wantController {
					t.Fatal("wrong controller after recovery")
				}
				// A clean second startup must accept the historical owning PREPARE
				// context, even after a cold controller change, with no marker left.
				before = f.a.clone()
				expected = expectedLifecycleStartup(f)
				must(t, f.a.Close())
				census = retirementJournalCensus(t, path)
				a, err = OpenLifecycleExpected(f.c, current, expected)
				must(t, err)
				f.a = a
				assertLifecycleCopyRecovered(t, f, before, b, replay)
				wantCalls := 0
				if copyDataAction(tc.action) {
					wantCalls = 2
				}
				if calls != wantCalls {
					t.Fatalf("preflight calls = %d, want %d", calls, wantCalls)
				}
				if copyDataAction(tc.action) {
					if !f.a.copyReplayPending(v.ID) || f.a.copyFences[v.ID] == nil {
						t.Fatal("recovered DATA obligation lost its fence")
					}
					f.c.Barrier, f.a.barrier = barrier, barrier
					f.control = f.authControl(f.controllerKey, f.a.s.Controller.Epoch)
					g = copySuccessor(t, f, b)
					pending, err := g.PendingCopyOperation(replay.Intent)
					must(t, err)
					if pending != tc.action {
						t.Fatal("drained successor lost exact pending action")
					}
					wantErr(t, g.CheckCopyReplay(), ErrBlocked)
					must(t, f.a.validate())
					op, err := g.BeginCopyOperation(39, tc.action, replay.Intent)
					must(t, err)
					must(t, op.Complete(nil)) // unit server completion seam, not physical undo
					must(t, g.CheckCopyReplay())
					if len(f.a.s.CopyReplay) != 0 {
						t.Fatal("successful exact replay did not clear the obligation")
					}
					must(t, f.a.validate())
					g.Release()
				}
			})
		}
	}
}

func TestLifecycleCopyRecoveryRefusesWithoutMutation(t *testing.T) {
	for _, cold := range []bool{false, true} {
		mode := "expected"
		if cold {
			mode = "cold"
		}
		for _, kind := range []string{
			"legacy-version", "malformed", "noncanonical", "unknown-field", "wrong-action", "wrong-root", "wrong-device",
			"mode", "hardlink", "symlink", "directory", "fifo", "oversize",
			"metadata-unbound", "state-temp", "proof-temp", "copy-temp", "barrier", "uncertain",
			"missing-preflight", "failing-preflight", "unrelated-root", "grant", "epoch", "controller", "open-revision",
		} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				f, current := newLifecycleFixture(t)
				// Validate an unrelated retained root as well as the copy owner.
				f.volume("unrelated")
				_, _, g, replay := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
				expected := expectedLifecycleStartup(f)
				r := coldRequest(t, f, current, expected, fp(t, newKey(t)))
				if kind == "metadata-unbound" {
					// A real metadata pair cannot authorize an unbound copy record.
					replay.Root.Inode++
					must(t, os.WriteFile(filepath.Join(f.path, registryName, copyOperationName), retirementJSON(t, replay), 0600))
					func() {
						defer func() {
							if recover() != "copy-metadata-cut" {
								t.Fatal("missing metadata cut")
							}
						}()
						f.a.j.afterStep = func(step string) {
							if step == "state-sync" {
								panic("copy-metadata-cut")
							}
						}
						next := f.a.clone()
						next.Revision++
						must(t, f.a.j.persist(next))
					}()
					f.a.j.afterStep = nil
				}
				closeLifecycleCopyCrash(t, f, g)
				path := filepath.Join(f.path, registryName)
				marker := filepath.Join(path, copyOperationName)
				switch kind {
				case "legacy-version":
					replay.Version = 1
					must(t, os.WriteFile(marker, retirementJSON(t, replay), 0600))
				case "malformed":
					must(t, os.WriteFile(marker, []byte("{"), 0600))
				case "noncanonical":
					must(t, os.WriteFile(marker, append(retirementJSON(t, replay), '\n'), 0600))
				case "unknown-field":
					raw := retirementJSON(t, replay)
					must(t, os.WriteFile(marker, append([]byte(`{"unknown":1,`), raw[1:]...), 0600))
				case "wrong-action":
					replay.Action = "ordinary-data"
					must(t, os.WriteFile(marker, retirementJSON(t, replay), 0600))
				case "wrong-root":
					replay.Root.Inode++
					must(t, os.WriteFile(marker, retirementJSON(t, replay), 0600))
				case "wrong-device":
					f.c.DeviceID += "-foreign"
				case "mode":
					must(t, os.Chmod(marker, 0644))
				case "hardlink":
					must(t, os.Link(marker, filepath.Join(t.TempDir(), "alias")))
				case "symlink", "directory", "fifo":
					must(t, os.Remove(marker))
					if kind == "symlink" {
						target := filepath.Join(t.TempDir(), "marker")
						must(t, os.WriteFile(target, retirementJSON(t, replay), 0600))
						must(t, os.Symlink(target, marker))
					} else if kind == "directory" {
						must(t, os.Mkdir(marker, 0700))
					} else {
						must(t, unix.Mkfifo(marker, 0600))
					}
				case "oversize":
					must(t, os.WriteFile(marker, make([]byte, maxCopyOperationBytes+1), 0600))
				case "state-temp", "proof-temp", "copy-temp":
					prefix := map[string]string{"state-temp": "state-", "proof-temp": "proof-", "copy-temp": "copy-op-"}[kind]
					must(t, os.WriteFile(filepath.Join(path, prefix+string(mustID(t))+".tmp"), []byte("evidence"), 0600))
				case "barrier", "uncertain":
					name := pendingName
					if kind == "barrier" {
						name = barrierName
					}
					must(t, os.WriteFile(filepath.Join(path, name), []byte(uncertainMarkerText), 0600))
				case "unrelated-root":
					root := filepath.Join(f.path, "volumes", "unrelated")
					must(t, os.Rename(root, root+"-hidden"))
				case "grant":
					current.Grant.ID = mustID(t)
					current = signLifecycle(t, f.bootstrap, current.Grant)
					r.Predecessor.CurrentGrant = current.Grant
				case "epoch":
					expected.Epoch = mustID(t)
					r.Predecessor.ServiceEpoch = expected.Epoch
				case "controller":
					expected.Controller.Key = fp(t, newKey(t))
					r.Predecessor.ControllerKey = expected.Controller.Key
					r.Predecessor.CurrentGrant.NewKey = expected.Controller.Key
				case "open-revision":
					expected.OpenRevision++
					r.Predecessor.OpenRevision = expected.OpenRevision
				}
				before := retirementJournalCensus(t, path)
				calls := 0
				f.c.Barrier = func(Binding, *os.File) error { t.Fatal("refusal invoked barrier"); return nil }
				if kind != "missing-preflight" {
					f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
						calls++
						assertRetirementJournalCensus(t, path, before)
						if kind != "failing-preflight" {
							t.Fatal("preflight preceded complete root/anchor/artifact validation")
						}
						return ErrConflict
					}
				}
				var a *Authority
				var err error
				if cold {
					a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
				} else {
					a, err = OpenLifecycleExpected(f.c, current, expected)
				}
				if a != nil {
					a.Close()
					t.Fatal("refusal returned an authority")
				}
				if err == nil {
					t.Fatal("accepted invalid recovery evidence")
				}
				if kind == "missing-preflight" || kind == "failing-preflight" {
					wantErr(t, err, ErrRepairRequired)
				}
				wantCalls := 0
				if kind == "failing-preflight" {
					wantCalls = 1
				}
				if calls != wantCalls {
					t.Fatalf("preflight calls = %d, want %d", calls, wantCalls)
				}
				assertRetirementJournalCensus(t, path, before)
			})
		}
	}
}

// A surviving DATA owner does not become the new daemon's PREPARE. Its durable
// copy obligation must retain the original bounded context after live takeover.
func TestLifecycleCopyRecoveryAfterLiveTakeover(t *testing.T) {
	f, current := newLifecycleFixture(t)
	v, b, g, intent := copyDataFixture(t, f, CopySealed)
	origin := *f.a.s.Prepares[b.Prepare].Context
	key := newKey(t)
	grant := LifecycleGrant{LifecycleTakeover, mustID(t), current.Grant.Identity, current.Grant.Serial + 1, 1, fp(t, key)}
	p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	current = signLifecycle(t, f.bootstrap, grant)
	_, err = f.a.TakeoverLifecycle(p, current)
	must(t, err)
	o, err := g.BeginCopyDataOperation(38, CopyOperationRollback, intent.ID)
	must(t, err)
	replay := o.token.record
	if replay.Controller != (Controller{origin.ControllerEpoch, origin.ControllerKey}) || replay.Epoch != origin.ServiceEpoch {
		t.Fatal("live takeover rewrote copy owner context")
	}
	before := f.a.clone()
	r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
	closeLifecycleCopyCrash(t, f, g)
	f.c.CopyRecoveryPreflight = copyDataPreflight
	f.a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
	must(t, err)
	assertLifecycleCopyRecovered(t, f, before, b, replay)
	if f.a.s.Controller.Epoch != 3 || !f.a.copyReplayPending(v.ID) {
		t.Fatal("cold recovery lost the original DATA obligation")
	}
}

func TestLifecycleCopyRecoveryRequiresBothAnchors(t *testing.T) {
	f, current := newLifecycleFixture(t)
	_, _, g, _ := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
	closeLifecycleCopyCrash(t, f, g)
	path := filepath.Join(f.path, registryName)
	before := retirementJournalCensus(t, path)
	f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error { t.Fatal("unanchored preflight"); return nil }
	for _, open := range []func() (*Authority, error){
		func() (*Authority, error) { return OpenLifecycle(f.c, current.Grant.Identity) },
		func() (*Authority, error) { return OpenLifecycleCurrent(f.c, current) },
	} {
		a, err := open()
		if a != nil {
			a.Close()
			t.Fatal("unanchored recovery returned authority")
		}
		wantErr(t, err, ErrRepairRequired)
		assertRetirementJournalCensus(t, path, before)
	}
}

func TestLifecycleCopyRecoveryPersistedReplayContext(t *testing.T) {
	for _, field := range []string{"legacy-version", "epoch", "controller-epoch", "controller-key", "missing-preflight", "failing-preflight"} {
		t.Run(field, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			v, _, g, _ := lifecycleCopyMarker(t, f, CopyOperationRollback, CopySealed)
			r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
			closeLifecycleCopyCrash(t, f, g)
			f.c.CopyRecoveryPreflight = copyDataPreflight
			a, err := ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
			must(t, err)
			f.a = a
			expected := expectedLifecycleStartup(f)
			state := f.a.clone()
			must(t, f.a.Close())
			replay := state.CopyReplay[v.ID]
			switch field {
			case "legacy-version":
				replay.Version = 1
			case "epoch":
				// Keep matcher inputs coherent: only the owning PREPARE.Context
				// can reject this forged, otherwise self-consistent old epoch.
				replay.Epoch = mustID(t)
				replay.Before.Epoch = replay.Epoch
				intent := state.Copy.Intents[v.ID]
				intent.Epoch = replay.Epoch
				state.Copy.Intents[v.ID] = intent
			case "controller-epoch":
				replay.Controller.Epoch = state.Controller.Epoch
			case "controller-key":
				replay.Controller.Key = state.Controller.Key
			}
			if field != "missing-preflight" && field != "failing-preflight" {
				state.CopyReplay[v.ID] = replay
				must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), retirementJSON(t, state), 0600))
			}
			path := filepath.Join(f.path, registryName)
			before := retirementJournalCensus(t, path)
			calls := 0
			f.c.CopyRecoveryPreflight = nil
			if field != "missing-preflight" {
				f.c.CopyRecoveryPreflight = func(*os.File, string, string, CopyIntent) error {
					calls++
					assertRetirementJournalCensus(t, path, before)
					if field != "failing-preflight" {
						t.Fatal("preflight accepted mismatched owning PREPARE context")
					}
					return ErrConflict
				}
			}
			a, err = OpenLifecycleExpected(f.c, r.Takeover, expected)
			if a != nil {
				a.Close()
				t.Fatal("invalid persisted replay returned authority")
			}
			if err == nil {
				t.Fatal("accepted invalid persisted replay")
			}
			wantCalls := 0
			if field == "failing-preflight" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("preflight calls = %d, want %d", calls, wantCalls)
			}
			assertRetirementJournalCensus(t, path, before)
		})
	}
}
