package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func coldRequest(t *testing.T, f *fixture, current SignedLifecycleGrant, expected ExpectedLifecycleStartup, key Fingerprint) LifecycleColdOpenRequest {
	t.Helper()
	g := LifecycleGrant{LifecycleTakeover, mustID(t), current.Grant.Identity, current.Grant.Serial + 1, expected.Controller.Epoch, key}
	return LifecycleColdOpenRequest{g.ID,
		LifecycleColdPredecessor{current.Grant, expected.Epoch, expected.Controller.Epoch, expected.Controller.Key, expected.OpenRevision, fp(t, f.bootstrap)},
		signLifecycle(t, f.bootstrap, g),
		LifecycleColdLaunch{mustID(t), strings.Repeat("a", 64), strings.Repeat("b", 64), "cccccccc-cccc-1ccc-accc-cccccccccccc", 1 << 30},
		1700000000, 3600}
}

func signCold(t *testing.T, key ed25519.PrivateKey, r LifecycleColdOpenRequest) SignedLifecycleColdOpen {
	t.Helper()
	b, err := LifecycleColdOpenSigningBytes(r)
	must(t, err)
	return SignedLifecycleColdOpen{r, ed25519.Sign(key, b)}
}

func TestLifecycleColdWireAndBothSignatures(t *testing.T) {
	f, current := newLifecycleFixture(t)
	r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
	s := signCold(t, f.bootstrap, r)
	must(t, VerifyLifecycleColdOpen(f.c.BootstrapKey, s))
	b, err := LifecycleColdOpenSigningBytes(r)
	must(t, err)
	wire, err := json.Marshal(r)
	must(t, err)
	if !bytes.Equal(b, append([]byte("cengine.storageauthority.lifecycle-cold-open.v1\x00"), wire...)) || !strings.HasPrefix(string(wire), `{"operation_id":`) {
		t.Fatal("wrong signing domain or request order")
	}
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	for _, kind := range []string{"outer", "inner", "root", "pin"} {
		t.Run(kind, func(t *testing.T) {
			candidate := s
			switch kind {
			case "outer":
				candidate.Signature = make([]byte, 64)
			case "inner":
				candidate.Request.Takeover.Signature = make([]byte, 64)
				candidate = signCold(t, f.bootstrap, candidate.Request)
			case "root":
				candidate = signCold(t, newKey(t), r)
			case "pin":
				candidate.Request.Predecessor.BootstrapKey = fp(t, newKey(t))
				candidate = signCold(t, f.bootstrap, candidate.Request)
			}
			_, err := ColdOpenAndTakeover(f.c, candidate)
			wantErr(t, err, ErrUnauthorized) // signatures precede the held flock
			assertJournalContents(t, path, before)
		})
	}
	_, err = ColdOpenAndTakeover(f.c, s)
	wantErr(t, err, ErrLocked)
}

func TestLifecycleColdValidation(t *testing.T) {
	f, current := newLifecycleFixture(t)
	r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
	for name, mutate := range map[string]func(*LifecycleColdOpenRequest){
		"operation":      func(r *LifecycleColdOpenRequest) { r.OperationID = mustID(t) },
		"service":        func(r *LifecycleColdOpenRequest) { r.Predecessor.ServiceEpoch = "bad" },
		"controller":     func(r *LifecycleColdOpenRequest) { r.Predecessor.ControllerEpoch++ },
		"controller-key": func(r *LifecycleColdOpenRequest) { r.Predecessor.ControllerKey = fp(t, newKey(t)) },
		"open":           func(r *LifecycleColdOpenRequest) { r.Predecessor.OpenRevision = 0 },
		"serial":         func(r *LifecycleColdOpenRequest) { r.Takeover.Grant.Serial = r.Predecessor.CurrentGrant.Serial },
		"expected":       func(r *LifecycleColdOpenRequest) { r.Takeover.Grant.ExpectedEpoch++ },
		"same-id": func(r *LifecycleColdOpenRequest) {
			r.OperationID = r.Predecessor.CurrentGrant.ID
			r.Takeover.Grant.ID = r.OperationID
		},
		"same-key":          func(r *LifecycleColdOpenRequest) { r.Takeover.Grant.NewKey = r.Predecessor.ControllerKey },
		"bootstrap":         func(r *LifecycleColdOpenRequest) { r.Takeover.Grant.NewKey = r.Predecessor.BootstrapKey },
		"launch":            func(r *LifecycleColdOpenRequest) { r.Launch.ShimLaunchUUID = "bad" },
		"spec":              func(r *LifecycleColdOpenRequest) { r.Launch.SpecSHA256 = strings.Repeat("A", 64) },
		"initramfs":         func(r *LifecycleColdOpenRequest) { r.Launch.InitramfsSHA256 = "a" },
		"ext4":              func(r *LifecycleColdOpenRequest) { r.Launch.Ext4UUID = "00000000-0000-0000-0000-000000000000" },
		"bytes-zero":        func(r *LifecycleColdOpenRequest) { r.Launch.Bytes = 0 },
		"bytes-overflow":    func(r *LifecycleColdOpenRequest) { r.Launch.Bytes = 1 << 63 },
		"time-zero":         func(r *LifecycleColdOpenRequest) { r.NowUnixSeconds = 0 },
		"time-overflow":     func(r *LifecycleColdOpenRequest) { r.NowUnixSeconds = 253402300800 },
		"expiry-overflow":   func(r *LifecycleColdOpenRequest) { r.NowUnixSeconds = 253402300799 },
		"lifetime-zero":     func(r *LifecycleColdOpenRequest) { r.LifetimeSeconds = 0 },
		"lifetime-overflow": func(r *LifecycleColdOpenRequest) { r.LifetimeSeconds = 86401 },
		"inner-size":        func(r *LifecycleColdOpenRequest) { r.Takeover.Signature = nil },
	} {
		t.Run(name, func(t *testing.T) { bad := r; mutate(&bad); wantErr(t, bad.Validate(), ErrInvalid) })
	}
	r.NowUnixSeconds, r.LifetimeSeconds, r.Launch.Bytes = 253402300798, 1, 1<<63-1
	must(t, r.Validate())
	wantErr(t, (SignedLifecycleColdOpen{Request: r}).Validate(), ErrInvalid)
}

func TestLifecycleColdAtomicReplayAndPrepareContexts(t *testing.T) {
	f, current := newLifecycleFixture(t)
	prep := lifecycleReserve(t, f, "cold-prepare")
	key := newKey(t)
	r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, key))
	signed := signCold(t, f.bootstrap, r)
	beforeState := f.a.clone()
	must(t, f.a.Close())
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	for name, mutate := range map[string]func(*LifecycleColdOpenRequest){
		"epoch": func(r *LifecycleColdOpenRequest) { r.Predecessor.ServiceEpoch = mustID(t) },
		"open":  func(r *LifecycleColdOpenRequest) { r.Predecessor.OpenRevision++ },
		"grant": func(r *LifecycleColdOpenRequest) { r.Predecessor.CurrentGrant.ID = mustID(t) },
		"controller": func(r *LifecycleColdOpenRequest) {
			r.Predecessor.CurrentGrant.NewKey = fp(t, newKey(t))
			r.Predecessor.ControllerKey = r.Predecessor.CurrentGrant.NewKey
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			_, err := ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, bad))
			wantErr(t, err, ErrConflict)
			assertJournalContents(t, path, before)
		})
	}
	a, err := ColdOpenAndTakeover(f.c, signed)
	must(t, err)
	f.a = a
	if a.s.Epoch == beforeState.Epoch || a.s.Revision != beforeState.Revision+1 || a.s.Controller != (Controller{2, fp(t, key)}) || a.s.Lifecycle.Latest != (lifecycleApplied{r.Takeover.Grant, a.s.Epoch, a.s.Revision}) || a.s.Lifecycle.OpenRevision != a.s.Revision {
		t.Fatal("cold startup was not one atomic E/C/receipt/open commit")
	}
	if !reflect.DeepEqual(a.s.Prepares[prep], beforeState.Prepares[prep]) {
		t.Fatal("cold open rewrote historical prepare")
	}
	for _, rec := range a.s.Attachments {
		if rec.Phase != Retiring {
			t.Fatal("startup failed to fence attachment")
		}
	}
	must(t, a.validate())
	marker := *a.s.Lifecycle.ColdApplied
	must(t, a.Close())
	before = journalContents(t, path)
	got, err := ColdOpenAndTakeover(f.c, signed)
	wantErr(t, err, ErrLifecycleColdAlreadyApplied)
	if got != nil {
		t.Fatal("replay returned authority")
	}
	assertJournalContents(t, path, before)
	f.a, err = OpenLifecycleCurrent(f.c, r.Takeover)
	must(t, err)
	if *f.a.s.Lifecycle.ColdApplied != marker {
		t.Fatal("same-C open dropped marker")
	}
	must(t, f.a.Close())
	before = journalContents(t, path)
	_, err = ColdOpenAndTakeover(f.c, signed)
	wantErr(t, err, ErrLifecycleColdAlreadyApplied)
	assertJournalContents(t, path, before)
	f.a, err = OpenLifecycleCurrent(f.c, r.Takeover)
	must(t, err)
	nextKey := newKey(t)
	g := LifecycleGrant{LifecycleTakeover, mustID(t), r.Takeover.Grant.Identity, r.Takeover.Grant.Serial + 1, 2, fp(t, nextKey)}
	p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(nextKey, tls.VersionTLS13, true))
	must(t, err)
	_, err = f.a.TakeoverLifecycle(p, signLifecycle(t, f.bootstrap, g))
	must(t, err)
	if f.a.s.Lifecycle.ColdApplied != nil {
		t.Fatal("ordinary takeover retained marker")
	}
}

// ROOT resolves a completed dead C2 only as history. Guest receives a brand new
// signed C2->C3 open, never the original C1->C2 envelope or C2 private key.
func TestLifecycleColdDeadPredecessorFreshKeyChainPreservesPreparedState(t *testing.T) {
	f, current := newLifecycleFixture(t)
	prep := lifecycleReserve(t, f, "dead-cold-prepare")
	original := f.a.clone()
	first := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
	must(t, f.a.Close())
	a, err := ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, first))
	must(t, err)
	f.a = a
	dead := a.clone()
	second := coldRequest(t, f, first.Takeover, expectedLifecycleStartup(f), fp(t, newKey(t)))
	must(t, a.Close())
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	_, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, first))
	wantErr(t, err, ErrLifecycleColdAlreadyApplied)
	assertJournalContents(t, path, before)
	bad := second
	bad.Predecessor.ServiceEpoch = original.Epoch
	_, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, bad))
	wantErr(t, err, ErrConflict)
	assertJournalContents(t, path, before)
	bad = second
	bad.Predecessor.CurrentGrant = current.Grant
	bad.Predecessor.ControllerEpoch = original.Controller.Epoch
	bad.Predecessor.ControllerKey = original.Controller.Key
	bad.Predecessor.OpenRevision = original.Lifecycle.OpenRevision
	bad.Predecessor.ServiceEpoch = original.Epoch
	bad.Takeover.Grant.ExpectedEpoch = original.Controller.Epoch
	bad.Takeover = signLifecycle(t, f.bootstrap, bad.Takeover.Grant)
	_, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, bad))
	wantErr(t, err, ErrConflict)
	assertJournalContents(t, path, before)
	f.a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, second))
	must(t, err)
	if f.a.s.Controller.Epoch != 3 || f.a.s.Controller.Key != second.Takeover.Grant.NewKey ||
		f.a.s.Controller.Key == dead.Controller.Key || f.a.s.Epoch == dead.Epoch ||
		f.a.s.Revision != dead.Revision+1 {
		t.Fatal("recovery did not apply one fresh C2->C3 E/key commit")
	}
	if !reflect.DeepEqual(f.a.s.Prepares[prep], original.Prepares[prep]) {
		t.Fatal("recovery rewrote original prepared state")
	}
	must(t, f.a.validate())
}

// Drive the real journal writer in a subprocess; the cut occurs while publishing
// the same startup state shape as ColdOpenAndTakeover, without a production hook.
func TestLifecycleColdCrashHelper(t *testing.T) {
	raw := os.Getenv("CENGINE_COLD_CRASH")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	var input struct {
		Root, Boundary string
		Bootstrap      []byte
		Request        LifecycleColdOpenRequest
	}
	must(t, json.Unmarshal([]byte(raw), &input))
	root, err := os.Open(input.Root)
	must(t, err)
	c, err := configured(Config{Root: root, DeviceID: "test-device-uuid", BootstrapKey: input.Bootstrap, Barrier: func(Binding, *os.File) error { return nil }})
	must(t, err)
	j, err := openJournal(c, false)
	must(t, err)
	state, err := j.load()
	must(t, err)
	a := &Authority{s: state, j: j, limits: c.Limits}
	next := a.clone()
	next.Epoch = mustID(t)
	g := input.Request.Takeover.Grant
	next.Controller = Controller{g.ExpectedEpoch + 1, g.NewKey}
	next.Lifecycle.OpenRevision = state.Revision + 1
	next.Lifecycle.Latest = lifecycleApplied{g, next.Epoch, state.Revision + 1}
	next.Lifecycle.ColdApplied = &lifecycleColdApplied{coldRequestDigest(input.Request), g.ID, next.Epoch, state.Revision + 1}
	j.afterStep = func(name string) {
		if name == input.Boundary {
			os.Exit(91)
		}
	}
	err = a.commit(next)
	t.Fatalf("cold cut not reached: %v", err)
}

func TestLifecycleColdInterruptedCommitRefusesRecovery(t *testing.T) {
	for _, boundary := range []string{"proof-parent-sync", "state-write", "proof-ready-close", "proof-ready-parent-sync", "state-rename", "state-parent-sync"} {
		t.Run(boundary, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
			signed := signCold(t, f.bootstrap, r)
			must(t, f.a.Close())
			input := struct {
				Root, Boundary string
				Bootstrap      []byte
				Request        LifecycleColdOpenRequest
			}{f.path, boundary, f.c.BootstrapKey, r}
			cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleColdCrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "CENGINE_COLD_CRASH="+string(retirementJSON(t, input)), "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 91 {
				t.Fatalf("not abrupt exit: %v %s", err, out)
			}
			path := filepath.Join(f.path, registryName)
			before := retirementJournalCensus(t, path)
			_, err = ColdOpenAndTakeover(f.c, signed)
			wantErr(t, err, ErrRepairRequired)
			assertRetirementJournalCensus(t, path, before)
			raw, err := os.ReadFile(filepath.Join(path, stateName))
			must(t, err)
			var visible diskState
			must(t, json.Unmarshal(raw, &visible))
			grant := signLifecycle(t, f.bootstrap, visible.Lifecycle.Latest.Grant)
			expected := ExpectedLifecycleStartup{ExpectedStartup{visible.Store.ID, visible.Epoch, visible.Controller}, visible.Lifecycle.OpenRevision}
			_, err = OpenLifecycleExpected(f.c, grant, expected)
			wantErr(t, err, ErrRepairRequired)
			assertRetirementJournalCensus(t, path, before)
		})
	}
}

func TestLifecycleColdMarkerValidation(t *testing.T) {
	f, current := newLifecycleFixture(t)
	r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
	must(t, f.a.Close())
	a, err := ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
	must(t, err)
	f.a = a
	good := *a.s.Lifecycle.ColdApplied
	for name, mutate := range map[string]func(*lifecycleColdApplied){
		"digest":   func(m *lifecycleColdApplied) { m.RequestSHA256 = "bad" },
		"grant":    func(m *lifecycleColdApplied) { m.GrantID = mustID(t) },
		"epoch":    func(m *lifecycleColdApplied) { m.ServiceEpoch = mustID(t) },
		"revision": func(m *lifecycleColdApplied) { m.OpenRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			mutate(&bad)
			a.s.Lifecycle.ColdApplied = &bad
			wantErr(t, a.validate(), ErrInvalid)
		})
	}
	a.s.Lifecycle.ColdApplied = &good
	must(t, a.validate())
}

func TestLifecycleColdKeyReuseAndRecovery(t *testing.T) {
	for _, boundary := range []string{"state-write", "proof-ready-close", "state-parent-sync"} {
		t.Run(boundary, func(t *testing.T) {
			f, current, expected, binding := lifecycleRecoveryCrash(t, "checkpoint", boundary)
			r := coldRequest(t, f, current, expected, binding.Key)
			path := filepath.Join(f.path, registryName)
			before := retirementJournalCensus(t, path)
			_, err := ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
			wantErr(t, err, ErrUnauthorized)
			assertRetirementJournalCensus(t, path, before)
			r.Takeover.Grant.NewKey = fp(t, newKey(t))
			r.Takeover = signLifecycle(t, f.bootstrap, r.Takeover.Grant)
			bad := r
			bad.Predecessor.OpenRevision++
			_, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, bad))
			wantErr(t, err, ErrConflict)
			assertRetirementJournalCensus(t, path, before)
			raw, err := os.ReadFile(filepath.Join(path, stateName))
			must(t, err)
			var old diskState
			must(t, json.Unmarshal(raw, &old))
			f.a, err = ColdOpenAndTakeover(f.c, signCold(t, f.bootstrap, r))
			must(t, err)
			if f.a.s.Revision != old.Revision+1 || !reflect.DeepEqual(f.a.s.Prepares, old.Prepares) {
				t.Fatal("recovery changed prepare contexts or added commits")
			}
			if len(lifecycleFiles(t, f)) != 2 {
				t.Fatal("workload recovery artifacts retained")
			}
		})
	}
}
