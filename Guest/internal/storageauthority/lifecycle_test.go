package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func signLifecycle(t *testing.T, key ed25519.PrivateKey, g LifecycleGrant) SignedLifecycleGrant {
	t.Helper()
	b, err := LifecycleGrantSigningBytes(g)
	must(t, err)
	return SignedLifecycleGrant{g, ed25519.Sign(key, b)}
}

// Lifecycle fixtures provision directly through the signed constructor.
func newLifecycleFixture(t *testing.T) (*fixture, SignedLifecycleGrant) {
	t.Helper()
	f := newLifecycleWorkloadFixture(t, nil)
	return f, signLifecycle(t, f.bootstrap, f.a.s.Lifecycle.Latest.Grant)
}

func newLifecycleWorkloadFixture(t *testing.T, barrier Barrier) *fixture {
	t.Helper()
	return newFixture(t, barrier)
}

// Retain the trusted fixture's signed grant across close, never infer authority
// from the on-disk registry being tested or bypass the lifecycle admission path.
func (f *fixture) openCurrent() (*Authority, error) {
	return f.openExpected(expectedStartup(f))
}

func (f *fixture) signedCurrent() SignedLifecycleGrant {
	return signLifecycle(f.t, f.bootstrap, f.a.s.Lifecycle.Latest.Grant)
}
func (f *fixture) openExpected(expected ExpectedStartup) (*Authority, error) {
	return OpenLifecycleExpected(f.c, f.signedCurrent(), ExpectedLifecycleStartup{expected, f.a.s.Lifecycle.OpenRevision})
}
func (f *fixture) takeoverGrant(epoch uint64, key Fingerprint) LifecycleGrant {
	l := f.a.s.Lifecycle
	return LifecycleGrant{LifecycleTakeover, mustID(f.t), l.Identity, l.Latest.Grant.Serial + 1, epoch, key}
}

func lifecycleRetirement(t *testing.T, f *fixture) SignedLifecycleGrant {
	l := f.a.s.Lifecycle
	return signLifecycle(t, f.bootstrap, LifecycleGrant{LifecycleRetire, mustID(t), l.Identity, l.Latest.Grant.Serial + 1, f.a.s.Controller.Epoch, f.a.s.Controller.Key})
}

func lifecycleFiles(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(filepath.Join(f.path, registryName))
	must(t, err)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(f.path, registryName, e.Name()))
		must(t, err)
		out[e.Name()] = string(b)
	}
	return out
}

func TestLifecycleFreshBoundaryAndNoMutation(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	must(t, f.a.validate())
	if f.a.s.Schema != 4 || f.a.s.Controller.Epoch != 1 {
		t.Fatal("fresh registry has the wrong schema or controller epoch")
	}
	must(t, f.a.Close())
	before := lifecycleFiles(t, f)
	for _, call := range []func() (*Authority, error){

		func() (*Authority, error) { return InitializeLifecycle(f.c, initial) },
		func() (*Authority, error) {
			wrong := initial.Grant.Identity
			wrong.Generation++
			return OpenLifecycle(f.c, wrong)
		},
	} {
		if a, err := call(); err == nil {
			a.Close()
			t.Fatal("existing-store initialization or mismatched identity accepted")
		}
		if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
			t.Fatal("refusal mutated registry")
		}
	}
	var err error
	f.a, err = OpenLifecycle(f.c, initial.Grant.Identity)
	must(t, err)
	must(t, f.a.validate())
	wrongSchema := newFixture(t, nil)
	wrongSchema.a.s.Schema = SchemaVersion
	must(t, wrongSchema.a.j.persist(wrongSchema.a.s))
	must(t, wrongSchema.a.Close())
	before = lifecycleFiles(t, wrongSchema)
	_, err = OpenLifecycle(wrongSchema.c, initial.Grant.Identity)
	wantErr(t, err, ErrInvalid)
	if !reflect.DeepEqual(before, lifecycleFiles(t, wrongSchema)) {
		t.Fatal("schema rejection changed the registry")
	}
}

func expectedLifecycleStartup(f *fixture) ExpectedLifecycleStartup {
	return ExpectedLifecycleStartup{ExpectedStartup: expectedStartup(f), OpenRevision: f.a.s.Lifecycle.OpenRevision}
}

func TestLifecycleOpenCurrentAndExpectedAdmission(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	v := f.volume("admission")
	binding, _ := f.runtime(v, ReadWrite)
	beforeState := f.a.clone()
	expected := expectedLifecycleStartup(f)
	must(t, f.a.Close())
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	wrongGrant := initial.Grant
	wrongGrant.ID = mustID(t)
	wrong := signLifecycle(t, f.bootstrap, wrongGrant)
	for name, call := range map[string]func() (*Authority, error){
		"current-grant": func() (*Authority, error) { return OpenLifecycleCurrent(f.c, wrong) },
		"expected-grant": func() (*Authority, error) {
			return OpenLifecycleExpected(f.c, wrong, expected)
		},
		"predecessor": func() (*Authority, error) {
			stale := expected
			stale.Epoch = mustID(t)
			return OpenLifecycleExpected(f.c, initial, stale)
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := call()
			wantErr(t, err, ErrConflict)
			if got != nil {
				t.Fatal("rejected admission returned authority")
			}
			assertJournalContents(t, path, before)
		})
	}
	var err error
	f.a, err = OpenLifecycleExpected(f.c, initial, expected)
	must(t, err)
	beforeState.Epoch = f.a.Epoch()
	beforeState.Revision++
	beforeState.Lifecycle.OpenRevision = beforeState.Revision
	rec := beforeState.Attachments[binding.Attachment]
	rec.Phase = Retiring
	beforeState.Attachments[binding.Attachment] = rec
	if f.a.Epoch() == expected.Epoch || !reflect.DeepEqual(beforeState, f.a.s) {
		t.Fatal("startup changed more than E/revision/open_revision and ACTIVE fencing")
	}
	must(t, f.a.Close())
	before = journalContents(t, path)
	_, err = OpenLifecycleExpected(f.c, initial, expected)
	wantErr(t, err, ErrConflict)
	assertJournalContents(t, path, before)
}

func TestLifecycleOpenAdmissionBeforeJournal(t *testing.T) {
	f, initial := newLifecycleFixture(t) // held flock makes validation order observable
	expected := expectedLifecycleStartup(f)
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	bad := initial
	bad.Signature = make([]byte, ed25519.SignatureSize)
	_, err := OpenLifecycleCurrent(f.c, bad)
	wantErr(t, err, ErrUnauthorized)
	_, err = OpenLifecycleExpected(f.c, bad, expected)
	wantErr(t, err, ErrUnauthorized)
	for _, mutate := range []func(*ExpectedLifecycleStartup){
		func(e *ExpectedLifecycleStartup) { e.Store = "" },
		func(e *ExpectedLifecycleStartup) { e.Epoch = "" },
		func(e *ExpectedLifecycleStartup) { e.Controller.Epoch = 0 },
		func(e *ExpectedLifecycleStartup) { e.Controller.Key = "" },
		func(e *ExpectedLifecycleStartup) { e.OpenRevision = 0 },
	} {
		wrong := expected
		mutate(&wrong)
		_, err = OpenLifecycleExpected(f.c, initial, wrong)
		wantErr(t, err, ErrInvalid)
	}
	_, err = OpenLifecycleCurrent(f.c, initial)
	wantErr(t, err, ErrLocked)
	_, err = OpenLifecycleExpected(f.c, initial, expected)
	wantErr(t, err, ErrLocked)
	assertJournalContents(t, path, before)
}

func TestLifecycleOpenAdmissionNeverCleansRecoveryEvidence(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	expected := expectedLifecycleStartup(f)
	path := filepath.Join(f.path, registryName)
	raw, err := os.ReadFile(filepath.Join(path, stateName))
	must(t, err)
	// V1 accepts this landed-only certificate, but schema 4 requires a
	// nonempty predecessor: incomplete initialization is not workload recovery.
	proof := commitProof{commitProofVersion, expected.Store, expected.Epoch, f.a.s.Revision, "", contentDigest(raw), true}
	data, err := json.Marshal(proof)
	must(t, err)
	must(t, f.a.Close())
	must(t, os.WriteFile(filepath.Join(path, commitProofName), data, 0600))
	// Confirm this is a valid certificate, not merely invalid proof rejection.
	// Lifecycle admission rejects this incomplete-initialization proof before
	// cleanup; an exact grant must not override that independent fence.
	j, err := openJournal(f.c, false)
	must(t, err)
	loaded, err := j.loadCommitProof()
	j.close()
	must(t, err)
	if loaded == nil || *loaded != proof {
		t.Fatal("recovery fixture is not a valid landed-commit certificate")
	}
	before := journalContents(t, path)
	wrongGrant := initial.Grant
	wrongGrant.ID = mustID(t)
	wrong := signLifecycle(t, f.bootstrap, wrongGrant)
	stale := expected
	stale.Epoch = mustID(t)
	for i, call := range []func() (*Authority, error){
		func() (*Authority, error) { return OpenLifecycleCurrent(f.c, wrong) },
		func() (*Authority, error) { return OpenLifecycleExpected(f.c, initial, stale) },
		func() (*Authority, error) { return OpenLifecycleExpected(f.c, initial, expected) },
	} {
		got, err := call()
		want := ErrConflict // exact boot anchors are checked before recovery admission
		if i == 2 {
			want = ErrRepairRequired
		}
		wantErr(t, err, want)
		if got != nil {
			t.Fatal("uncertain open returned authority")
		}
		assertJournalContents(t, path, before)
	}
}

func TestLifecycleInitializeRejectsBeforeCreation(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	for _, kind := range []string{"signature", "root-alias", "operation", "zero-generation", "zero-serial", "zero-binding"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			must(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
			root, err := os.Open(path)
			must(t, err)
			defer root.Close()
			c := f.c
			c.Root = root
			g := initial.Grant
			switch kind {
			case "root-alias":
				g.NewKey = fp(t, f.bootstrap)
			case "operation":
				g.Operation, g.ExpectedEpoch = LifecycleTakeover, 1
			case "zero-generation":
				g.Identity.Generation = 0
			case "zero-serial":
				g.Serial = 0
			case "zero-binding":
				g.Identity.Binding = ""
			}
			signed := SignedLifecycleGrant{Grant: g, Signature: initial.Signature}
			if g.Validate() == nil {
				signed = signLifecycle(t, f.bootstrap, g)
			}
			if kind == "signature" {
				signed.Signature[0] ^= 1
			}
			if a, err := InitializeLifecycle(c, signed); err == nil {
				a.Close()
				t.Fatal("bad initialization")
			}
			if _, err := os.Stat(filepath.Join(path, registryName)); !os.IsNotExist(err) {
				t.Fatal("invalid grant created registry", err)
			}
		})
	}
}

func TestLifecycleTakeoverTLSReplayAndAliases(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	v := f.volume("alias")
	b, _ := f.runtime(v, ReadWrite)
	key := newKey(t)
	g := LifecycleGrant{LifecycleTakeover, mustID(t), initial.Grant.Identity, initial.Grant.Serial + 1, 1, fp(t, key)}
	signed := signLifecycle(t, f.bootstrap, g)
	p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	_, err = f.a.TakeoverLifecycle(&SuccessorPrincipal{}, signed)
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.TakeoverLifecycle(p, signLifecycle(t, f.controllerKey, g))
	wantErr(t, err, ErrUnauthorized)
	for _, alias := range []Fingerprint{f.a.s.Bootstrap, f.a.s.Controller.Key, b.Key} {
		bad := g
		bad.NewKey = alias
		// Internal test-only possession seam isolates alias authorization checks.
		_, err = f.a.TakeoverLifecycle(&SuccessorPrincipal{f.a, alias}, signLifecycle(t, f.bootstrap, bad))
		wantErr(t, err, ErrUnauthorized)
	}
	got, err := f.a.TakeoverLifecycle(p, signed)
	must(t, err)
	revision := f.a.s.Revision
	again, err := f.a.TakeoverLifecycle(p, signed)
	must(t, err)
	if got != again || f.a.s.Revision != revision {
		t.Fatal("exact retry mutated")
	}
	_, err = f.a.Query(f.control)
	wantErr(t, err, ErrUnauthorized)
	for _, mutate := range []func(*LifecycleGrant){
		func(g *LifecycleGrant) { g.Identity.Generation++ },
		func(g *LifecycleGrant) { g.Identity.Binding = fp(t, newKey(t)) },
		func(g *LifecycleGrant) { g.Serial-- },
		func(g *LifecycleGrant) { g.ExpectedEpoch-- },
		func(g *LifecycleGrant) { g.ID = mustID(t) },
	} {
		bad := g
		mutate(&bad)
		if bad.Validate() != nil {
			continue
		}
		_, err = f.a.TakeoverLifecycle(p, signLifecycle(t, f.bootstrap, bad))
		wantErr(t, err, ErrUnauthorized)
	}
	must(t, f.a.validate())
}

func TestLifecycleMoreThan4096DurableTakeoversBounded(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	// The unit-only internal principal seam skips 4100 TLS handshakes, NOT ROOT
	// signatures or real journal fsync/rename. This is not native qualification.
	f.a.limits.Operations = 1
	var first SignedLifecycleGrant
	var last SignedLifecycleGrant
	for i := 0; i < 4100; i++ {
		g := LifecycleGrant{LifecycleTakeover, mustID(t), initial.Grant.Identity, uint64(i) + 12, uint64(i) + 1, fp(t, newKey(t))}
		last = signLifecycle(t, f.bootstrap, g)
		if i == 0 {
			first = last
		}
		got, err := f.a.TakeoverLifecycle(&SuccessorPrincipal{f.a, g.NewKey}, last)
		must(t, err)
		if got.Epoch != uint64(i)+2 {
			t.Fatal("epoch")
		}
		if f.a.s.Grants != nil || f.a.s.ControllerKeys != nil || len(f.a.s.Operations) != 0 {
			t.Fatal("unbounded history")
		}
	}
	must(t, f.a.validate())
	files := lifecycleFiles(t, f)
	if len(files) != 2 || len(files[stateName]) > 2500 {
		t.Fatalf("unbounded journal: %d entries %d bytes", len(files), len(files[stateName]))
	}
	t.Logf("4100 completed takeovers: %d files, %d checkpoint bytes", len(files), len(files[stateName]))
	_, err := f.a.TakeoverLifecycle(&SuccessorPrincipal{f.a, first.Grant.NewKey}, first)
	wantErr(t, err, ErrUnauthorized)
	must(t, f.a.Close())
	f.a, err = OpenLifecycle(f.c, initial.Grant.Identity)
	must(t, err)
	revision := f.a.s.Revision
	_, err = f.a.TakeoverLifecycle(&SuccessorPrincipal{f.a, last.Grant.NewKey}, last)
	must(t, err)
	if f.a.s.Revision != revision {
		t.Fatal("lost reply retry mutated")
	}
}

func TestLifecycleRetirementReceiptsAndReadOnlyTLSResult(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	v := f.volume("data")
	b, p := f.runtime(v, ReadWrite)
	grant := lifecycleRetirement(t, f)
	before := lifecycleFiles(t, f)
	wantErr(t, f.a.RetireLifecycle(f.control, grant), ErrBusy)
	if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
		t.Fatal("busy refusal changed disk")
	}
	var calls int
	f.a.barrier = func(Binding, *os.File) error { calls++; return nil }
	f.retire(b)
	if calls != 1 {
		t.Fatal("missing original resource barrier")
	}
	must(t, f.a.RetireLifecycle(f.control, grant))
	if calls != 2 {
		t.Fatal("missing final resource barrier")
	}
	must(t, f.a.validate())
	_, err := f.a.Admit(p, v.ID, false)
	wantErr(t, err, ErrBlocked)
	_, err = f.a.Query(f.control)
	wantErr(t, err, ErrBlocked)
	wantErr(t, f.a.RetireLifecycle(f.control, grant), ErrBlocked)
	_, err = f.a.AuthenticateController(context.Background(), f.conn(f.controllerKey, tls.VersionTLS13, true), 1)
	wantErr(t, err, ErrBlocked)
	result, err := f.a.LifecycleResult(f.control, grant.Grant, bytes.Repeat([]byte{1}, 32))
	must(t, err)
	readOnly, err := f.a.AuthenticateLifecycleResult(context.Background(), f.conn(f.controllerKey, tls.VersionTLS13, true), 1)
	must(t, err)
	_, err = f.a.Query(readOnly)
	wantErr(t, err, ErrBlocked)
	for _, conn := range []*tls.Conn{nil, f.conn(newKey(t), tls.VersionTLS13, true), f.conn(f.controllerKey, tls.VersionTLS12, true), f.conn(f.controllerKey, tls.VersionTLS13, false)} {
		_, err = f.a.AuthenticateLifecycleResult(context.Background(), conn, 1)
		wantErr(t, err, ErrUnauthorized)
	}
	before = lifecycleFiles(t, f)
	again, err := f.a.LifecycleResult(readOnly, grant.Grant, bytes.Repeat([]byte{2}, 32))
	must(t, err)
	if result.ServiceEpoch != again.ServiceEpoch || result.Revision != again.Revision || result.Grant != again.Grant || bytes.Equal(result.Nonce, again.Nonce) {
		t.Fatal("seal result not stable/fresh")
	}
	if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
		t.Fatal("result replay mutated disk")
	}
	must(t, f.a.Close())
	for _, call := range []func() (*Authority, error){

		func() (*Authority, error) { return OpenLifecycle(f.c, initial.Grant.Identity) },
		func() (*Authority, error) { return InitializeLifecycle(f.c, initial) },
	} {
		if a, err := call(); err == nil {
			a.Close()
			t.Fatal("sealed reopen/init")
		}
	}
	if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
		t.Fatal("sealed refusal mutated disk")
	}
}

func TestLifecycleUncertaintyPreserved(t *testing.T) {
	for _, name := range []string{pendingName, quarantineName, barrierName, dataIOName, copyOperationName, commitProofName, "proof-stranded.tmp", "state-stranded.tmp", lifecycleFenceName} {
		t.Run(name, func(t *testing.T) {
			f, initial := newLifecycleFixture(t)
			must(t, os.WriteFile(filepath.Join(f.path, registryName, name), []byte("uncertain"), 0600))
			before := lifecycleFiles(t, f)
			if err := f.a.RetireLifecycle(f.control, lifecycleRetirement(t, f)); err == nil {
				t.Fatal("retired through uncertainty")
			}
			must(t, f.a.Close())
			if a, err := OpenLifecycle(f.c, initial.Grant.Identity); err == nil {
				a.Close()
				t.Fatal("reopened uncertainty")
			}
			if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
				t.Fatal("uncertainty evidence changed")
			}
		})
	}
}

func TestLifecycleRetirementPublishingFaultsNeverReopen(t *testing.T) {
	for _, phase := range []string{"intent", "seal"} {
		for _, boundary := range persistBoundaries {
			t.Run(phase+"/"+boundary, func(t *testing.T) {
				f, initial := newLifecycleFixture(t)
				grant := lifecycleRetirement(t, f)
				commits := 0
				fired := false
				f.a.j.fault = func(name string) error {
					if name == "state-read-prior" {
						commits++
					}
					wanted := 1
					if phase == "seal" {
						wanted = 2
					}
					if commits == wanted && name == boundary && !fired {
						fired = true
						return unix.EIO
					}
					return nil
				}
				wantErr(t, f.a.RetireLifecycle(f.control, grant), ErrBlocked)
				if !fired {
					t.Fatal("fault not reached")
				}
				_, err := f.a.LifecycleResult(f.control, grant.Grant, make([]byte, 32))
				wantErr(t, err, ErrBlocked)
				f.a.j.fault = nil
				must(t, f.a.Close())
				before := lifecycleFiles(t, f)
				if a, err := OpenLifecycle(f.c, initial.Grant.Identity); err == nil {
					a.Close()
					t.Fatal("uncertain publication reopened")
				}
				if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
					t.Fatal("fault evidence changed")
				}
			})
		}
	}
	for _, boundary := range []string{"marker-open", "marker-write", "marker-sync", "marker-close", "marker-parent-sync", "lifecycle-exports-sync", "lifecycle-root-sync", "lifecycle-registry-sync"} {
		t.Run(boundary, func(t *testing.T) {
			f, initial := newLifecycleFixture(t)
			f.a.j.fault = func(name string) error {
				if name == boundary {
					return unix.ENOSPC
				}
				return nil
			}
			wantErr(t, f.a.RetireLifecycle(f.control, lifecycleRetirement(t, f)), ErrBlocked)
			f.a.j.fault = nil
			must(t, f.a.Close())
			if a, err := OpenLifecycle(f.c, initial.Grant.Identity); err == nil {
				a.Close()
				t.Fatal("barrier fault reopened")
			}
		})
	}
}

func TestLifecycleStrictCountersAndVersion(t *testing.T) {
	for name, mutate := range map[string]func(*diskState){
		"version":    func(s *diskState) { s.Lifecycle.Version = "" },
		"generation": func(s *diskState) { s.Lifecycle.Identity.Generation = 0 },
		"serial":     func(s *diskState) { s.Lifecycle.Latest.Grant.Serial = 0 },
		"epoch":      func(s *diskState) { s.Controller.Epoch = 0 },
		"history":    func(s *diskState) { s.ControllerKeys = &struct{}{} },
		"schema":     func(s *diskState) { s.Schema = SchemaVersion },
	} {
		t.Run(name, func(t *testing.T) {
			f, initial := newLifecycleFixture(t)
			must(t, f.a.Close())
			mutate(f.a.s)
			raw, err := json.Marshal(f.a.s)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), raw, 0600))
			before := lifecycleFiles(t, f)
			if a, err := OpenLifecycle(f.c, initial.Grant.Identity); err == nil {
				a.Close()
				t.Fatal(fmt.Sprintf("invalid %s defaulted", name))
			}
			if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
				t.Fatal("invalid state changed")
			}
		})
	}
}

func TestLifecycleRetirementOutstandingState(t *testing.T) {
	for _, kind := range []string{"prepare", "data-io", "copy-io", "inflight", "drains", "count", "resource-error"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := newLifecycleFixture(t)
			if kind == "prepare" {
				v := f.volume("pending")
				id := mustID(t)
				b, _ := f.binding(v, PrepareRole, ReadWrite, id)
				must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), id, []Binding{b}}))
				f.retire(b) // durable Drained is insufficient while P remains unresolved
			}
			switch kind {
			case "data-io":
				f.a.dataIO = &durabilityToken{}
			case "copy-io":
				f.a.copyIO = &copyOperationToken{}
			case "inflight":
				f.a.inflight = 1
			case "drains":
				f.a.drains = 1
			case "count":
				rt := newRuntime()
				rt.count = 1
				f.a.runtime[mustID(t)] = rt
			case "resource-error":
				rt := newRuntime()
				rt.err = unix.EIO
				f.a.runtime[mustID(t)] = rt
			}
			before := lifecycleFiles(t, f)
			if err := f.a.RetireLifecycle(f.control, lifecycleRetirement(t, f)); err == nil {
				t.Fatal("outstanding state sealed")
			}
			if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
				t.Fatal("refusal changed evidence")
			}
			if f.a.s.Lifecycle.Retiring != nil {
				t.Fatal("premature fence")
			}
			f.a.inflight, f.a.drains = 0, 0 // test-only synthetic accounting, no real owner
		})
	}
}

func TestLifecycleRetirementAfterDeletedVolume(t *testing.T) {
	f, _ := newLifecycleFixture(t)
	v := f.volume("deleted")
	b, _ := f.runtime(v, ReadWrite)
	f.retire(b)
	_, err := f.a.DeleteVolume(f.control, DeleteVolumeRequest{mustID(t), f.a.s.Store.ID, v.ID})
	must(t, err)
	f.a.barrier = func(Binding, *os.File) error { t.Fatal("barrier given deleted root"); return ErrInvalid }
	must(t, f.a.RetireLifecycle(f.control, lifecycleRetirement(t, f)))
}

type lifecycleCrashInput struct {
	Root      string
	Bootstrap []byte
	Identity  LifecycleIdentity
	Grant     SignedLifecycleGrant
	Phase     string
	Boundary  string
}

// Actual process exit after real durability IO: no defers or poison can create
// refusal artifacts on behalf of the interrupted implementation.
func TestLifecycleAbruptRetirementHelper(t *testing.T) {
	raw := os.Getenv("CENGINE_LIFECYCLE_CRASH")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	var input lifecycleCrashInput
	must(t, json.Unmarshal([]byte(raw), &input))
	root, err := os.Open(input.Root)
	must(t, err)
	a, err := OpenLifecycle(Config{Root: root, DeviceID: "test-device-uuid", BootstrapKey: ed25519.PublicKey(input.Bootstrap), Barrier: func(Binding, *os.File) error { return nil }}, input.Identity)
	must(t, err)
	commits := 0
	a.j.afterStep = func(name string) {
		if name == "state-read-prior" {
			commits++
		}
		wanted := 1
		if input.Phase == "seal" {
			wanted = 2
		}
		if commits == wanted && name == input.Boundary {
			os.Exit(91)
		}
	}
	must(t, a.RetireLifecycle(&ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}, input.Grant))
	t.Fatal("crash edge not reached")
}

func TestLifecycleAbruptRetirementNeverReopens(t *testing.T) {
	for _, phase := range []string{"intent", "seal"} {
		for _, boundary := range persistBoundaries {
			t.Run(phase+"/"+boundary, func(t *testing.T) {
				f, initial := newLifecycleFixture(t)
				input := lifecycleCrashInput{f.path, []byte(f.c.BootstrapKey), initial.Grant.Identity, lifecycleRetirement(t, f), phase, boundary}
				must(t, f.a.Close())
				raw, err := json.Marshal(input)
				must(t, err)
				cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleAbruptRetirementHelper$")
				cmd.Env = append(os.Environ(), "CENGINE_LIFECYCLE_CRASH="+string(raw))
				out, err := cmd.CombinedOutput()
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 91 {
					t.Fatalf("not abrupt exit: %v %s", err, out)
				}
				before := lifecycleFiles(t, f)
				if _, ok := before[quarantineName]; ok {
					t.Fatal("crash unexpectedly poisoned")
				}
				if a, err := OpenLifecycle(f.c, initial.Grant.Identity); err == nil {
					a.Close()
					t.Fatal("interrupted retirement reopened")
				}
				if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
					t.Fatal("crash refusal modified evidence")
				}
			})
		}
	}
}

func TestLifecycleTakeoverCapacityDoesNotMutateLatest(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	for _, kind := range []string{"bytes", "revision"} {
		t.Run(kind, func(t *testing.T) {
			limits, revision := f.a.limits, f.a.s.Revision
			if kind == "bytes" {
				f.a.limits.JournalBytes = 1
			} else {
				f.a.s.Revision = ^uint64(0) - 2
			}
			before, err := json.Marshal(f.a.s)
			must(t, err)
			g := LifecycleGrant{LifecycleTakeover, mustID(t), initial.Grant.Identity, 12, 1, fp(t, newKey(t))}
			_, err = f.a.TakeoverLifecycle(&SuccessorPrincipal{f.a, g.NewKey}, signLifecycle(t, f.bootstrap, g))
			wantErr(t, err, ErrLimit)
			after, err := json.Marshal(f.a.s)
			must(t, err)
			if !bytes.Equal(before, after) || f.a.fault != nil {
				t.Fatal("clean capacity refusal mutated or poisoned")
			}
			f.a.limits, f.a.s.Revision = limits, revision
		})
	}
	must(t, f.a.validate())
}
