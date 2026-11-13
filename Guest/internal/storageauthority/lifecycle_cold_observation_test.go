package storageauthority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signObservation(t *testing.T, key ed25519.PrivateKey, r LifecycleColdObservationRequest) SignedLifecycleColdObservation {
	t.Helper()
	b, err := LifecycleColdObservationSigningBytes(r)
	must(t, err)
	return SignedLifecycleColdObservation{r, ed25519.Sign(key, b)}
}
func observationRequest(t *testing.T, old SignedLifecycleColdOpen) LifecycleColdObservationRequest {
	t.Helper()
	raw, err := json.Marshal(old)
	must(t, err)
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	must(t, dec.Decode(&tree))
	raw, err = json.Marshal(tree)
	must(t, err)
	l := old.Request.Launch
	l.ShimLaunchUUID = mustID(t)
	return LifecycleColdObservationRequest{mustID(t), raw, l}
}
func observedRecovery(t *testing.T, f *fixture, old SignedLifecycleColdOpen, auth SignedLifecycleColdObservation, o LifecycleColdObservation) SignedLifecycleColdOpen {
	t.Helper()
	r := old.Request
	r.Predecessor = o.Predecessor
	r.Launch = auth.Request.Observer
	r.Observation = &auth
	g := r.Takeover.Grant
	g.ID = mustID(t)
	g.Serial++
	g.ExpectedEpoch = o.Predecessor.ControllerEpoch
	g.NewKey = fp(t, newKey(t))
	r.OperationID = g.ID
	r.Takeover = signLifecycle(t, f.bootstrap, g)
	return signCold(t, f.bootstrap, r)
}
func TestLifecycleColdObservationOutcomesAndRecovery(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "applied"}[applied], func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			r := coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t)))
			old := signCold(t, f.bootstrap, r)
			must(t, f.a.Close())
			var err error
			if applied {
				f.a, err = ColdOpenAndTakeover(f.c, old)
				must(t, err)
				must(t, f.a.Close())
			}
			auth := signObservation(t, f.bootstrap, observationRequest(t, old))
			path := filepath.Join(f.path, registryName)
			before := journalContents(t, path)
			c := f.c
			c.Barrier = func(Binding, *os.File) error { t.Fatal("observation barrier"); return ErrInvalid }
			o, err := ObserveLifecycleColdReadOnly(c, auth)
			must(t, err)
			must(t, o.ValidateFor(auth.Request))
			assertJournalContents(t, path, before)
			if (o.Outcome == "applied") != applied {
				t.Fatal(o)
			}
			fresh := observedRecovery(t, f, old, auth, o)
			f.a, err = ColdOpenAndTakeover(f.c, fresh)
			must(t, err)
			if f.a.s.Controller.Epoch != o.Predecessor.ControllerEpoch+1 || f.a.s.Controller.Key == r.Takeover.Grant.NewKey {
				t.Fatal("old request replayed")
			}
		})
	}
}
func TestLifecycleColdObservationRejectsEveryArtifactWithoutMutation(t *testing.T) {
	for _, name := range []string{pendingName, barrierName, quarantineName, dataIOName, commitProofName, copyOperationName, "unknown", "state-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.tmp", "proof-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.tmp", "prepare-retire-proof-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.tmp", "copy-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		t.Run(name, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			old := signCold(t, f.bootstrap, coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t))))
			auth := signObservation(t, f.bootstrap, observationRequest(t, old))
			must(t, f.a.Close())
			o, err := ObserveLifecycleColdReadOnly(f.c, auth)
			must(t, err)
			fresh := observedRecovery(t, f, old, auth, o)
			path := filepath.Join(f.path, registryName)
			must(t, os.WriteFile(filepath.Join(path, name), []byte("evidence"), 0600))
			before := journalContents(t, path)
			if _, err := ObserveLifecycleColdReadOnly(f.c, auth); err == nil {
				t.Fatal("artifact admitted")
			}
			assertJournalContents(t, path, before)
			if _, err := ColdOpenAndTakeover(f.c, fresh); err == nil {
				t.Fatal("observed takeover admitted artifact")
			}
			assertJournalContents(t, path, before)
		})
	}
}
func TestLifecycleColdObservationSignatureAndBindings(t *testing.T) {
	f, current := newLifecycleFixture(t)
	old := signCold(t, f.bootstrap, coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t))))
	r := observationRequest(t, old)
	auth := signObservation(t, f.bootstrap, r)
	b, err := LifecycleColdObservationSigningBytes(r)
	must(t, err)
	if !strings.HasPrefix(string(b), "cengine.storageauthority.lifecycle-cold-observe.v1\x00{\"observation_id\":") {
		t.Fatal("signing domain/order")
	}
	for name, mutate := range map[string]func(*SignedLifecycleColdObservation){
		"signature": func(s *SignedLifecycleColdObservation) { s.Signature[0] ^= 1 },
		"subject-signature": func(s *SignedLifecycleColdObservation) {
			v, _ := s.Request.SubjectOpen()
			v.Signature[0] ^= 1
			s.Request = observationRequest(t, v)
			*s = signObservation(t, f.bootstrap, s.Request)
		},
		"takeover-signature": func(s *SignedLifecycleColdObservation) {
			v, _ := s.Request.SubjectOpen()
			v.Request.Takeover.Signature[0] ^= 1
			v = signCold(t, f.bootstrap, v.Request)
			s.Request = observationRequest(t, v)
			*s = signObservation(t, f.bootstrap, s.Request)
		},
		"launch": func(s *SignedLifecycleColdObservation) {
			s.Request.Observer.ShimLaunchUUID = old.Request.Launch.ShimLaunchUUID
		},
		"disk": func(s *SignedLifecycleColdObservation) {
			s.Request.Observer.Ext4UUID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		},
		"bytes":        func(s *SignedLifecycleColdObservation) { s.Request.Observer.Bytes++ },
		"size":         func(s *SignedLifecycleColdObservation) { s.Request.Subject = make([]byte, 65537) },
		"id":           func(s *SignedLifecycleColdObservation) { s.Request.ObservationID = old.Request.OperationID },
		"noncanonical": func(s *SignedLifecycleColdObservation) { s.Request.Subject = append(s.Request.Subject, ' ') },
	} {
		t.Run(name, func(t *testing.T) {
			bad := auth.Clone()
			mutate(&bad)
			if _, err := ObserveLifecycleColdReadOnly(f.c, bad); err == nil || err == ErrLocked {
				t.Fatalf("signature-first: %v", err)
			}
		})
	}
	_, err = ObserveLifecycleColdReadOnly(f.c, auth)
	wantErr(t, err, ErrLocked)
	must(t, f.a.Close())
	o, err := ObserveLifecycleColdReadOnly(f.c, auth)
	must(t, err)
	for _, change := range []func(*LifecycleColdObservation){func(o *LifecycleColdObservation) { o.RequestSHA256 = strings.Repeat("f", 64) }, func(o *LifecycleColdObservation) { o.Predecessor.ControllerEpoch++ }, func(o *LifecycleColdObservation) { o.Outcome = "applied" }} {
		bad := o
		change(&bad)
		if bad.ValidateFor(r) == nil {
			t.Fatal("bad observation accepted")
		}
	}
	fresh := observedRecovery(t, f, old, auth, o)
	for _, change := range []func(*LifecycleColdOpenRequest){func(r *LifecycleColdOpenRequest) { r.Takeover.Grant.Serial = old.Request.Takeover.Grant.Serial }, func(r *LifecycleColdOpenRequest) { r.Takeover.Grant.NewKey = old.Request.Takeover.Grant.NewKey }, func(r *LifecycleColdOpenRequest) {
		r.OperationID = old.Request.OperationID
		r.Takeover.Grant.ID = r.OperationID
	}, func(r *LifecycleColdOpenRequest) { r.Predecessor.ServiceEpoch = mustID(t) }} {
		bad := fresh.Request
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("abandoned grant/bad projection accepted")
		}
	}
}
func TestLifecycleColdObservationRevalidatesUnderAdmissionFlock(t *testing.T) {
	f, current := newLifecycleFixture(t)
	old := signCold(t, f.bootstrap, coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t))))
	auth := signObservation(t, f.bootstrap, observationRequest(t, old))
	must(t, f.a.Close())
	o, err := ObserveLifecycleColdReadOnly(f.c, auth)
	must(t, err)
	fresh := observedRecovery(t, f, old, auth, o)
	// Advance the real disk after the read probe, before the constructor's flock.
	f.a, err = ColdOpenAndTakeover(f.c, old)
	must(t, err)
	must(t, f.a.Close())
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	_, err = ColdOpenAndTakeover(f.c, fresh)
	wantErr(t, err, ErrConflict)
	assertJournalContents(t, path, before)
	// Also exercise admission directly with an actual held flock and poison census.
	c, err := configured(f.c)
	must(t, err)
	j, err := openJournal(c, false)
	must(t, err)
	defer j.close()
	state, err := j.load()
	must(t, err)
	a := &Authority{s: state, j: j, limits: f.a.limits}
	must(t, os.WriteFile(filepath.Join(path, "unknown"), []byte("inert"), 0600))
	before = journalContents(t, path)
	if err = a.admitColdOpen(fresh.Request); err == nil {
		t.Fatal("same-flock guard missing")
	}
	assertJournalContents(t, path, before)
}

func TestLifecycleColdObservationMismatchedAppliedStateAndDevice(t *testing.T) {
	for _, kind := range []string{"digest", "grant", "epoch", "revision", "advanced-open", "advanced-state", "device", "root", "store", "bootstrap", "retiring"} {
		t.Run(kind, func(t *testing.T) {
			f, current := newLifecycleFixture(t)
			old := signCold(t, f.bootstrap, coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t))))
			auth := signObservation(t, f.bootstrap, observationRequest(t, old))
			must(t, f.a.Close())
			var err error
			f.a, err = ColdOpenAndTakeover(f.c, old)
			must(t, err)
			s := f.a.s
			switch kind {
			case "digest":
				s.Lifecycle.ColdApplied.RequestSHA256 = strings.Repeat("f", 64)
			case "grant":
				s.Lifecycle.ColdApplied.GrantID = mustID(t)
			case "epoch":
				s.Lifecycle.ColdApplied.ServiceEpoch = mustID(t)
			case "revision":
				s.Lifecycle.ColdApplied.OpenRevision++
			case "advanced-open":
				s.Revision++
				s.Epoch = mustID(t)
				s.Lifecycle.OpenRevision = s.Revision
			case "advanced-state":
				s.Revision++
			case "device":
				s.Store.DeviceID = "different-device"
			case "root":
				s.Store.Root.Inode++
			case "store":
				s.Store.ID = mustID(t)
			case "bootstrap":
				s.Bootstrap = fp(t, newKey(t))
			case "retiring":
				g := lifecycleRetirement(t, f).Grant
				s.Lifecycle.Retiring = &g
			}
			raw, err := json.Marshal(s)
			must(t, err)
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName)
			must(t, os.WriteFile(filepath.Join(path, stateName), raw, 0600))
			before := journalContents(t, path)
			if _, err = ObserveLifecycleColdReadOnly(f.c, auth); err == nil {
				t.Fatal("mismatch admitted")
			}
			assertJournalContents(t, path, before)
		})
	}
}
func TestLifecycleColdObservationRejectsNestedSubject(t *testing.T) {
	f, current := newLifecycleFixture(t)
	old := signCold(t, f.bootstrap, coldRequest(t, f, current, expectedLifecycleStartup(f), fp(t, newKey(t))))
	r := observationRequest(t, old)
	var wire map[string]any
	must(t, json.Unmarshal(r.Subject, &wire))
	wire["request"].(map[string]any)["observation"] = nil
	r.Subject, _ = json.Marshal(wire)
	if r.Validate() == nil {
		t.Fatal("nested/null observation admitted")
	}
}
