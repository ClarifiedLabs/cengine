package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const lifecycleResumeVectorPath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-resume-open-v1.json"

// The frozen signed vector pins the declaration order, the distinct signing
// domain, the unsigned original grant, and both ROOT signatures for the
// matching Swift/Go wire implementations.
func TestLifecycleResumeWireVector(t *testing.T) {
	raw, err := os.ReadFile(lifecycleResumeVectorPath)
	must(t, err)
	var vector struct {
		RootSeed             string          `json:"root_seed"`
		RootPublicKey        string          `json:"root_public_key"`
		Request              json.RawMessage `json:"request"`
		SigningBytes         string          `json:"signing_bytes"`
		TakeoverSigningBytes string          `json:"takeover_signing_bytes"`
		RequestSHA256        string          `json:"request_sha256"`
		Signature            string          `json:"signature"`
	}
	must(t, json.Unmarshal(raw, &vector))
	seed, err := base64.StdEncoding.DecodeString(vector.RootSeed)
	must(t, err)
	root := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(root) != vector.RootPublicKey {
		t.Fatal("root seed/public key mismatch")
	}
	var signed SignedLifecycleResumeOpen
	must(t, json.Unmarshal(vector.Request, &signed.Request))
	// The fixture carries the outer signature beside the request, not inside it.
	sig, err := base64.StdEncoding.DecodeString(vector.Signature)
	must(t, err)
	signed.Signature = sig
	must(t, signed.Validate())
	if signed.Request.Original.Operation != LifecycleInitialize || signed.Request.Original.ExpectedEpoch != 0 ||
		signed.Request.Takeover.Grant.Operation != LifecycleTakeover || signed.Request.Takeover.Grant.ExpectedEpoch != 1 {
		t.Fatal("vector operations are not original initialize + expected-one takeover")
	}
	must(t, VerifyLifecycleResumeOpen(root, signed))
	b, err := LifecycleResumeOpenSigningBytes(signed.Request)
	must(t, err)
	if base64.StdEncoding.EncodeToString(b) != vector.SigningBytes {
		t.Fatal("signing bytes drifted from fixture")
	}
	if !bytes.HasPrefix(b, []byte("cengine.storageauthority.lifecycle-resume-open.v1\x00")) {
		t.Fatal("wrong signing domain")
	}
	tb, err := LifecycleGrantSigningBytes(signed.Request.Takeover.Grant)
	must(t, err)
	if base64.StdEncoding.EncodeToString(tb) != vector.TakeoverSigningBytes {
		t.Fatal("takeover grant signing bytes drifted from fixture")
	}
	sum := sha256Sum(b)
	if hex.EncodeToString(sum) != vector.RequestSHA256 {
		t.Fatal("request digest drifted from fixture")
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func resumeRequest(t *testing.T, bootstrap ed25519.PrivateKey, original LifecycleGrant, key Fingerprint) LifecycleResumeOpenRequest {
	t.Helper()
	g := LifecycleGrant{LifecycleTakeover, mustID(t), original.Identity, original.Serial + 1, 1, key}
	return LifecycleResumeOpenRequest{g.ID, original,
		signLifecycle(t, bootstrap, g),
		LifecycleColdLaunch{mustID(t), strings.Repeat("a", 64), strings.Repeat("b", 64), "cccccccc-cccc-1ccc-accc-cccccccccccc", 1 << 30},
		1700000000, 3600}
}

func signResume(t *testing.T, key ed25519.PrivateKey, r LifecycleResumeOpenRequest) SignedLifecycleResumeOpen {
	t.Helper()
	b, err := LifecycleResumeOpenSigningBytes(r)
	must(t, err)
	return SignedLifecycleResumeOpen{r, ed25519.Sign(key, b)}
}

// newResumeLayoutFixture provisions a closed empty-layout root. volumes and
// lost+found are both optional format artifacts; fresh format can fail before
// either exists.
func newResumeLayoutFixture(t *testing.T, volumes, lostFound bool) *fixture {
	t.Helper()
	f := newFixture(t, nil)
	must(t, f.a.Close())
	f.path = t.TempDir()
	if volumes {
		must(t, os.Mkdir(filepath.Join(f.path, "volumes"), 0700))
	}
	if lostFound {
		must(t, os.Mkdir(filepath.Join(f.path, "lost+found"), 0700))
	}
	root, err := os.Open(f.path)
	must(t, err)
	t.Cleanup(func() { root.Close() })
	f.c.Root = root
	return f
}

func newResumeEmptyFixture(t *testing.T) *fixture {
	t.Helper()
	return newResumeLayoutFixture(t, true, true)
}

func resumeGenesisFixture(t *testing.T) (*fixture, LifecycleGrant) {
	t.Helper()
	f, initial := newLifecycleFixture(t)
	return f, initial.Grant
}

func TestLifecycleResumeWireAndBothSignatures(t *testing.T) {
	f := newResumeEmptyFixture(t)
	original := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, newKey(t))}
	r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
	s := signResume(t, f.bootstrap, r)
	must(t, VerifyLifecycleResumeOpen(f.c.BootstrapKey, s))
	b, err := LifecycleResumeOpenSigningBytes(r)
	must(t, err)
	wire, err := json.Marshal(r)
	must(t, err)
	if !bytes.Equal(b, append([]byte("cengine.storageauthority.lifecycle-resume-open.v1\x00"), wire...)) || !strings.HasPrefix(string(wire), `{"operation_id":`) {
		t.Fatal("wrong signing domain or request order")
	}
	rootBefore := rootCensus(t, f.path)
	for _, kind := range []string{"outer", "inner", "root", "root-key"} {
		t.Run(kind, func(t *testing.T) {
			candidate := s
			switch kind {
			case "outer":
				candidate.Signature = make([]byte, 64)
			case "inner":
				candidate.Request.Takeover.Signature = make([]byte, 64)
				candidate = signResume(t, f.bootstrap, candidate.Request)
			case "root":
				candidate = signResume(t, newKey(t), r)
			case "root-key":
				candidate.Request.Takeover.Grant.NewKey = fp(t, f.bootstrap)
				candidate = signResume(t, f.bootstrap, candidate.Request)
			}
			_, err := ResumeOpenAndTakeover(f.c, candidate)
			wantErr(t, err, ErrUnauthorized) // signatures precede the held flock
			if !reflect.DeepEqual(rootBefore, rootCensus(t, f.path)) {
				t.Fatal("refusal mutated the closed empty layout")
			}
		})
	}
}

func TestLifecycleResumeValidation(t *testing.T) {
	f := newResumeEmptyFixture(t)
	original := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, newKey(t))}
	r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
	for name, mutate := range map[string]func(*LifecycleResumeOpenRequest){
		"operation":    func(r *LifecycleResumeOpenRequest) { r.OperationID = mustID(t) },
		"original-op":  func(r *LifecycleResumeOpenRequest) { r.Original.Operation = LifecycleTakeover },
		"original-exp": func(r *LifecycleResumeOpenRequest) { r.Original.ExpectedEpoch = 1 },
		"identity":     func(r *LifecycleResumeOpenRequest) { r.Original.Identity.Generation++ },
		"serial":       func(r *LifecycleResumeOpenRequest) { r.Takeover.Grant.Serial = r.Original.Serial },
		"expected":     func(r *LifecycleResumeOpenRequest) { r.Takeover.Grant.ExpectedEpoch = 2 },
		"same-id": func(r *LifecycleResumeOpenRequest) {
			r.OperationID = r.Original.ID
			r.Takeover.Grant.ID = r.OperationID
		},
		"same-key":        func(r *LifecycleResumeOpenRequest) { r.Takeover.Grant.NewKey = r.Original.NewKey },
		"launch":          func(r *LifecycleResumeOpenRequest) { r.Launch.ShimLaunchUUID = "bad" },
		"bytes-zero":      func(r *LifecycleResumeOpenRequest) { r.Launch.Bytes = 0 },
		"time-zero":       func(r *LifecycleResumeOpenRequest) { r.NowUnixSeconds = 0 },
		"lifetime-zero":   func(r *LifecycleResumeOpenRequest) { r.LifetimeSeconds = 0 },
		"expiry-overflow": func(r *LifecycleResumeOpenRequest) { r.NowUnixSeconds = 253402300799 },
		"inner-size":      func(r *LifecycleResumeOpenRequest) { r.Takeover.Signature = nil },
	} {
		t.Run(name, func(t *testing.T) { bad := r; mutate(&bad); wantErr(t, bad.Validate(), ErrInvalid) })
	}
	r.NowUnixSeconds, r.LifetimeSeconds, r.Launch.Bytes = 253402300798, 1, 1<<63-1
	must(t, r.Validate())
	wantErr(t, (SignedLifecycleResumeOpen{Request: r}).Validate(), ErrInvalid)
	// The request carries no bootstrap fingerprint, so the root-alias rule is a
	// verification-time pin check, not part of structural validation.
	rootAlias := r
	rootAlias.Takeover.Grant.NewKey = fp(t, f.bootstrap)
	must(t, rootAlias.Validate())
	wantErr(t, VerifyLifecycleResumeOpen(f.c.BootstrapKey, signResume(t, f.bootstrap, rootAlias)), ErrUnauthorized)
}

func TestLifecycleResumeEmptyLayoutOneCommitSuccessor(t *testing.T) {
	f := newResumeEmptyFixture(t)
	original := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, newKey(t))}
	key := newKey(t)
	r := resumeRequest(t, f.bootstrap, original, fp(t, key))
	signed := signResume(t, f.bootstrap, r)
	a, err := ResumeOpenAndTakeover(f.c, signed)
	must(t, err)
	f.a = a
	// ONE journal save: the successor lands directly at revision 1 with
	// controller epoch 2. The synthetic genesis and the old original key were
	// never persisted.
	if a.s.Revision != 1 || a.s.Lifecycle.OpenRevision != 1 || a.s.Controller != (Controller{2, fp(t, key)}) ||
		a.s.Lifecycle.Latest != (lifecycleApplied{r.Takeover.Grant, a.s.Epoch, 1}) {
		t.Fatal("resume did not publish exactly one successor at revision 1")
	}
	marker := *a.s.Lifecycle.ResumeApplied
	want := lifecycleResumeApplied{resumeRequestDigest(r), r.Takeover.Grant.ID, a.s.Epoch, 1}
	if marker != want {
		t.Fatal("resume marker mismatch", marker, want)
	}
	if a.s.Lifecycle.ColdApplied != nil || a.s.Lifecycle.Retiring != nil || a.s.Lifecycle.Seal != nil {
		t.Fatal("unexpected retirement/cold state")
	}
	must(t, a.validate())
	if files := lifecycleFiles(t, f); len(files) != 2 {
		t.Fatal("resume left extra namespace entries", len(files))
	}
	// The durable bytes themselves prove the single publication: state.json is
	// the revision-1 successor, with no epoch-1 original-key genesis behind it.
	raw, err := os.ReadFile(filepath.Join(f.path, registryName, stateName))
	must(t, err)
	var durable diskState
	must(t, json.Unmarshal(raw, &durable))
	if durable.Revision != 1 || durable.Controller != (Controller{2, fp(t, key)}) {
		t.Fatal("durable state is not the single revision-1 successor")
	}
	must(t, a.Close())
	// Replay of the applied resume refuses with every byte preserved.
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	got, err := ResumeOpenAndTakeover(f.c, signed)
	wantErr(t, err, ErrLifecycleResumeAlreadyApplied)
	if got != nil {
		t.Fatal("replay returned authority")
	}
	assertJournalContents(t, path, before)
	// Crash-cut leftovers (a surviving commit proof) also refuse, and the retry
	// performs NO cleanup: the proof and every byte stay untouched.
	must(t, os.WriteFile(filepath.Join(path, commitProofName), []byte("uncertain"), 0600))
	before = journalContents(t, path)
	_, err = ResumeOpenAndTakeover(f.c, signed)
	wantErr(t, err, ErrRepairRequired)
	assertJournalContents(t, path, before)
}

func TestLifecycleResumeEmptyOptionalArtifactsAndNoVolumes(t *testing.T) {
	for name, fixture := range map[string]func(*testing.T) *fixture{
		"bare-root":       func(t *testing.T) *fixture { return newResumeLayoutFixture(t, false, false) },
		"lost+found-only": func(t *testing.T) *fixture { return newResumeLayoutFixture(t, false, true) },
		"no-lost+found":   func(t *testing.T) *fixture { return newResumeLayoutFixture(t, true, false) },
	} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			original := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, newKey(t))}
			key := newKey(t)
			r := resumeRequest(t, f.bootstrap, original, fp(t, key))
			a, err := ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, r))
			must(t, err)
			f.a = a
			if a.s.Revision != 1 || a.s.Controller != (Controller{2, fp(t, key)}) {
				t.Fatal("no-volumes resume did not publish the one revision-1 successor")
			}
			must(t, a.validate())
			// The missing volumes artifact was created only after admission.
			st, err := os.Stat(filepath.Join(f.path, "volumes"))
			must(t, err)
			if st.Mode().Perm() != 0700 {
				t.Fatal("created volumes artifact is not private")
			}
			entries, err := os.ReadDir(filepath.Join(f.path, "volumes"))
			must(t, err)
			if len(entries) != 0 {
				t.Fatal("created volumes artifact is not empty")
			}
		})
	}
	// A refused resume on a volumes-missing layout must not create volumes:
	// creation happens only after the read-only census admits the layout.
	t.Run("refusal-leaves-no-volumes", func(t *testing.T) {
		f := newResumeLayoutFixture(t, false, true)
		must(t, os.WriteFile(filepath.Join(f.path, "stray"), []byte("x"), 0600))
		original := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, newKey(t))}
		r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
		_, err := ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, r))
		if err == nil {
			t.Fatal("strange entry accepted on volumes-missing layout")
		}
		if _, statErr := os.Stat(filepath.Join(f.path, "volumes")); !os.IsNotExist(statErr) {
			t.Fatal("refusal created the volumes artifact")
		}
		if _, statErr := os.Stat(filepath.Join(f.path, registryName)); !os.IsNotExist(statErr) {
			t.Fatal("refusal created the registry")
		}
	})
}

func TestLifecycleResumeGenesisRegistryAndReplay(t *testing.T) {
	f, original := resumeGenesisFixture(t)
	key := newKey(t)
	r := resumeRequest(t, f.bootstrap, original, fp(t, key))
	signed := signResume(t, f.bootstrap, r)
	must(t, f.a.Close())
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	for name, call := range map[string]func() (*Authority, error){
		"original-id": func() (*Authority, error) {
			bad := r
			bad.Original.ID = mustID(t)
			return ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, bad))
		},
		"original-key": func() (*Authority, error) {
			bad := r
			bad.Original.NewKey = fp(t, newKey(t))
			return ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, bad))
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := call()
			wantErr(t, err, ErrConflict)
			if got != nil {
				t.Fatal("refused resume returned authority")
			}
			assertJournalContents(t, path, before)
		})
	}
	a, err := ResumeOpenAndTakeover(f.c, signed)
	must(t, err)
	f.a = a
	if a.s.Revision != 2 || a.s.Controller != (Controller{2, fp(t, key)}) || a.s.Lifecycle.Latest.Grant != r.Takeover.Grant {
		t.Fatal("genesis registry was not consumed into the one applied successor")
	}
	must(t, a.validate())
	must(t, a.Close())
	before = journalContents(t, path)
	got, err := ResumeOpenAndTakeover(f.c, signed)
	wantErr(t, err, ErrLifecycleResumeAlreadyApplied)
	if got != nil {
		t.Fatal("replay returned authority")
	}
	assertJournalContents(t, path, before) // identical state.json bytes prove E never advanced
	f.a, err = OpenLifecycleCurrent(f.c, r.Takeover)
	must(t, err)
	if *f.a.s.Lifecycle.ResumeApplied != *a.s.Lifecycle.ResumeApplied {
		t.Fatal("same-C open dropped resume marker")
	}
	must(t, f.a.Close())
	before = journalContents(t, path) // the same-C open advanced E above
	// A consumed registry rejects any other original outright.
	other := r
	other.Original = LifecycleGrant{LifecycleInitialize, mustID(t), other.Original.Identity, other.Original.Serial + 9, 0, fp(t, newKey(t))}
	other.Takeover.Grant.Serial = other.Original.Serial + 1
	other.Takeover = signLifecycle(t, f.bootstrap, other.Takeover.Grant)
	_, err = ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, other))
	wantErr(t, err, ErrConflict)
	assertJournalContents(t, path, before)
}

// Drive the real journal writer from an existing genesis registry, cutting
// publication of the same successor state shape as ResumeOpenAndTakeover.
func TestLifecycleResumeCrashHelper(t *testing.T) {
	raw := os.Getenv("CENGINE_RESUME_CRASH")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	var input struct {
		Root, Boundary string
		Bootstrap      []byte
		Request        LifecycleResumeOpenRequest
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
	if !exactResumeGenesis(state, input.Request.Original) {
		t.Fatal("resume crash helper requires existing genesis")
	}
	a := &Authority{s: state, j: j, limits: c.Limits}
	next := a.clone()
	next.Epoch = mustID(t)
	g := input.Request.Takeover.Grant
	next.Controller = Controller{g.ExpectedEpoch + 1, g.NewKey}
	next.Lifecycle.OpenRevision = state.Revision + 1
	next.Lifecycle.Latest = lifecycleApplied{g, next.Epoch, state.Revision + 1}
	next.Lifecycle.ResumeApplied = &lifecycleResumeApplied{resumeRequestDigest(input.Request), g.ID, next.Epoch, state.Revision + 1}
	j.afterStep = func(name string) {
		if name == input.Boundary {
			os.Exit(91)
		}
	}
	err = a.commit(next)
	t.Fatalf("resume cut not reached: %v", err)
}

func TestLifecycleResumeInterruptedCommitRefusesRecovery(t *testing.T) {
	for _, boundary := range []string{"state-rename", "state-parent-sync"} {
		t.Run(boundary, func(t *testing.T) {
			f, original := resumeGenesisFixture(t)
			r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
			signed := signResume(t, f.bootstrap, r)
			must(t, f.a.Close())
			input := struct {
				Root, Boundary string
				Bootstrap      []byte
				Request        LifecycleResumeOpenRequest
			}{f.path, boundary, f.c.BootstrapKey, r}
			cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleResumeCrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "CENGINE_RESUME_CRASH="+string(retirementJSON(t, input)), "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 91 {
				t.Fatalf("not abrupt exit: %v %s", err, out)
			}
			path := filepath.Join(f.path, registryName)
			before := retirementJournalCensus(t, path)
			raw, err := os.ReadFile(filepath.Join(path, stateName))
			must(t, err)
			var visible diskState
			must(t, json.Unmarshal(raw, &visible))
			marker := lifecycleResumeApplied{resumeRequestDigest(r), r.Takeover.Grant.ID, visible.Epoch, 2}
			if visible.Revision != 2 || visible.Lifecycle.ResumeApplied == nil || *visible.Lifecycle.ResumeApplied != marker ||
				visible.Lifecycle.Latest.Grant != r.Takeover.Grant || visible.Lifecycle.OpenRevision != 2 {
				t.Fatal("interrupted resume successor is not visible")
			}
			grant := signLifecycle(t, f.bootstrap, visible.Lifecycle.Latest.Grant)
			expected := ExpectedLifecycleStartup{ExpectedStartup{visible.Store.ID, visible.Epoch, visible.Controller}, visible.Lifecycle.OpenRevision}
			for attempt := 0; attempt < 2; attempt++ {
				got, err := ResumeOpenAndTakeover(f.c, signed)
				if got != nil {
					got.Close()
					t.Fatal("interrupted resume returned authority")
				}
				wantErr(t, err, ErrRepairRequired)
				assertRetirementJournalCensus(t, path, before)
				got, err = OpenLifecycleExpected(f.c, grant, expected)
				if got != nil {
					got.Close()
					t.Fatal("expected open recovered interrupted resume")
				}
				wantErr(t, err, ErrRepairRequired)
				assertRetirementJournalCensus(t, path, before)
			}
		})
	}
}

func TestLifecycleResumeOrdinaryTakeoverClearsMarker(t *testing.T) {
	f, original := resumeGenesisFixture(t)
	key := newKey(t)
	r := resumeRequest(t, f.bootstrap, original, fp(t, key))
	must(t, f.a.Close())
	a, err := ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, r))
	must(t, err)
	nextKey := newKey(t)
	g := LifecycleGrant{LifecycleTakeover, mustID(t), r.Takeover.Grant.Identity, r.Takeover.Grant.Serial + 1, 2, fp(t, nextKey)}
	p, err := a.AuthenticateSuccessor(context.Background(), f.conn(nextKey, tls.VersionTLS13, true))
	must(t, err)
	if _, err = a.TakeoverLifecycle(p, signLifecycle(t, f.bootstrap, g)); err != nil {
		t.Fatal(err)
	}
	if a.s.Lifecycle.ResumeApplied != nil {
		t.Fatal("ordinary takeover retained resume marker")
	}
	must(t, a.validate())
	must(t, a.Close())
}

func TestLifecycleResumeRefusesPartialUnknownUncertain(t *testing.T) {
	// Empty-layout violations refuse before the registry exists. A missing
	// lost+found is NOT a violation: it is an optional format artifact.
	for name, violate := range map[string]func(string){
		"extra-entry": func(dir string) { must(t, os.WriteFile(filepath.Join(dir, "stray"), []byte("x"), 0600)) },
		"nonempty-volumes": func(dir string) {
			must(t, os.Mkdir(filepath.Join(dir, "volumes", "data"), 0700))
		},
		"open-mode":            func(dir string) { must(t, os.Chmod(filepath.Join(dir, "volumes"), 0755)) },
		"lost+found-open-mode": func(dir string) { must(t, os.Chmod(filepath.Join(dir, "lost+found"), 0755)) },
		"file-instead-of-dir": func(dir string) {
			must(t, os.Remove(filepath.Join(dir, "volumes")))
			must(t, os.WriteFile(filepath.Join(dir, "volumes"), []byte("x"), 0600))
		},
	} {
		t.Run("empty/"+name, func(t *testing.T) {
			f := newResumeEmptyFixture(t)
			violate(f.path)
			before := rootCensus(t, f.path)
			original := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, newKey(t))}
			r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
			_, err := ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, r))
			if err == nil {
				t.Fatal("partial empty layout accepted")
			}
			if _, statErr := os.Stat(filepath.Join(f.path, registryName)); !os.IsNotExist(statErr) {
				t.Fatal("refusal created the registry")
			}
			if !reflect.DeepEqual(before, rootCensus(t, f.path)) {
				t.Fatal("refusal mutated the closed layout")
			}
		})
	}
	// Registry violations refuse with every byte preserved.
	for name, violate := range map[string]func(*fixture){
		"extra-namespace": func(f *fixture) {
			must(t, os.WriteFile(filepath.Join(f.path, registryName, "stray"), []byte("x"), 0600))
		},
		"uncertain": func(f *fixture) {
			must(t, os.WriteFile(filepath.Join(f.path, registryName, commitProofName), []byte("uncertain"), 0600))
		},
		"controller-keys-map": func(f *fixture) {
			raw, err := os.ReadFile(filepath.Join(f.path, registryName, stateName))
			must(t, err)
			var s diskState
			must(t, json.Unmarshal(raw, &s))
			s.ControllerKeys = &struct{}{}
			raw, err = json.Marshal(s)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), raw, 0600))
		},
		"duplicate-json-field": func(f *fixture) {
			raw, err := os.ReadFile(filepath.Join(f.path, registryName, stateName))
			must(t, err)
			var rawMap map[string]any
			must(t, json.Unmarshal(raw, &rawMap))
			rawMap["revision"] = 1
			dup, err := json.Marshal(rawMap)
			must(t, err)
			dup = bytes.Replace(dup, []byte(`"revision":1`), []byte(`"revision":1,"revision":1`), 1)
			must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), dup, 0600))
		},
		"state-tombstone-only": func(f *fixture) {
			must(t, os.Remove(filepath.Join(f.path, registryName, stateName)))
		},
		"root-stray-refuses-before-mutation": func(f *fixture) {
			must(t, os.WriteFile(filepath.Join(f.path, "stray"), []byte("x"), 0600))
		},
		"root-nonempty-volumes-refuses-before-mutation": func(f *fixture) {
			must(t, os.Mkdir(filepath.Join(f.path, "volumes", "data"), 0700))
		},
		"root-open-mode-volumes-refuses-before-mutation": func(f *fixture) {
			must(t, os.Chmod(filepath.Join(f.path, "volumes"), 0755))
		},
	} {
		t.Run("registry/"+name, func(t *testing.T) {
			f, original := resumeGenesisFixture(t)
			must(t, f.a.Close())
			violate(f)
			path := filepath.Join(f.path, registryName)
			before := journalContents(t, path)
			r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
			got, err := ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, r))
			if err == nil {
				got.Close()
				t.Fatal("violating registry accepted")
			}
			assertJournalContents(t, path, before)
		})
	}
}

func rootCensus(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
			must(t, err)
			names := []string{}
			for _, s := range sub {
				names = append(names, s.Name())
			}
			out[e.Name()+"/"] = strings.Join(names, ",")
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		must(t, err)
		out[e.Name()] = string(b)
	}
	return out
}

// Mixed nil/empty maps: genesis tables must be non-nil and empty, v1 history
// and copy replay must be absent entirely. A hand-tampered encoding that
// validate would also reject must refuse with every byte preserved.
func TestLifecycleResumeRejectsMixedGenesisMaps(t *testing.T) {
	for name, mutate := range map[string]func(*diskState){
		"nil-volume-lifecycles": func(s *diskState) { s.VolumeLifecycles = nil },
		"empty-grants":          func(s *diskState) { s.Grants = &struct{}{} },
		"nil-copy":              func(s *diskState) { s.Copy = nil },
		"nil-copy-intents":      func(s *diskState) { s.Copy.Intents = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f, original := resumeGenesisFixture(t)
			must(t, f.a.Close())
			raw, err := os.ReadFile(filepath.Join(f.path, registryName, stateName))
			must(t, err)
			var s diskState
			must(t, json.Unmarshal(raw, &s))
			mutate(&s)
			raw, err = json.Marshal(s)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), raw, 0600))
			path := filepath.Join(f.path, registryName)
			before := journalContents(t, path)
			r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
			got, err := ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, r))
			if err == nil {
				got.Close()
				t.Fatal("mixed-map genesis accepted")
			}
			assertJournalContents(t, path, before)
		})
	}
}

// A registry copied onto an unknown root (different device/inode identity)
// passes the closed census but must refuse at the store binding with every
// byte preserved: the foreign registry is never consumed, cleaned or rewritten.
func TestLifecycleResumeRefusesUnknownRootWithExistingRegistry(t *testing.T) {
	f, original := resumeGenesisFixture(t)
	must(t, f.a.Close())
	foreign := t.TempDir()
	must(t, os.Mkdir(filepath.Join(foreign, "volumes"), 0700))
	must(t, os.Mkdir(filepath.Join(foreign, "lost+found"), 0700))
	entries, err := os.ReadDir(filepath.Join(f.path, registryName))
	must(t, err)
	must(t, os.Mkdir(filepath.Join(foreign, registryName), 0700))
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(f.path, registryName, e.Name()))
		must(t, err)
		must(t, os.WriteFile(filepath.Join(foreign, registryName, e.Name()), b, 0600))
	}
	root, err := os.Open(foreign)
	must(t, err)
	t.Cleanup(func() { root.Close() })
	f.c.Root = root
	r := resumeRequest(t, f.bootstrap, original, fp(t, newKey(t)))
	got, err := ResumeOpenAndTakeover(f.c, signResume(t, f.bootstrap, r))
	wantErr(t, err, ErrConflict)
	if got != nil {
		t.Fatal("unknown-root resume returned authority")
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(foreign, registryName, e.Name()))
		must(t, err)
		want, err := os.ReadFile(filepath.Join(f.path, registryName, e.Name()))
		must(t, err)
		if !bytes.Equal(b, want) {
			t.Fatal("unknown-root refusal rewrote the foreign registry")
		}
	}
}

// The layout census must not leak descriptors on either branch: the lowest
// free FD is reusable after the probe returns.
func TestResumeLayoutCensusClosesDescriptors(t *testing.T) {
	probe := func(root *os.File, want resumeCensus) {
		t.Helper()
		lo, err := os.Open("/dev/null")
		must(t, err)
		loFD := lo.Fd()
		must(t, lo.Close())
		got, err := probeResumeLayout(root)
		must(t, err)
		if got != want {
			t.Fatalf("census = %d, want %d", got, want)
		}
		hi, err := os.Open("/dev/null")
		must(t, err)
		defer hi.Close()
		if hi.Fd() != loFD {
			t.Fatalf("census leaked a descriptor: lowest fd moved %d -> %d", loFD, hi.Fd())
		}
	}
	f := newResumeEmptyFixture(t)
	probe(f.c.Root, resumeCensusEmpty)
	fg, _ := resumeGenesisFixture(t)
	probe(fg.c.Root, resumeCensusRegistry)
}
