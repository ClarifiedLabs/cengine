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
)

type lifecycleRecoveryInput struct {
	Root           string
	Bootstrap      []byte
	Current        SignedLifecycleGrant
	Expected       ExpectedLifecycleStartup
	Complete       CompleteRequest
	Retire         RetireRequest
	Mode, Boundary string
}

// Real process exit after real journal IO, never a reconstructed proof. The
// internal principal/callback seams do not claim native registry or ext4 proof.
func TestLifecycleRecoveryCrashHelper(t *testing.T) {
	raw := os.Getenv("CENGINE_LIFECYCLE_RECOVERY_CRASH")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	var input lifecycleRecoveryInput
	must(t, json.Unmarshal([]byte(raw), &input))
	root, err := os.Open(input.Root)
	must(t, err)
	a, err := OpenLifecycleExpected(Config{Root: root, DeviceID: "test-device-uuid", BootstrapKey: input.Bootstrap,
		Barrier: func(_ Binding, root *os.File) error { return root.Sync() }}, input.Current, input.Expected)
	must(t, err)
	anchor := ExpectedLifecycleStartup{ExpectedStartup{a.s.Store.ID, a.s.Epoch, a.s.Controller}, a.s.Lifecycle.OpenRevision}
	writeCrashWitness(t, input.Root, "recovery-anchor.json", retirementJSON(t, anchor))
	p := &ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}
	if input.Mode == "root-only" {
		a.prepareRetirementProof = func(_ Binding, _ *os.File, publish func() (bool, error)) (bool, error) { return publish() }
	}
	certified := false
	a.j.afterStep = func(name string) {
		if name == "barrier-complete-parent-sync" {
			certified = true
		}
		// Receipt metadata cuts must not fire during the earlier retire intent.
		if name == input.Boundary && (input.Mode != "retirement" || certified || name == "barrier-complete-write") {
			os.Exit(91)
		}
	}
	if input.Mode == "checkpoint" {
		err = a.CompletePrepare(p, input.Complete)
	} else {
		_, err = a.Retire(context.Background(), p, input.Retire)
	}
	t.Fatalf("cut not reached: %v", err)
}

func lifecycleRecoveryCrash(t *testing.T, mode, boundary string) (*fixture, SignedLifecycleGrant, ExpectedLifecycleStartup, Binding) {
	t.Helper()
	f, current := newLifecycleFixture(t)
	b := prepareRetirementBinding(t, f)
	// Retain a physical acknowledged file across all reopen/refusal checks.
	writeCrashWitness(t, filepath.Join(f.path, "volumes", "prepare-target"), "payload", []byte("stable physical PREPARE data\n"))
	input := lifecycleRecoveryInput{Root: f.path, Bootstrap: f.c.BootstrapKey, Current: current,
		Mode: mode, Boundary: boundary, Retire: RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}}
	if mode == "checkpoint" {
		r := f.retire(b)
		input.Complete = CompleteRequest{Operation: mustID(t), Prepare: b.Prepare, Receipts: []Receipt{r}, Attestation: Attestation{b.Prepare, true, true}}
	}
	input.Expected = expectedLifecycleStartup(f)
	must(t, f.a.Close())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleRecoveryCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CENGINE_LIFECYCLE_RECOVERY_CRASH="+string(retirementJSON(t, input)), "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 91 {
		t.Fatalf("not abrupt exit: %v %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(f.path, "recovery-anchor.json"))
	must(t, err)
	var expected ExpectedLifecycleStartup
	must(t, json.Unmarshal(raw, &expected))
	return f, current, expected, b
}

func TestLifecycleProvenRecovery(t *testing.T) {
	for _, tc := range []struct{ mode, boundary string }{
		{"checkpoint", "proof-write"},
		{"checkpoint", "proof-sync"},
		{"checkpoint", "proof-close"},
		{"checkpoint", "proof-parent-sync"},
		{"checkpoint", "state-write"},
		{"checkpoint", "proof-ready-close"},
		{"checkpoint", "proof-ready-parent-sync"},
		{"checkpoint", "state-rename"},
		{"checkpoint", "state-parent-sync"},
		{"retirement", "barrier-complete-write"},
		{"retirement", "barrier-complete-parent-sync"},
		{"retirement", "proof-ready-close"},
		{"retirement", "state-parent-sync"},
		{"root-only", "prepare-retire-proof-write"},
		{"root-only", "prepare-retire-proof-sync"},
		{"root-only", "prepare-retire-proof-close"},
		{"root-only", "prepare-retire-proof-parent-sync"},
		{"root-only", "barrier-complete-write"},
		{"root-only", "barrier-complete-sync"},
		{"root-only", "barrier-complete-close"},
	} {
		t.Run(tc.mode+"/"+tc.boundary, func(t *testing.T) {
			f, current, expected, b := lifecycleRecoveryCrash(t, tc.mode, tc.boundary)
			path := filepath.Join(f.path, registryName)
			raw, err := os.ReadFile(filepath.Join(path, stateName))
			must(t, err)
			var before diskState
			must(t, json.Unmarshal(raw, &before))
			applied := before.Lifecycle.Latest
			// Pin the selected crash edge, not just preservation of whatever image
			// happened to be visible. Ready publication is NOT state publication.
			if tc.mode == "checkpoint" {
				want := Pending
				if tc.boundary == "state-rename" || tc.boundary == "state-parent-sync" {
					want = Completed
				}
				if before.Prepares[b.Prepare].Phase != want {
					t.Fatal("checkpoint landed at the wrong boundary")
				}
			}
			f.c.Barrier = func(Binding, *os.File) error { t.Error("recovery ran a barrier"); return ErrBlocked }
			// Even a fully proven artifact cannot bypass either external anchor.
			files := retirementJournalCensus(t, path)
			wrong := expected
			wrong.OpenRevision++
			_, err = OpenLifecycleExpected(f.c, current, wrong)
			wantErr(t, err, ErrConflict)
			assertRetirementJournalCensus(t, path, files)
			for _, call := range []func() (*Authority, error){

				func() (*Authority, error) { return OpenLifecycle(f.c, current.Grant.Identity) },
				func() (*Authority, error) { return OpenLifecycleCurrent(f.c, current) },
			} {
				a, err := call()
				if err == nil {
					a.Close()
					t.Fatal("unguarded recovery accepted")
				}
				assertRetirementJournalCensus(t, path, files)
			}
			a, err := OpenLifecycleExpected(f.c, current, expected)
			must(t, err)
			f.a = a
			before.Epoch, before.Revision = a.s.Epoch, before.Revision+1
			before.Lifecycle.OpenRevision = before.Revision
			if a.s.Epoch == expected.Epoch || !reflect.DeepEqual(&before, a.s) || a.s.Lifecycle.Latest != applied {
				t.Fatal("recovery changed checkpoint/receipt/stable grant beyond E/revision/open anchor")
			}
			if len(lifecycleFiles(t, f)) != 2 {
				t.Fatal("bound artifacts not cleaned")
			}
			payload, err := os.ReadFile(filepath.Join(f.path, "volumes", "prepare-target", "payload"))
			must(t, err)
			if string(payload) != "stable physical PREPARE data\n" {
				t.Fatal("physical payload changed")
			}
			if tc.mode == "root-only" || (tc.mode == "retirement" && tc.boundary != "state-parent-sync") {
				rec := a.s.Attachments[b.Attachment]
				if rec.Phase != Retiring || rec.Receipt != nil || a.s.Prepares[b.Prepare].Phase != Pending {
					t.Fatal("retry-only recovery manufactured completion")
				}
				a.barrier = func(_ Binding, root *os.File) error { return root.Sync() }
				_, err = a.Retire(context.Background(), &ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}, RetireRequest{rec.Retirement, b.Store, b.Volume, b.Attachment, b.Launch})
				must(t, err)
			}
			fresh := expectedLifecycleStartup(f)
			must(t, a.Close())
			files = retirementJournalCensus(t, path)
			_, err = OpenLifecycleExpected(f.c, current, expected)
			wantErr(t, err, ErrConflict)
			assertRetirementJournalCensus(t, path, files)
			f.a, err = OpenLifecycleExpected(f.c, current, fresh)
			must(t, err)
		})
	}
}

func TestLifecycleRecoveryBoundArtifactsRequireExactPair(t *testing.T) {
	for _, kind := range []string{"candidate-epoch", "candidate-open-revision", "candidate-grant", "candidate-canonical", "ready-digest", "duplicate-candidate", "barrier-pair", "root-only-binding", "root-only-mixed"} {
		t.Run(kind, func(t *testing.T) {
			mode, boundary := "checkpoint", "proof-ready-close"
			if kind == "barrier-pair" {
				mode = "retirement"
			}
			if kind == "root-only-binding" || kind == "root-only-mixed" {
				mode, boundary = "root-only", "prepare-retire-proof-parent-sync"
			}
			f, current, expected, _ := lifecycleRecoveryCrash(t, mode, boundary)
			path := filepath.Join(f.path, registryName)
			if mode == "root-only" {
				raw, err := os.ReadFile(filepath.Join(path, barrierName))
				must(t, err)
				p, err := decodePrepareRetirementProof(raw)
				must(t, err)
				if kind == "root-only-binding" {
					p.Binding.Launch = mustID(t)
				} else {
					must(t, os.WriteFile(filepath.Join(path, "prepare-retire-complete-"+string(mustID(t))+".tmp"), raw, 0600))
				}
				must(t, os.WriteFile(filepath.Join(path, barrierName), retirementJSON(t, p), 0600))
			} else {
				files := lifecycleFiles(t, f)
				var stateName, readyName string
				for name := range files {
					if lifecycleTemporary(name, "state-") {
						stateName = name
					}
					if lifecycleTemporary(name, "proof-") {
						readyName = name
					}
				}
				if stateName == "" || readyName == "" {
					t.Fatal("missing real checkpoint artifacts")
				}
				var candidate diskState
				must(t, json.Unmarshal([]byte(files[stateName]), &candidate))
				switch kind {
				case "candidate-epoch":
					candidate.Epoch = mustID(t)
				case "candidate-open-revision":
					candidate.Lifecycle.OpenRevision++
				case "candidate-grant":
					candidate.Lifecycle.Latest.Grant.ID = mustID(t)
				}
				raw := retirementJSON(t, candidate)
				if kind == "candidate-canonical" {
					raw = append(raw, '\n')
				}
				must(t, os.WriteFile(filepath.Join(path, stateName), raw, 0600))
				// Update both digests too: candidate anchor/canonical validation must
				// reject even when all transaction content hashes still agree.
				var meta commitProof
				must(t, json.Unmarshal([]byte(files[commitProofName]), &meta))
				meta.Next = contentDigest(raw)
				must(t, os.WriteFile(filepath.Join(path, commitProofName), retirementJSON(t, meta), 0600))
				meta.Ready = true
				if kind == "ready-digest" {
					meta.Next = contentDigest([]byte("another transaction"))
				}
				must(t, os.WriteFile(filepath.Join(path, readyName), retirementJSON(t, meta), 0600))
				if kind == "duplicate-candidate" {
					must(t, os.WriteFile(filepath.Join(path, "state-"+string(mustID(t))+".tmp"), raw, 0600))
				}
				if kind == "barrier-pair" {
					var p retirementProof
					must(t, json.Unmarshal([]byte(files[barrierName]), &p))
					p.Next = contentDigest([]byte("different receipt"))
					must(t, os.WriteFile(filepath.Join(path, barrierName), retirementJSON(t, p), 0600))
				}
			}
			before := retirementJournalCensus(t, path)
			for range 2 {
				a, err := OpenLifecycleExpected(f.c, current, expected)
				if err == nil {
					a.Close()
					t.Fatal("mixed/changed proof admitted")
				}
				assertRetirementJournalCensus(t, path, before)
			}
		})
	}
}

func TestLifecycleRecoveryIdentityOnlyRefusesUnboundProofTemp(t *testing.T) {
	// proof-ready-close retains both transaction temporaries; later boundaries
	// have already renamed the state candidate into place.
	f, current, expected, _ := lifecycleRecoveryCrash(t, "checkpoint", "proof-ready-close")
	path := filepath.Join(f.path, registryName)
	// Retain the crash's published evidence but rebuild the namespace as clean
	// lock+state plus one stray unbound proof temporary: a pure count check would
	// see exactly two extra names disappear while OpenLifecycle (current==nil)
	// has no transaction to discharge any temporary.
	files := lifecycleFiles(t, f)
	stateTemp, readyTemp := "", ""
	for name := range files {
		if lifecycleTemporary(name, "state-") {
			stateTemp = name
		}
		if lifecycleTemporary(name, "proof-") {
			readyTemp = name
		}
	}
	if stateTemp == "" || readyTemp == "" {
		t.Fatal("missing real checkpoint artifacts")
	}
	for _, name := range []string{commitProofName, stateTemp, readyTemp} {
		must(t, os.Remove(filepath.Join(path, name)))
	}
	stray := "proof-" + string(mustID(t)) + ".tmp"
	must(t, os.WriteFile(filepath.Join(path, stray), []byte("retained unbound proof temporary"), 0600))
	before := retirementJournalCensus(t, path)
	for range 2 {
		a, err := OpenLifecycle(f.c, current.Grant.Identity)
		if err == nil {
			a.Close()
			t.Fatal("identity-only open admitted an unbound proof temporary")
		}
		assertRetirementJournalCensus(t, path, before)
	}
	_, err := OpenLifecycleExpected(f.c, current, expected)
	if err == nil {
		t.Fatal("unbound temporary cannot be discharged")
	}
	assertRetirementJournalCensus(t, path, before)
}

func TestLifecycleRecoveryFastPathIsNotCountOnly(t *testing.T) {
	f, current, expected, _ := lifecycleRecoveryCrash(t, "checkpoint", "proof-ready-close")
	path := filepath.Join(f.path, registryName)
	files := lifecycleFiles(t, f)
	var stateTemp, readyTemp string
	for name := range files {
		if lifecycleTemporary(name, "state-") {
			stateTemp = name
		}
		if lifecycleTemporary(name, "proof-") {
			readyTemp = name
		}
	}
	if stateTemp == "" || readyTemp == "" {
		t.Fatal("missing real checkpoint artifacts")
	}
	// Collapse the namespace to lock+state+stray: the exact count the old fast
	// path accepted, but the stray name is outside the lock/stateName whitelist.
	for _, name := range []string{commitProofName, stateTemp, readyTemp} {
		must(t, os.Remove(filepath.Join(path, name)))
	}
	stray := "proof-" + string(mustID(t)) + ".tmp"
	must(t, os.WriteFile(filepath.Join(path, stray), []byte("retained stray temporary"), 0600))
	before := retirementJournalCensus(t, path)
	for range 2 {
		a, err := OpenLifecycleExpected(f.c, current, expected)
		if err == nil {
			a.Close()
			t.Fatal("count-only fast path admitted a stray temporary")
		}
		assertRetirementJournalCensus(t, path, before)
	}
}

func TestLifecycleRootOnlyCompletionTemporaryRefusesUnboundEvidence(t *testing.T) {
	for _, kind := range []string{"prior", "next", "operation", "binding", "revision", "epoch", "controller", "attempt-name", "partial", "public", "duplicate", "missing-proof"} {
		t.Run(kind, func(t *testing.T) {
			f, current, expected, _ := lifecycleRecoveryCrash(t, "root-only", "barrier-complete-close")
			path := filepath.Join(f.path, registryName)
			var name string
			for entry := range lifecycleFiles(t, f) {
				if lifecycleTemporary(entry, "prepare-retire-complete-") {
					name = entry
				}
			}
			if name == "" {
				t.Fatal("missing real completion candidate")
			}
			raw, err := os.ReadFile(filepath.Join(path, name))
			must(t, err)
			p, err := decodeRetirementProof(raw)
			must(t, err)
			switch kind {
			case "prior":
				p.Prior = contentDigest([]byte("foreign predecessor"))
			case "next":
				p.Next = contentDigest([]byte("foreign successor"))
			case "operation":
				p.Operation = mustID(t)
			case "binding":
				p.Binding.Attachment = mustID(t)
			case "revision":
				p.Revision++
			case "epoch":
				p.Epoch = mustID(t)
			case "controller":
				p.Controller.Key = fp(t, newKey(t))
			case "attempt-name":
				p.Attempt = mustID(t)
			}
			raw = retirementJSON(t, p)
			if kind == "partial" {
				raw = raw[:len(raw)/2]
			}
			must(t, os.WriteFile(filepath.Join(path, name), raw, 0600))
			switch kind {
			case "public":
				must(t, os.Chmod(filepath.Join(path, name), 0644))
			case "duplicate":
				must(t, os.WriteFile(filepath.Join(path, "prepare-retire-complete-"+string(mustID(t))+".tmp"), raw, 0600))
			case "missing-proof":
				must(t, os.Remove(filepath.Join(path, barrierName)))
			}
			before := retirementJournalCensus(t, path)
			for range 2 {
				a, err := OpenLifecycleExpected(f.c, current, expected)
				if a != nil {
					a.Close()
					t.Fatal("unbound candidate returned authority")
				}
				if err == nil {
					t.Fatal("unbound candidate admitted")
				}
				assertRetirementJournalCensus(t, path, before)
			}
		})
	}
}

func TestLifecycleRecoveryRefusalPreservesAllBytes(t *testing.T) {
	for _, kind := range []string{"signature", "grant", "store", "epoch", "controller", "key", "open-revision", "root", "proof-store", "proof-epoch", "proof-revision", "proof-next", "proof-version", "unready", "unknown-field", "unknown", "terminal", "uncertain", "data", "quarantine", "copy", "mixed", "copied-proof", "hardlink", "symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			f, current, expected, _ := lifecycleRecoveryCrash(t, "checkpoint", "state-parent-sync")
			path := filepath.Join(f.path, registryName)
			proofPath := filepath.Join(path, commitProofName)
			raw, err := os.ReadFile(proofPath)
			must(t, err)
			var proof commitProof
			must(t, json.Unmarshal(raw, &proof))
			switch kind {
			case "signature":
				current.Signature[0] ^= 1
			case "grant":
				current.Grant.ID = mustID(t)
				current = signLifecycle(t, f.bootstrap, current.Grant)
			case "store":
				expected.Store = mustID(t)
			case "epoch":
				expected.Epoch = mustID(t)
			case "controller":
				expected.Controller.Epoch++
			case "key":
				expected.Controller.Key = fp(t, newKey(t))
			case "open-revision":
				expected.OpenRevision++
			case "root":
				v := filepath.Join(f.path, "volumes", "prepare-target")
				must(t, os.Rename(v, v+"-retained"))
				must(t, os.Mkdir(v, 0700))
			case "proof-store":
				proof.Store = mustID(t)
			case "proof-epoch":
				proof.Epoch = mustID(t)
			case "proof-revision":
				proof.Revision++
			case "proof-next":
				proof.Next = contentDigest([]byte("other"))
			case "proof-version":
				proof.Version++
			case "unready":
				proof.Ready = false
			case "copied-proof":
				other, _, _, _ := lifecycleRecoveryCrash(t, "checkpoint", "state-parent-sync")
				foreign, err := os.ReadFile(registryFile(t, other, commitProofName))
				must(t, err)
				must(t, json.Unmarshal(foreign, &proof))
			}
			raw = retirementJSON(t, proof)
			if kind == "unknown-field" {
				raw = append(raw[:len(raw)-1], []byte(",\"unknown\":true}")...)
			}
			must(t, os.WriteFile(proofPath, raw, 0600))
			names := map[string]string{"unknown": "foreign", "terminal": lifecycleFenceName, "uncertain": pendingName, "data": dataIOName, "quarantine": quarantineName, "copy": copyOperationName, "mixed": "state-" + string(mustID(t)) + ".tmp"}
			if name := names[kind]; name != "" {
				must(t, os.WriteFile(filepath.Join(path, name), []byte("retained evidence"), 0600))
			}
			switch kind {
			case "hardlink":
				must(t, os.Link(proofPath, filepath.Join(f.path, "linked-proof")))
			case "symlink":
				must(t, os.Rename(proofPath, filepath.Join(f.path, "linked-proof")))
				must(t, os.Symlink(filepath.Join(f.path, "linked-proof"), proofPath))
			case "public":
				must(t, os.Chmod(proofPath, 0644))
			}
			before := retirementJournalCensus(t, path)
			for range 2 {
				a, err := OpenLifecycleExpected(f.c, current, expected)
				if err == nil {
					a.Close()
					t.Fatal("invalid evidence admitted")
				}
				assertRetirementJournalCensus(t, path, before)
			}
		})
	}
}
