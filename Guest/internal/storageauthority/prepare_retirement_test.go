//go:build linux || darwin

package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var prepareRetirementPublicationSteps = []string{
	"prepare-retire-proof-open", "prepare-retire-proof-write", "prepare-retire-proof-sync",
	"prepare-retire-proof-close", "prepare-retire-proof-rename", "prepare-retire-proof-parent-sync",
}
var prepareRetirementRecoverySteps = []string{
	"recover-prepare-retire-parent-sync", "recover-prepare-retire-unlink", "recover-prepare-retire-clear-sync",
}

func prepareRetirementBinding(t *testing.T, f *fixture) Binding {
	t.Helper()
	b, _ := f.binding(f.volume("prepare-target"), PrepareRole, ReadWrite, mustID(t))
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), b.Prepare, []Binding{b}}))
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}))
	return b
}

func prepareRetirementImage(t *testing.T) (*fixture, prepareRetirementProof) {
	t.Helper()
	f := newFixture(t, nil)
	stable, _ := f.runtime(f.volume("stable"), ReadOnly)
	f.retire(stable)
	b := prepareRetirementBinding(t, f)
	var raw, prior []byte
	f.a.prepareRetirementProof = func(_ Binding, _ *os.File, publish func() (bool, error)) (bool, error) {
		_ = f.a.Epoch() // verifies callback is not called under authority.mu
		return publish()
	}
	f.a.barrier = func(Binding, *os.File) (err error) {
		raw, err = os.ReadFile(registryFile(t, f, barrierName))
		if err == nil {
			prior, err = os.ReadFile(registryFile(t, f, stateName))
		}
		return err
	}
	f.retire(b)
	p, err := decodePrepareRetirementProof(raw)
	must(t, err)
	if _, err = decodeRetirementProof(raw); err == nil {
		t.Fatal("old v1 decoder accepted retry-only evidence")
	}
	must(t, f.a.Close())
	must(t, os.WriteFile(registryFile(t, f, stateName), prior, 0600))
	must(t, os.WriteFile(registryFile(t, f, barrierName), raw, 0600))
	return f, *p
}

func TestPrepareRetirementCompletionClearsLiveProof(t *testing.T) {
	f := newFixture(t, nil)
	f.a.prepareRetirementProof = func(_ Binding, _ *os.File, publish func() (bool, error)) (bool, error) {
		return publish()
	}
	for repeat := 0; repeat < 2; repeat++ {
		b, _ := f.binding(f.volume("repeated-prepare-"+string(rune('a'+repeat))), PrepareRole, ReadWrite, mustID(t))
		must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), b.Prepare, []Binding{b}}))
		must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}))
		f.retire(b)
		if f.a.j.rootOnly != nil {
			t.Fatal("successful retirement retained live retry-only proof")
		}
	}
}

func TestPrepareRetirementRecoveryRetainsExactPredecessor(t *testing.T) {
	f, p := prepareRetirementImage(t)
	var before diskState
	raw, err := os.ReadFile(registryFile(t, f, stateName))
	must(t, err)
	must(t, json.Unmarshal(raw, &before))
	f.c.Barrier = func(Binding, *os.File) error { t.Error("startup ran barrier"); return ErrInvalid }
	f.c.PrepareRetirementProof = func(Binding, *os.File, func() (bool, error)) (bool, error) {
		t.Error("startup inspected live registry")
		return false, ErrInvalid
	}
	f.a, err = f.openExpected(ExpectedStartup{p.Store.ID, p.Epoch, p.Controller})
	must(t, err)
	if f.a.s.Epoch == before.Epoch {
		t.Fatal("epoch not rotated")
	}
	before.Epoch, before.Revision = f.a.s.Epoch, before.Revision+1
	before.Lifecycle.OpenRevision = before.Revision
	if !reflect.DeepEqual(&before, f.a.s) {
		t.Fatal("recovery changed predecessor beyond epoch/revision")
	}
	if _, err := os.Stat(registryFile(t, f, barrierName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("marker retained", err)
	}
	// Only a fresh full barrier can turn this retryable state into a receipt.
	f.a.prepareRetirementProof = nil
	calls := 0
	f.a.barrier = func(Binding, *os.File) error { calls++; return nil }
	f.control = f.authControl(f.controllerKey, p.Controller.Epoch)
	r, err := f.a.Retire(context.Background(), f.control, RetireRequest{p.Operation, p.Binding.Store, p.Binding.Volume, p.Binding.Attachment, p.Binding.Launch})
	must(t, err)
	if calls != 1 || r.Attachment != p.Binding.Attachment {
		t.Fatal("retry did not run exactly one barrier")
	}
}

func TestPrepareRetirementProofTamperAndOverlapInert(t *testing.T) {
	for _, field := range []string{"version", "kind", "attempt", "store", "store-root", "exports", "device", "epoch", "controller", "bootstrap", "volume", "volume-root", "binding", "launch", "container", "key", "role", "mode", "prepare", "operation", "revision", "prior", "unknown", "duplicate", "noncanonical", "next", "oversize", "data", "copy", "metadata", "quarantine", "pending", "symlink", "hardlink", "public"} {
		t.Run(field, func(t *testing.T) {
			f, p := prepareRetirementImage(t)
			expected := ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}
			switch field {
			case "version":
				p.Version++
			case "kind":
				p.Kind += "-unknown"
			case "attempt":
				p.Attempt = "invalid"
			case "store":
				p.Store.ID = mustID(t)
			case "store-root":
				p.Store.Root.Inode++
			case "exports":
				p.Store.Exports.Inode++
			case "device":
				p.Store.DeviceID += "-other"
			case "epoch":
				p.Epoch = mustID(t)
			case "controller":
				p.Controller.Epoch++
			case "bootstrap":
				p.Bootstrap = fp(t, newKey(t))
			case "volume":
				p.Volume.ID = mustID(t)
			case "volume-root":
				p.Volume.Root.Inode++
			case "binding":
				p.Binding.Attachment = mustID(t)
			case "launch":
				p.Binding.Launch = mustID(t)
			case "container":
				p.Binding.Container = mustContainerID(t)
			case "key":
				p.Binding.Key = fp(t, newKey(t))
			case "role":
				p.Binding.Role = RuntimeRole
			case "mode":
				p.Binding.Mode = ReadOnly
			case "prepare":
				p.Binding.Prepare = mustID(t)
			case "operation":
				p.Operation = mustID(t)
			case "revision":
				p.Revision++
			case "prior":
				p.Prior = contentDigest([]byte("different"))
			}
			raw := retirementJSON(t, p)
			switch field {
			case "unknown":
				raw = append(raw[:len(raw)-1], []byte(",\"unknown\":true}")...)
			case "duplicate":
				raw = append([]byte("{\"version\":2,"), raw[1:]...)
			case "noncanonical":
				raw = append(raw, '\n')
			case "next":
				raw = append(raw[:len(raw)-1], []byte(",\"next_digest\":\"fake\"}")...)
			case "oversize":
				raw = bytes.Repeat([]byte("x"), maxRetirementProofBytes+1)
			}
			marker := registryFile(t, f, barrierName)
			must(t, os.WriteFile(marker, raw, 0600))
			slots := map[string]string{"data": dataIOName, "copy": copyOperationName, "metadata": commitProofName, "quarantine": quarantineName, "pending": pendingName}
			if name := slots[field]; name != "" {
				must(t, os.WriteFile(registryFile(t, f, name), []byte("obligation"), 0600))
			}
			switch field {
			case "symlink":
				must(t, os.Rename(marker, marker+"-saved"))
				must(t, os.Symlink(marker+"-saved", marker))
			case "hardlink":
				must(t, os.Link(marker, marker+"-linked"))
			case "public":
				must(t, os.Chmod(marker, 0644))
			}
			retirementRefusesUnchanged(t, f, expected, ErrRepairRequired)
		})
	}
}

func TestPrepareRetirementExpectedAndRootsBeforeCleanup(t *testing.T) {
	for _, field := range []string{"store", "epoch", "controller", "root"} {
		t.Run(field, func(t *testing.T) {
			f, p := prepareRetirementImage(t)
			expected := ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}
			switch field {
			case "store":
				expected.Store = mustID(t)
			case "epoch":
				expected.Epoch = mustID(t)
			case "controller":
				expected.Controller.Epoch++
			case "root":
				path := filepath.Join(f.path, "volumes", "stable") // ALL roots, not just selected
				must(t, os.Rename(path, path+"-old"))
				must(t, os.Mkdir(path, 0700))
			}
			before := retirementJournalCensus(t, filepath.Join(f.path, registryName))
			for range 2 {
				a, err := f.openExpected(expected)
				if a != nil {
					a.Close()
					t.Fatal("invalid expected/root accepted")
				}
				wantErr(t, err, ErrConflict)
				assertRetirementJournalCensus(t, filepath.Join(f.path, registryName), before)
			}
		})
	}
}

func TestPrepareRetirementCallbackScopeAndFallback(t *testing.T) {
	for _, mode := range []string{"nil", "false", "publish", "twice", "lie", "error", "panic", "other-active", "copy", "data-slot", "copy-slot", "metadata-slot", "raw-state"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, nil)
			b := prepareRetirementBinding(t, f)
			if mode == "other-active" {
				f.runtime(f.volume("other"), ReadOnly)
			}
			var escaped func() (bool, error)
			f.a.prepareRetirementProof = func(_ Binding, _ *os.File, publish func() (bool, error)) (bool, error) {
				escaped = publish
				_ = f.a.Epoch()
				switch mode {
				case "false":
					return false, nil
				case "lie":
					return true, nil
				case "error":
					return false, unix.EIO
				case "panic":
					panic("inspection")
				case "data-slot", "copy-slot", "metadata-slot":
					name := map[string]string{"data-slot": dataIOName, "copy-slot": copyOperationName, "metadata-slot": commitProofName}[mode]
					if err := os.WriteFile(registryFile(t, f, name), []byte("obligation"), 0600); err != nil {
						return false, err
					}
				case "raw-state":
					raw, err := os.ReadFile(registryFile(t, f, stateName))
					if err != nil {
						return false, err
					}
					if err = os.WriteFile(registryFile(t, f, stateName), append(raw, '\n'), 0600); err != nil {
						return false, err
					}
				}
				ok, err := publish()
				if mode == "twice" {
					return publish()
				}
				return ok, err
			}
			if mode == "nil" {
				f.a.prepareRetirementProof = nil
			}
			// A valid but unfinished copy owned by a different attachment also
			// prevents publication, independently of retained registry ownership.
			if mode == "copy" {
				v := f.volume("copy")
				owner, g := copyPrepare(t, f, v, ReadWrite)
				_, err := g.BeginCopy(copyRoot(f, v))
				must(t, err)
				g.Release()
				callback := f.a.prepareRetirementProof
				f.a.prepareRetirementProof = nil
				f.retire(owner)
				f.a.prepareRetirementProof = callback
			}
			calls := 0
			f.a.barrier = func(Binding, *os.File) error {
				calls++
				raw, err := os.ReadFile(registryFile(t, f, barrierName))
				if err != nil {
					return err
				}
				if mode == "publish" {
					_, err = decodePrepareRetirementProof(raw)
					return err
				}
				if string(raw) != uncertainIOText {
					return ErrConflict
				}
				return nil
			}
			r, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
			bad := mode == "twice" || mode == "lie" || mode == "error" || mode == "panic" || strings.HasSuffix(mode, "-slot") || mode == "raw-state"
			if bad {
				wantErr(t, err, ErrBlocked)
				if calls != 0 || r != (Receipt{}) {
					t.Fatal("inspection failure fell back or minted receipt")
				}
			} else {
				must(t, err)
				if calls != 1 {
					t.Fatal("missing complete barrier")
				}
			}
			if escaped != nil {
				before := retirementJournalCensus(t, filepath.Join(f.path, registryName))
				ok, err := escaped()
				if ok {
					t.Fatal("escaped publication accepted")
				}
				wantErr(t, err, ErrInvalid)
				assertRetirementJournalCensus(t, filepath.Join(f.path, registryName), before)
			}
		})
	}
}

func TestPrepareRetirementAsynchronousPublicationCannotSucceed(t *testing.T) {
	f := newFixture(t, nil)
	b := prepareRetirementBinding(t, f)
	entered, callbackReturning, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	publication := make(chan error, 1)
	f.a.j.fault = func(name string) error {
		if name == "prepare-retire-proof-write" {
			close(entered)
			<-release
		}
		return nil
	}
	f.a.prepareRetirementProof = func(_ Binding, _ *os.File, publish func() (bool, error)) (bool, error) {
		go func() { _, err := publish(); publication <- err }()
		<-entered
		close(callbackReturning)
		return true, nil // forbidden: publication is still inside journal IO
	}
	f.a.barrier = func(Binding, *os.File) error { t.Error("async publication reached barrier"); return ErrInvalid }
	result := make(chan error, 1)
	go func() {
		_, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
		result <- err
	}()
	await(t, callbackReturning)
	// Publication is held while the callback returns. This delay allows its
	// teardown to run; the production invariant itself uses atomic scope state.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wantErr(t, <-result, ErrBlocked)
	wantErr(t, <-publication, ErrBlocked)
	must(t, f.a.Close())
	retirementRefusesUnchanged(t, f, ExpectedStartup{f.a.s.Store.ID, f.a.s.Epoch, f.a.s.Controller}, ErrRepairRequired)
}

func TestPrepareRetirementPublicationFailuresSticky(t *testing.T) {
	steps := append(append([]string{}, prepareRetirementPublicationSteps...), "barrier")
	for _, failure := range []error{unix.EIO, unix.ENOSPC} {
		for _, step := range steps {
			t.Run(failure.Error()+"/"+step, func(t *testing.T) {
				f := newFixture(t, nil)
				b := prepareRetirementBinding(t, f)
				f.a.prepareRetirementProof = func(_ Binding, _ *os.File, publish func() (bool, error)) (bool, error) { return publish() }
				reached := false
				f.a.j.fault = func(name string) error {
					if name == step {
						reached = true
						return failure
					}
					return nil
				}
				f.a.barrier = func(Binding, *os.File) error {
					if step == "barrier" {
						reached = true
						return failure
					}
					return nil
				}
				r, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
				wantErr(t, err, ErrBlocked)
				if !reached || r != (Receipt{}) {
					t.Fatal("failure not exercised")
				}
				must(t, f.a.Close())
				retirementRefusesUnchanged(t, f, ExpectedStartup{f.a.s.Store.ID, f.a.s.Epoch, f.a.s.Controller}, ErrRepairRequired)
			})
		}
	}
}

const prepareRetirementCrashEnv = "CENGINE_PREPARE_RETIREMENT_ROOT"

type prepareRetirementManifest struct {
	Bootstrap ed25519.PublicKey
	Before    diskState
	Current   SignedLifecycleGrant
}

// Same-host process death exercises production writes, not physical power loss.
func TestPrepareRetirementCrashWorker(t *testing.T) {
	path := os.Getenv(prepareRetirementCrashEnv)
	if path == "" {
		return
	}
	edge, boundary := os.Getenv("PREPARE_RETIREMENT_EDGE"), os.Getenv("PREPARE_RETIREMENT_BOUNDARY")
	checkpoint := func(when, name string) {
		if edge == when && boundary == name {
			os.Exit(crashExit)
		}
	}
	if os.Getenv("PREPARE_RETIREMENT_MODE") == "cleanup" {
		raw, err := os.ReadFile(filepath.Join(path, "prepare-retire-manifest"))
		must(t, err)
		var m prepareRetirementManifest
		must(t, json.Unmarshal(raw, &m))
		root, err := os.Open(path)
		must(t, err)
		cfg, err := configured(Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { return ErrInvalid }})
		must(t, err)
		j, err := openJournal(cfg, false)
		must(t, err)
		a := &Authority{j: j, s: &m.Before, limits: cfg.Limits}
		must(t, a.validate())
		must(t, a.validatePrepareRetirementRecovery())
		j.fault = func(name string) error { checkpoint("before", name); return nil }
		j.afterStep = func(name string) { checkpoint("after", name) }
		must(t, j.recoverPrepareRetirement())
		t.Fatal("cleanup checkpoint missed")
	}
	f := newFixtureAt(t, nil, path)
	b := prepareRetirementBinding(t, f)
	f.a.prepareRetirementProof = func(_ Binding, _ *os.File, publish func() (bool, error)) (bool, error) {
		f.a.mu.Lock()
		before := f.a.clone()
		f.a.mu.Unlock()
		if err := os.WriteFile(filepath.Join(path, "prepare-retire-manifest"), retirementJSON(t, prepareRetirementManifest{f.c.BootstrapKey, *before, f.signedCurrent()}), 0600); err != nil {
			return false, err
		}
		f.a.j.fault = func(name string) error { checkpoint("before", name); return nil }
		f.a.j.afterStep = func(name string) { checkpoint("after", name) }
		return publish()
	}
	f.a.barrier = func(Binding, *os.File) error { checkpoint("inside", "barrier"); return nil }
	_, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
	t.Fatal("publication checkpoint missed", err)
}

func prepareRetirementCrash(t *testing.T, path, mode, edge, boundary string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPrepareRetirementCrashWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), prepareRetirementCrashEnv+"="+path, "PREPARE_RETIREMENT_MODE="+mode, "PREPARE_RETIREMENT_EDGE="+edge, "PREPARE_RETIREMENT_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
		t.Fatalf("worker: %v\n%s", err, output)
	}
}

func TestPrepareRetirementAbruptPublicationAndRecovery(t *testing.T) {
	for _, mode := range []string{"publish", "cleanup"} {
		steps := append(append([]string{}, prepareRetirementPublicationSteps...), retirementCompletionBoundaries...)
		if mode == "cleanup" {
			steps = prepareRetirementRecoverySteps
		}
		for _, edge := range []string{"before", "after"} {
			for _, step := range steps {
				t.Run(mode+"/"+edge+"/"+step, func(t *testing.T) {
					path := t.TempDir()
					if mode == "cleanup" {
						prepareRetirementCrash(t, path, "publish", "inside", "barrier")
					}
					prepareRetirementCrash(t, path, mode, edge, step)
					raw, err := os.ReadFile(filepath.Join(path, "prepare-retire-manifest"))
					must(t, err)
					var m prepareRetirementManifest
					must(t, json.Unmarshal(raw, &m))
					root, err := os.Open(path)
					must(t, err)
					defer root.Close()
					cfg := Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { t.Error("Open ran barrier"); return ErrInvalid }}
					expected := ExpectedStartup{m.Before.Store.ID, m.Before.Epoch, m.Before.Controller}
					open := func() (*Authority, error) {
						return OpenLifecycleExpected(cfg, m.Current, ExpectedLifecycleStartup{expected, m.Before.Lifecycle.OpenRevision})
					}
					// Both initial and completion publications need complete candidate
					// bytes; an empty temporary cannot be authenticated or discarded.
					empty := edge == "after" && (step == "prepare-retire-proof-open" || step == "barrier-complete-open") ||
						edge == "before" && (step == "prepare-retire-proof-write" || step == "barrier-complete-write")
					if empty {
						lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
						return
					}
					a, err := open()
					must(t, err)
					defer a.Close()
					m.Before.Epoch = a.s.Epoch
					m.Before.Revision++
					m.Before.Lifecycle.OpenRevision = m.Before.Revision
					if !reflect.DeepEqual(&m.Before, a.s) {
						t.Fatal("recovery changed pending predecessor or minted receipt")
					}
					// Inert completion temps must never enter a later generic census.
					for _, name := range mustReadDirNames(t, filepath.Join(path, registryName)) {
						if strings.HasPrefix(name, "barrier-") && name != barrierName {
							t.Fatalf("prefix completion leaked generic candidate %s", name)
						}
					}
				})
			}
		}
	}
}

func TestPrepareRetirementRecoverySemanticPredicates(t *testing.T) {
	for _, mode := range []string{"other-retiring", "drained-target", "completed-prepare", "selected-copy-begun", "selected-copy-completed", "historical-copy-completed", "historical-copy-begun", "bad-receipt", "copy-replay"} {
		t.Run(mode, func(t *testing.T) {
			f, p := prepareRetirementImage(t)
			raw, err := os.ReadFile(registryFile(t, f, stateName))
			must(t, err)
			var s diskState
			must(t, json.Unmarshal(raw, &s))
			target := s.Attachments[p.Binding.Attachment]
			var other Attachment
			for id, rec := range s.Attachments {
				if id != target.Binding.Attachment {
					other = rec
				}
			}
			switch mode {
			case "other-retiring":
				other.Phase, other.Receipt = Retiring, nil
				s.Attachments[other.Binding.Attachment] = other
			case "drained-target", "completed-prepare":
				b := target.Binding
				r := Receipt{SchemaVersion, b.Store, b.Volume, b.Attachment, b.Launch, b.Prepare, s.Revision}
				target.Phase, target.Receipt = Drained, &r
				s.Attachments[b.Attachment] = target
				if mode == "completed-prepare" {
					prep := s.Prepares[b.Prepare]
					prep.Phase = Completed
					prep.Attestation = &Attestation{b.Prepare, true, true}
					s.Prepares[b.Prepare] = prep
				}
			case "selected-copy-begun", "selected-copy-completed", "historical-copy-completed", "historical-copy-begun":
				owner := target.Binding
				phase := CopyCompleted
				if strings.HasSuffix(mode, "-begun") {
					phase = CopyBegun
				}
				if strings.HasPrefix(mode, "historical-") {
					other.Binding.Role, other.Binding.Mode, other.Binding.Prepare = PrepareRole, ReadWrite, mustID(t)
					other.Receipt.Prepare = other.Binding.Prepare
					s.Attachments[other.Binding.Attachment] = other
					owner = other.Binding
					s.Prepares[owner.Prepare] = Prepare{ID: owner.Prepare, Attachments: []Binding{owner}, Phase: Pending, Context: &PrepareContext{s.Epoch, s.Controller.Epoch, s.Controller.Key}}
				}
				s.Copy.Intents[owner.Volume] = CopyIntent{ID: mustID(t), Owner: owner, Epoch: s.Epoch, Root: copyRoot(f, s.Volumes[owner.Volume]), Phase: phase}
			case "bad-receipt":
				other.Receipt.Revision = s.Revision + 1
				s.Attachments[other.Binding.Attachment] = other
			case "copy-replay":
				s.CopyReplay = map[ID]copyOperationRecord{target.Binding.Volume: {}}
			}
			// Updating the digest is insufficient: recovery must also enforce the
			// exact semantic predicates (all cases except these two are valid states).
			if mode != "bad-receipt" && mode != "copy-replay" {
				must(t, (&Authority{s: &s, limits: f.a.limits}).validate())
			}
			raw = retirementJSON(t, s)
			p.Prior = contentDigest(raw)
			must(t, os.WriteFile(registryFile(t, f, stateName), raw, 0600))
			must(t, os.WriteFile(registryFile(t, f, barrierName), retirementJSON(t, p), 0600))
			expected := ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}
			if mode == "historical-copy-completed" {
				f.a, err = f.openExpected(expected)
				must(t, err)
				got := f.a.s.Attachments[target.Binding.Attachment]
				if got.Phase != Retiring || got.Receipt != nil || f.a.s.Copy.Intents[other.Binding.Volume] != s.Copy.Intents[other.Binding.Volume] {
					t.Fatal("historical copy proof changed predecessor")
				}
			} else {
				retirementRefusesUnchanged(t, f, expected, nil)
			}
		})
	}
}

func TestPrepareRetirementRecoveryFailuresSticky(t *testing.T) {
	for _, failure := range []error{unix.EIO, unix.ENOSPC} {
		for _, step := range prepareRetirementRecoverySteps {
			t.Run(failure.Error()+"/"+step, func(t *testing.T) {
				f, p := prepareRetirementImage(t)
				cfg, err := configured(f.c)
				must(t, err)
				j, err := openJournal(cfg, false)
				must(t, err)
				s, err := j.load()
				must(t, err)
				a := &Authority{j: j, s: s, limits: cfg.Limits}
				must(t, a.validate())
				must(t, a.validatePrepareRetirementRecovery())
				reached := false
				j.fault = func(name string) error {
					if name == step {
						reached = true
						return failure
					}
					return nil
				}
				wantErr(t, j.recoverPrepareRetirement(), ErrRepairRequired)
				j.close()
				if !reached {
					t.Fatal("cleanup failure not reached")
				}
				retirementRefusesUnchanged(t, f, ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}, ErrRepairRequired)
			})
		}
	}
}

func mustReadDirNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	must(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
