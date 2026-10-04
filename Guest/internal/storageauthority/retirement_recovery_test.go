//go:build linux || darwin

package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

var retirementCompletionBoundaries = []string{
	"barrier-complete-open", "barrier-complete-write", "barrier-complete-sync",
	"barrier-complete-close", "barrier-complete-rename", "barrier-complete-parent-sync",
}

var retirementCleanupBoundaries = []string{
	"recover-barrier-parent-sync", "recover-barrier-unlink", "recover-barrier-clear-sync",
}

func retirementJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	must(t, err)
	return raw
}

// Capture an actual completed barrier's proof and both exact images, then install
// a selected crash image after Close. Negative tests mutate only this evidence;
// the abrupt-exit tests below exercise publication without fixture rewriting.
func retirementRecoveryImage(t *testing.T, landed bool) (*fixture, retirementProof, Receipt) {
	t.Helper()
	f := newFixture(t, nil)
	stableBinding, _ := f.runtime(f.volume("stable"), ReadOnly)
	stable := f.retire(stableBinding)
	b, _ := f.runtime(f.volume("target"), ReadWrite)
	var proof retirementProof
	var prior []byte
	f.a.j.afterStep = func(name string) {
		if name == "barrier-complete-parent-sync" {
			raw, err := os.ReadFile(registryFile(t, f, barrierName))
			must(t, err)
			must(t, json.Unmarshal(raw, &proof))
			prior, err = os.ReadFile(registryFile(t, f, stateName))
			must(t, err)
		}
	}
	got := f.retire(b)
	if got != proof.receipt() || len(prior) == 0 {
		t.Fatal("did not capture the exact completed-barrier receipt")
	}
	f.a.j.afterStep = nil
	must(t, f.a.Close())
	if !landed {
		must(t, os.WriteFile(registryFile(t, f, stateName), prior, 0600))
	}
	must(t, os.WriteFile(registryFile(t, f, barrierName), retirementJSON(t, proof), 0600))
	meta := commitProof{commitProofVersion, proof.Store.ID, proof.Epoch, proof.Revision, proof.Prior, proof.Next, landed}
	must(t, os.WriteFile(registryFile(t, f, commitProofName), retirementJSON(t, meta), 0600))
	return f, proof, stable
}

// Census all journal bytes and names (including unpublished temporaries), not
// merely state.json. Repeated Open and OpenExpected must leave refusals inert.
func retirementRefusesUnchanged(t *testing.T, f *fixture, expected ExpectedStartup, want error) {
	t.Helper()
	path := filepath.Join(f.path, registryName)
	before := retirementJournalCensus(t, path)
	for range 2 {
		for _, guarded := range []bool{false, true} {
			var a *Authority
			var err error
			if guarded {
				a, err = f.openExpected(expected)
			} else {
				a, err = f.openCurrent()
			}
			if a != nil {
				_ = a.Close()
				t.Fatal("refused startup returned an authority")
			}
			if want != nil {
				wantErr(t, err, want)
			} else if err == nil {
				t.Fatal("invalid startup was accepted")
			}
			assertRetirementJournalCensus(t, path, before)
		}
	}
}

func TestRetirementRecoveryRejectsMismatchedProofWithoutCleanup(t *testing.T) {
	for _, field := range []string{
		"garbage", "version", "attempt", "epoch", "store", "store-root", "controller", "controller-key",
		"bootstrap", "volume", "volume-root", "binding-store", "binding-volume", "binding-attachment",
		"binding-launch", "binding-container", "binding-key", "binding-role", "binding-mode", "binding-prepare",
		"operation", "revision", "prior", "next", "unknown-field", "duplicate-field", "oversize",
		"unrelated-state", "changed-other-receipt", "unready-next", "metadata-pair",
	} {
		t.Run(field, func(t *testing.T) {
			f, p, stable := retirementRecoveryImage(t, true)
			expected := ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}
			switch field {
			case "version":
				p.Version++
			case "attempt":
				p.Attempt = "bad"
			case "epoch":
				p.Epoch = mustID(t)
			case "store":
				p.Store.ID = mustID(t)
			case "store-root":
				p.Store.Root.Inode++
			case "controller":
				p.Controller.Epoch++
			case "controller-key":
				p.Controller.Key = fp(t, newKey(t))
			case "bootstrap":
				p.Bootstrap = fp(t, newKey(t))
			case "volume":
				p.Volume.ID = mustID(t)
			case "volume-root":
				p.Volume.Root.Inode++
			case "binding-store":
				p.Binding.Store = mustID(t)
			case "binding-volume":
				p.Binding.Volume = mustID(t)
			case "binding-attachment":
				p.Binding.Attachment = stable.Attachment
			case "binding-launch":
				p.Binding.Launch = mustID(t)
			case "binding-container":
				p.Binding.Container = mustContainerID(t)
			case "binding-key":
				p.Binding.Key = fp(t, newKey(t))
			case "binding-role":
				p.Binding.Role = PrepareRole
			case "binding-mode":
				p.Binding.Mode = ReadOnly
			case "binding-prepare":
				p.Binding.Prepare = mustID(t)
			case "operation":
				p.Operation = mustID(t)
			case "revision":
				p.Revision++
			case "prior":
				p.Prior = contentDigest([]byte("wrong prior"))
			case "next":
				p.Next = contentDigest([]byte("wrong next"))
			case "unrelated-state", "changed-other-receipt":
				s := f.a.clone()
				if field == "unrelated-state" {
					s.Operations[mustID(t)] = digest("volume", VolumeRequest{mustID(t), p.Volume})
				} else {
					rec := s.Attachments[stable.Attachment]
					rec.Receipt.Revision--
					s.Attachments[stable.Attachment] = rec
				}
				// Even if the visible digest and metadata proof are updated, a
				// next image that changed unrelated evidence cannot match Prior.
				raw := retirementJSON(t, s)
				p.Next = contentDigest(raw)
				must(t, os.WriteFile(registryFile(t, f, stateName), raw, 0600))
				meta := commitProof{commitProofVersion, p.Store.ID, p.Epoch, p.Revision, p.Prior, p.Next, true}
				must(t, os.WriteFile(registryFile(t, f, commitProofName), retirementJSON(t, meta), 0600))
			case "unready-next", "metadata-pair":
				meta := commitProof{commitProofVersion, p.Store.ID, p.Epoch, p.Revision, p.Prior, p.Next, false}
				if field == "metadata-pair" {
					meta.Ready = true
					meta.Prior = contentDigest([]byte("another transaction"))
				}
				must(t, os.WriteFile(registryFile(t, f, commitProofName), retirementJSON(t, meta), 0600))
			}
			raw := retirementJSON(t, p)
			switch field {
			case "garbage":
				raw = []byte("{")
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(",\"unknown\":true}")...)
			case "duplicate-field":
				raw = append([]byte("{\"version\":1,"), raw[1:]...)
			case "oversize":
				raw = bytes.Repeat([]byte("x"), maxRetirementProofBytes+1)
			}
			must(t, os.WriteFile(registryFile(t, f, barrierName), raw, 0600))
			retirementRefusesUnchanged(t, f, expected, ErrRepairRequired)
		})
	}
}

func TestRetirementRecoveryPendingAndForeignMarkersStayInert(t *testing.T) {
	for _, name := range []string{barrierName, pendingName, dataIOName, quarantineName} {
		t.Run(name, func(t *testing.T) {
			f, p, _ := retirementRecoveryImage(t, true)
			must(t, os.WriteFile(registryFile(t, f, name), []byte(uncertainMarkerText), 0600))
			// A candidate proves only an exact RETIRING predecessor with no
			// metadata certificate. This landed image must remain refused.
			must(t, os.WriteFile(registryFile(t, f, "barrier-"+string(p.Attempt)+".tmp"), retirementJSON(t, p), 0600))
			retirementRefusesUnchanged(t, f, ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}, ErrRepairRequired)
		})
	}
}

func TestRetirementRecoveryGuardsPrecedeAllCleanup(t *testing.T) {
	for _, field := range []string{"store", "epoch", "controller", "controller-key", "device", "bootstrap", "volume-root"} {
		t.Run(field, func(t *testing.T) {
			f, p, _ := retirementRecoveryImage(t, true)
			expected := ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}
			switch field {
			case "store":
				expected.Store = mustID(t)
			case "epoch":
				expected.Epoch = mustID(t)
			case "controller":
				expected.Controller.Epoch++
			case "controller-key":
				expected.Controller.Key = fp(t, newKey(t))
			case "device":
				f.c.DeviceID += "-replacement"
			case "bootstrap":
				f.c.BootstrapKey = newKey(t).Public().(ed25519.PublicKey)
			case "volume-root":
				path := filepath.Join(f.path, "volumes", p.Volume.Name)
				must(t, os.Rename(path, path+"-old"))
				must(t, os.Mkdir(path, 0700))
			}
			path := filepath.Join(f.path, registryName)
			before := retirementJournalCensus(t, path)
			for range 2 {
				a, err := f.openExpected(expected)
				if a != nil {
					_ = a.Close()
					t.Fatal("guard returned authority")
				}
				if field == "bootstrap" {
					wantErr(t, err, ErrUnauthorized) // Signature verification precedes journal admission.
				} else {
					wantErr(t, err, ErrConflict)
				}
				assertRetirementJournalCensus(t, path, before)
			}
		})
	}
}

func TestRetirementRecoveryFailuresRemainSticky(t *testing.T) {
	stages := append([]string{"barrier-return", "barrier-panic", "barrier-close", "barrier-unlink", "barrier-clear-sync"}, retirementCompletionBoundaries...)
	stages = append(stages, persistBoundaries...)
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, nil)
			b, principal := f.runtime(f.volume("target"), ReadWrite)
			armed, reached := false, false
			f.a.barrier = func(_ Binding, root *os.File) error {
				armed = true
				switch stage {
				case "barrier-return":
					reached = true
					return unix.EIO
				case "barrier-panic":
					reached = true
					panic("retained resource failure")
				case "barrier-close":
					// A failed owned-handle close after successful sync is still
					// failure of the entire Barrier, not completion evidence.
					owned, err := dupDirectory(root)
					if err != nil {
						return err
					}
					if err = owned.Sync(); err != nil {
						return err
					}
					if err = owned.Close(); err != nil {
						return err
					}
					reached = true
					return owned.Close()
				}
				return nil
			}
			f.a.j.fault = func(name string) error {
				if armed && name == stage {
					reached = true
					return unix.ENOSPC
				}
				return nil
			}
			req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
			receipt, err := f.a.Retire(context.Background(), f.control, req)
			wantErr(t, err, ErrBlocked)
			if !reached || receipt != (Receipt{}) {
				t.Fatal("failure was not reached or acknowledged")
			}
			_, err = f.a.Admit(principal, b.Volume, true)
			wantErr(t, err, ErrBlocked)
			_, err = f.a.Retire(context.Background(), f.control, req)
			wantErr(t, err, ErrBlocked)
			if stage == "barrier-return" || stage == "barrier-panic" || stage == "barrier-close" {
				raw, err := os.ReadFile(registryFile(t, f, barrierName))
				must(t, err)
				if string(raw) != uncertainMarkerText {
					t.Fatal("failed barrier was certified")
				}
			}
			f.a.j.fault = nil
			expected := expectedStartup(f)
			must(t, f.a.Close())
			if _, err := os.Stat(registryFile(t, f, quarantineName)); err != nil {
				t.Fatal(err)
			}
			retirementRefusesUnchanged(t, f, expected, ErrRepairRequired)
		})
	}
}

func TestRetirementRecoveryCleanupFailuresRemainSticky(t *testing.T) {
	for _, stage := range retirementCleanupBoundaries {
		t.Run(stage, func(t *testing.T) {
			f, p, _ := retirementRecoveryImage(t, true)
			cfg, err := configured(f.c)
			must(t, err)
			j, err := openJournal(cfg, false)
			must(t, err)
			must(t, j.validateRetirementRecovery())
			must(t, j.recoverUncertainty())
			reached := false
			j.fault = func(name string) error {
				if name == stage {
					reached = true
					return unix.EIO
				}
				return nil
			}
			wantErr(t, j.recoverRetirement(), ErrRepairRequired)
			j.close()
			if !reached {
				t.Fatal("cleanup fault not reached")
			}
			retirementRefusesUnchanged(t, f, ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}, ErrRepairRequired)
		})
	}
}

func TestRetirementRecoveryTakeoverDuringPendingBarrier(t *testing.T) {
	f := newFixture(t, nil)
	b, _ := f.runtime(f.volume("target"), ReadWrite)
	entered, release := make(chan struct{}), make(chan struct{})
	f.a.barrier = func(Binding, *os.File) error { close(entered); <-release; return nil }
	var proof retirementProof
	var prior []byte
	f.a.j.afterStep = func(name string) {
		if name == "barrier-complete-parent-sync" {
			raw, err := os.ReadFile(registryFile(t, f, barrierName))
			must(t, err)
			must(t, json.Unmarshal(raw, &proof))
			prior, err = os.ReadFile(registryFile(t, f, stateName))
			must(t, err)
		}
	}
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	type result struct {
		receipt Receipt
		err     error
	}
	done := make(chan result, 1)
	go func() { r, err := f.a.Retire(context.Background(), f.control, req); done <- result{r, err} }()
	released := false
	defer func() {
		// Join retirement even when an assertion fails while its barrier is paused.
		if !released {
			close(release)
			<-done
		}
	}()
	await(t, entered)
	raw, err := os.ReadFile(registryFile(t, f, barrierName))
	must(t, err)
	if string(raw) != uncertainMarkerText {
		t.Fatal("pending barrier had completion proof")
	}
	wantErr(t, f.a.Close(), ErrBusy)
	key := newKey(t)
	successor, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	grant := f.takeoverGrant(1, fp(t, key))
	msg, err := LifecycleGrantSigningBytes(grant)
	must(t, err)
	current := f.a.clone()
	path := filepath.Join(f.path, registryName)
	before := retirementJournalCensus(t, path)
	signed := SignedLifecycleGrant{grant, ed25519.Sign(f.bootstrap, msg)}
	_, err = f.a.TakeoverLifecycle(successor, signed)
	wantErr(t, err, ErrRepairRequired)
	if !reflect.DeepEqual(current, f.a.clone()) {
		t.Fatal("refused takeover changed authority")
	}
	assertRetirementJournalCensus(t, path, before)
	controller := current.Controller
	after, err := os.ReadFile(registryFile(t, f, barrierName))
	must(t, err)
	if !bytes.Equal(raw, after) {
		t.Fatal("takeover rewrote pending barrier marker")
	}
	close(release)
	got := <-done
	released = true
	must(t, got.err)
	if proof.Controller != controller || proof.Prior != contentDigest(prior) || !bytes.Equal(prior, retirementJSON(t, current)) || got.receipt != proof.receipt() {
		t.Fatal("completion changed the refused-takeover predecessor/controller")
	}
	f.a.j.afterStep = nil
	must(t, f.a.Close())
	must(t, os.WriteFile(registryFile(t, f, barrierName), retirementJSON(t, proof), 0600))
	f.c.Barrier = func(Binding, *os.File) error { t.Fatal("recovery repeated completed barrier"); return nil }
	a, err := f.openExpected(ExpectedStartup{proof.Store.ID, proof.Epoch, controller})
	must(t, err)
	f.a = a
	f.control = f.authControl(f.controllerKey, controller.Epoch)
	if !reflect.DeepEqual(current.Operations, a.s.Operations) || a.s.Controller != controller {
		t.Fatal("recovery changed workload history or controller")
	}
	// Only the clean, drained/recovered namespace admits the real signed takeover.
	successor, err = a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	oldControl := f.control
	controller, err = a.TakeoverLifecycle(successor, signed)
	must(t, err)
	if controller != (Controller{2, fp(t, key)}) {
		t.Fatal("wrong successor", controller)
	}
	_, err = a.Query(oldControl)
	wantErr(t, err, ErrUnauthorized)
	f.controllerKey = key
	f.control = f.authControl(key, controller.Epoch)
	retry, err := a.Retire(context.Background(), f.control, req)
	must(t, err)
	if retry != got.receipt {
		t.Fatal("takeover/reopen changed exact receipt")
	}
	_, err = os.Stat(registryFile(t, f, barrierName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovered marker survived", err)
	}
}
