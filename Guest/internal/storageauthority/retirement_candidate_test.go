//go:build linux || darwin

package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

var retirementCandidatePromotionBoundaries = []string{
	"recover-barrier-candidate-sync", "recover-barrier-candidate-close", "recover-barrier-candidate-rename",
}

func retirementCandidateImage(t *testing.T, landed bool) (*fixture, retirementProof, Receipt, string) {
	t.Helper()
	f, p, stable := retirementRecoveryImage(t, landed)
	must(t, os.Remove(registryFile(t, f, commitProofName)))
	must(t, os.WriteFile(registryFile(t, f, barrierName), []byte(uncertainMarkerText), 0600))
	name := "barrier-" + string(p.Attempt) + ".tmp"
	must(t, os.WriteFile(registryFile(t, f, name), retirementJSON(t, p), 0600))
	return f, p, stable, name
}

// The refusal census must not follow symlinks or block reading a FIFO. Include
// every name, byte and stable inode/security attribute, including temporaries.
func retirementJournalCensus(t *testing.T, path string) map[string]any {
	t.Helper()
	entries, err := os.ReadDir(path)
	must(t, err)
	out := make(map[string]any)
	for _, entry := range entries {
		name := filepath.Join(path, entry.Name())
		var st unix.Stat_t
		must(t, unix.Lstat(name, &st))
		var data []byte
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			data, err = os.ReadFile(name)
			must(t, err)
		case unix.S_IFLNK:
			target, e := os.Readlink(name)
			must(t, e)
			data = []byte(target)
		}
		out[entry.Name()] = struct {
			Mode, UID, GID       uint32
			Links, Device, Inode uint64
			Size                 int64
			Data                 string
		}{uint32(st.Mode), st.Uid, st.Gid, uint64(st.Nlink), uint64(st.Dev), uint64(st.Ino), st.Size, string(data)}
	}
	return out
}

func assertRetirementJournalCensus(t *testing.T, path string, before map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(before, retirementJournalCensus(t, path)) {
		t.Fatal("refused startup changed journal names, bytes or inode/security attributes")
	}
}

func TestRetirementCandidateRejectsUnprovenSources(t *testing.T) {
	for _, field := range []string{
		"missing", "empty", "truncated", "garbage", "version", "noncanonical", "unknown-field", "duplicate-field",
		"attempt", "filename-attempt", "filename-invalid", "multiple", "multiple-empty", "malformed-alongside", "scan-limit",
		"prior", "next", "digest-invalid", "store-root", "volume-root", "operation", "epoch", "controller",
		"binding", "revision", "successor", "metadata", "metadata-ready", "metadata-corrupt",
		"published-corrupt", "generic-not-exact", "pending", "data", "quarantine",
		"symlink", "hardlink", "fifo", "directory", "oversize", "public",
		"marker-symlink", "marker-hardlink", "marker-fifo", "marker-public", "marker-oversize",
	} {
		t.Run(field, func(t *testing.T) {
			f, p, _, name := retirementCandidateImage(t, field == "successor")
			expected := ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}
			candidate := registryFile(t, f, name)
			marker := registryFile(t, f, barrierName)
			switch field {
			case "version":
				p.Version++
			case "attempt":
				p.Attempt = "bad"
			case "filename-attempt":
				p.Attempt = mustID(t)
			case "prior":
				p.Prior = contentDigest([]byte("another prior"))
			case "next":
				p.Next = contentDigest([]byte("another next"))
			case "digest-invalid":
				p.Prior = "bad"
			case "store-root":
				p.Store.Root.Inode++
			case "volume-root":
				p.Volume.Root.Inode++
			case "operation":
				p.Operation = mustID(t)
			case "epoch":
				p.Epoch = mustID(t)
			case "controller":
				p.Controller.Epoch++
			case "binding":
				p.Binding.Launch = mustID(t)
			case "revision":
				p.Revision++
			}
			raw := retirementJSON(t, p)
			switch field {
			case "empty":
				raw = nil
			case "truncated":
				raw = raw[:len(raw)/2]
			case "garbage":
				raw = []byte("{")
			case "noncanonical":
				raw = append(raw, '\n')
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(",\"extra\":true}")...)
			case "duplicate-field":
				raw = append([]byte("{\"version\":1,"), raw[1:]...)
			case "oversize":
				raw = bytes.Repeat([]byte("x"), maxRetirementProofBytes+1)
			}
			must(t, os.WriteFile(candidate, raw, 0600))
			switch field {
			case "missing":
				must(t, os.Remove(candidate))
			case "filename-invalid":
				must(t, os.Rename(candidate, registryFile(t, f, "barrier-not-a-uuid.tmp")))
			case "multiple", "multiple-empty":
				other := p
				other.Attempt = mustID(t)
				data := retirementJSON(t, other)
				if field == "multiple-empty" {
					data = nil
				}
				must(t, os.WriteFile(registryFile(t, f, "barrier-"+string(other.Attempt)+".tmp"), data, 0600))
			case "malformed-alongside":
				must(t, os.WriteFile(registryFile(t, f, "barrier-not-a-uuid.tmp"), raw, 0600))
			case "scan-limit":
				entries, err := os.ReadDir(filepath.Join(f.path, registryName))
				must(t, err)
				for i := len(entries); i < 257; i++ {
					must(t, os.WriteFile(registryFile(t, f, fmt.Sprintf("unrelated-%03d", i)), nil, 0600))
				}
			case "metadata", "metadata-ready", "metadata-corrupt":
				meta := commitProof{commitProofVersion, p.Store.ID, p.Epoch, p.Revision, p.Prior, p.Next, field == "metadata-ready"}
				data := retirementJSON(t, meta)
				if field == "metadata-corrupt" {
					data = []byte("{")
				}
				must(t, os.WriteFile(registryFile(t, f, commitProofName), data, 0600))
			case "published-corrupt":
				must(t, os.WriteFile(marker, []byte("{\"version\":1}"), 0600))
			case "generic-not-exact":
				must(t, os.WriteFile(marker, []byte(uncertainMarkerText+"\n"), 0600))
			case "pending", "data", "quarantine":
				markerName := map[string]string{"pending": pendingName, "data": dataIOName, "quarantine": quarantineName}[field]
				must(t, os.WriteFile(registryFile(t, f, markerName), []byte(uncertainMarkerText), 0600))
			case "symlink", "hardlink", "fifo", "directory", "public", "marker-symlink", "marker-hardlink", "marker-fifo", "marker-public", "marker-oversize":
				target, kind := candidate, field
				if len(field) > 7 && field[:7] == "marker-" {
					target, kind = marker, field[7:]
				}
				switch kind {
				case "symlink", "hardlink":
					other := filepath.Join(f.path, "foreign-proof")
					must(t, os.Rename(target, other))
					if kind == "symlink" {
						must(t, os.Symlink(other, target))
					} else {
						must(t, os.Link(other, target))
					}
				case "fifo":
					must(t, os.Remove(target))
					must(t, unix.Mkfifo(target, 0600))
				case "directory":
					must(t, os.Remove(target))
					must(t, os.Mkdir(target, 0700))
				case "public":
					must(t, os.Chmod(target, 0644))
				case "oversize":
					must(t, os.WriteFile(target, bytes.Repeat([]byte("x"), maxRetirementProofBytes+1), 0600))
				}
			}
			retirementRefusesUnchanged(t, f, expected, ErrRepairRequired)
		})
	}
}

func TestRetirementCandidateGuardsPrecedePromotion(t *testing.T) {
	for _, field := range []string{"store", "epoch", "controller", "controller-key", "device", "bootstrap", "volume-root"} {
		t.Run(field, func(t *testing.T) {
			f, p, _, _ := retirementCandidateImage(t, false)
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
					t.Fatal("mismatched guard returned authority")
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

func TestRetirementCandidateStateValidationPrecedesPromotion(t *testing.T) {
	for _, field := range []string{"json", "schema", "missing-operation"} {
		t.Run(field, func(t *testing.T) {
			f, p, _, _ := retirementCandidateImage(t, false)
			path := registryFile(t, f, stateName)
			raw, err := os.ReadFile(path)
			must(t, err)
			var state diskState
			must(t, json.Unmarshal(raw, &state))
			switch field {
			case "json":
				raw = []byte("{")
			case "schema":
				state.Schema++
				raw = retirementJSON(t, state)
			case "missing-operation":
				delete(state.Operations, p.Operation)
				raw = retirementJSON(t, state)
			}
			must(t, os.WriteFile(path, raw, 0600))
			retirementRefusesUnchanged(t, f, ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}, nil)
		})
	}
}

func TestRetirementCandidateWithoutMarkerIsInert(t *testing.T) {
	f, p, _, name := retirementCandidateImage(t, false)
	must(t, os.Remove(registryFile(t, f, barrierName)))
	// Without the published barrier marker an old-epoch candidate is unbound.
	// Lifecycle startup must refuse it, not promote, consume or silently ignore it.
	p.Epoch = mustID(t)
	must(t, os.WriteFile(registryFile(t, f, name), retirementJSON(t, p), 0600))
	retirementRefusesUnchanged(t, f, expectedStartup(f), ErrRepairRequired)
}

func TestRetirementCandidatePromotionFailuresRemainSticky(t *testing.T) {
	for _, boundary := range append(append([]string{}, retirementCandidatePromotionBoundaries...), retirementCleanupBoundaries...) {
		for _, failure := range []error{unix.EIO, unix.ENOSPC} {
			t.Run(boundary+"/"+failure.Error(), func(t *testing.T) {
				f, p, _, _ := retirementCandidateImage(t, false)
				cfg, err := configured(f.c)
				must(t, err)
				j, err := openJournal(cfg, false)
				must(t, err)
				must(t, j.validateRetirementRecovery())
				reached := false
				j.fault = func(name string) error {
					if name == boundary {
						reached = true
						return failure
					}
					return nil
				}
				wantErr(t, j.recoverRetirement(), ErrRepairRequired)
				j.close()
				if !reached {
					t.Fatal("promotion fault not reached")
				}
				for _, name := range []string{pendingName, quarantineName} {
					if _, err := os.Stat(registryFile(t, f, name)); err != nil {
						t.Fatal("missing sticky marker", name, err)
					}
				}
				retirementRefusesUnchanged(t, f, ExpectedStartup{p.Store.ID, p.Epoch, p.Controller}, ErrRepairRequired)
			})
		}
	}
}

func TestRetirementCandidateWaitsForEntireBarrierAndAvailability(t *testing.T) {
	for _, poisoned := range []bool{false, true} {
		t.Run(fmt.Sprint(poisoned), func(t *testing.T) {
			f := newFixture(t, nil)
			b, _ := f.runtime(f.volume("target"), ReadWrite)
			entered, release := make(chan struct{}), make(chan struct{})
			f.a.barrier = func(_ Binding, root *os.File) error {
				if err := root.Sync(); err != nil {
					return err
				}
				close(entered)
				<-release
				return nil
			}
			req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
			done := make(chan error, 1)
			go func() { _, err := f.a.Retire(context.Background(), f.control, req); done <- err }()
			await(t, entered)
			assertNoRetirementCandidate := func() {
				entries, err := os.ReadDir(filepath.Join(f.path, registryName))
				must(t, err)
				for _, entry := range entries {
					if matched, _ := filepath.Match("barrier-*.tmp", entry.Name()); matched {
						t.Fatal("candidate preceded full barrier/availability", entry.Name())
					}
				}
			}
			assertNoRetirementCandidate()
			if poisoned {
				f.a.mu.Lock()
				_ = f.a.poison(unix.EIO)
				f.a.mu.Unlock()
			}
			close(release)
			err := <-done
			if poisoned {
				wantErr(t, err, ErrBlocked)
				assertNoRetirementCandidate()
				raw, err := os.ReadFile(registryFile(t, f, barrierName))
				must(t, err)
				if string(raw) != uncertainMarkerText {
					t.Fatal("later successful sync certified poisoned barrier")
				}
			} else {
				must(t, err)
			}
		})
	}
}

func TestRetirementCandidateReturnedIOFailuresRemainSticky(t *testing.T) {
	for _, boundary := range []string{"barrier-complete-write", "barrier-complete-sync", "barrier-complete-close", "barrier-complete-rename"} {
		for _, failure := range []error{unix.EIO, unix.ENOSPC} {
			t.Run(boundary+"/"+failure.Error(), func(t *testing.T) {
				f := newFixture(t, nil)
				b, _ := f.runtime(f.volume("target"), ReadWrite)
				reached := false
				f.a.j.fault = func(name string) error {
					if name == boundary {
						reached = true
						return failure
					}
					return nil
				}
				req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
				receipt, err := f.a.Retire(context.Background(), f.control, req)
				wantErr(t, err, ErrBlocked)
				if !reached || receipt != (Receipt{}) {
					t.Fatal("candidate IO failure acknowledged")
				}
				f.a.j.fault = nil
				expected := expectedStartup(f)
				must(t, f.a.Close())
				retirementRefusesUnchanged(t, f, expected, ErrRepairRequired)
			})
		}
	}
}

func TestRetirementCandidateSelectionAndPromotionOrder(t *testing.T) {
	f, p, _, name := retirementCandidateImage(t, false)
	// Reserved candidate spelling is exact: unrelated journal temporaries do
	// not compete, even when they happen to contain a syntactically valid proof.
	for _, decoy := range []string{"state-" + string(p.Attempt) + ".tmp", "proof-" + string(p.Attempt) + ".tmp", "other-" + string(p.Attempt) + ".tmp"} {
		must(t, os.WriteFile(registryFile(t, f, decoy), retirementJSON(t, p), 0600))
	}
	// Exactly the bounded census limit is allowed; 257 entries refuse above.
	entries, err := os.ReadDir(filepath.Join(f.path, registryName))
	must(t, err)
	for i := len(entries); i < 256; i++ {
		must(t, os.WriteFile(registryFile(t, f, fmt.Sprintf("unrelated-%03d", i)), nil, 0600))
	}
	cfg, err := configured(f.c)
	must(t, err)
	j, err := openJournal(cfg, false)
	must(t, err)
	defer j.close()
	if j.retirementCandidate != name {
		t.Fatal("loader did not record exact candidate basename")
	}
	must(t, j.validateRetirementRecovery())
	before, err := os.ReadFile(registryFile(t, f, stateName))
	must(t, err)
	var steps []string
	j.afterStep = func(step string) { steps = append(steps, step) }
	must(t, j.recoverRetirement())
	want := append(append([]string{}, retirementCandidatePromotionBoundaries...), retirementCleanupBoundaries...)
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("promotion ordering: got %v, want %v", steps, want)
	}
	after, err := os.ReadFile(registryFile(t, f, stateName))
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("promotion manufactured metadata/receipt")
	}
	for _, gone := range []string{name, barrierName} {
		if _, err := os.Lstat(registryFile(t, f, gone)); !os.IsNotExist(err) {
			t.Fatal("promotion retained evidence", gone, err)
		}
	}
}
