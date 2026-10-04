package storageauthority

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func registryFile(t *testing.T, f *fixture, name string) string {
	t.Helper()
	return filepath.Join(f.path, registryName, name)
}

func journalFileAbsent(t *testing.T, f *fixture, name string) {
	t.Helper()
	if _, err := os.Stat(registryFile(t, f, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s removed, got %v", name, err)
	}
}

const uncertainMarkerText = "Uncertain authority IO or barrier: offline repair required.\n"

// captureLandedMetadataCommit saves the actual certificate after a workload
// rename and parent sync, before normal success removes it. Restoring these bytes
// models that exact crash cut, including its nonempty predecessor and same-E
// lifecycle/open anchor; it is not an initialization or cold-open certificate.
func captureLandedMetadataCommit(t *testing.T, f *fixture, commit func()) []byte {
	t.Helper()
	var proof []byte
	f.a.j.afterStep = func(step string) {
		if step == "state-parent-sync" {
			var err error
			proof, err = os.ReadFile(registryFile(t, f, commitProofName))
			must(t, err)
		}
	}
	defer func() { f.a.j.afterStep = nil }()
	commit()
	var decoded commitProof
	must(t, json.Unmarshal(proof, &decoded))
	if !decoded.Ready || decoded.Prior == "" || decoded.Prior == decoded.Next || decoded.Epoch != f.a.Epoch() {
		t.Fatal("workload producer did not emit a landed same-E certificate")
	}
	return proof
}

// craftLandedCrash installs a durable Ready certificate for an exact committed
// post-image. No legacy, data, barrier or known-error marker is present.
func craftLandedCrash(t *testing.T) (*fixture, Binding, Binding, ID) {
	t.Helper()
	f := newFixture(t, nil)
	v1, v2 := f.volume("one"), f.volume("two")
	p := mustID(t)
	b1, _ := f.binding(v1, PrepareRole, ReadWrite, p)
	b2, _ := f.binding(v2, PrepareRole, ReadWrite, p)
	data := captureLandedMetadataCommit(t, f, func() {
		must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p, []Binding{b1, b2}}))
	})
	must(t, f.a.Close())
	writeCrashWitness(t, filepath.Join(f.path, registryName), commitProofName, data)
	return f, b1, b2, p
}

// craftRollbackCrash performs two clean commits, then installs the durable
// crash state of a clean exit whose rename did not survive: the visible state
// is the exact predecessor bytes and the proof names them as Prior. A Ready
// certificate would also permit this outcome: publication may not have begun.
func craftRollbackCrash(t *testing.T) (*fixture, Binding, Binding) {
	t.Helper()
	f := newFixture(t, nil)
	v1, v2 := f.volume("one"), f.volume("two")
	p1 := mustID(t)
	b1, _ := f.binding(v1, PrepareRole, ReadWrite, p1)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p1, []Binding{b1}}))
	rawPrior, err := os.ReadFile(registryFile(t, f, stateName))
	must(t, err)
	var prior diskState
	must(t, json.Unmarshal(rawPrior, &prior))
	p2 := mustID(t)
	b2, _ := f.binding(v2, PrepareRole, ReadWrite, p2)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p2, []Binding{b2}}))
	rawNext, err := os.ReadFile(registryFile(t, f, stateName))
	must(t, err)
	must(t, f.a.Close())
	must(t, os.Remove(registryFile(t, f, stateName)))
	writeCrashWitness(t, filepath.Join(f.path, registryName), stateName, rawPrior)
	proof := commitProof{commitProofVersion, prior.Store.ID, prior.Epoch, prior.Revision + 1, contentDigest(rawPrior), contentDigest(rawNext), false}
	data, err := json.Marshal(proof)
	must(t, err)
	writeCrashWitness(t, filepath.Join(f.path, registryName), commitProofName, data)
	return f, b1, b2
}

func reopen(t *testing.T, f *fixture) {
	t.Helper()
	a, err := f.openCurrent()
	must(t, err)
	f.a = a
	f.control = f.authControl(f.controllerKey, 1)
}

// TestKnownIOFailureQuarantinesEveryPersistBoundary is the approved invariant:
// a returned EIO/ENOSPC/short-write at ANY persist boundary stays a sticky
// ErrRepairRequired across restart, pinned by the permanent quarantine marker.
func TestKnownIOFailureQuarantinesEveryPersistBoundary(t *testing.T) {
	for _, boundary := range persistBoundaries {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t, nil)
			v1, v2 := f.volume("one"), f.volume("two")
			p := mustID(t)
			b1, _ := f.binding(v1, PrepareRole, ReadWrite, p)
			b2, _ := f.binding(v2, PrepareRole, ReadWrite, p)
			fired := false
			f.a.j.fault = func(stage string) error {
				if stage == boundary && !fired {
					fired = true
					return unix.ENOSPC
				}
				return nil
			}
			wantErr(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p, []Binding{b1, b2}}), ErrBlocked)
			if !fired {
				t.Fatal("unreached injection")
			}
			f.a.j.fault = nil
			must(t, f.a.Close())
			if _, err := os.Stat(registryFile(t, f, quarantineName)); err != nil {
				t.Fatalf("known IO failure left no permanent quarantine marker: %v", err)
			}
			_, err := f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
			// Still blocked on a same-host retry: the quarantine marker is
			// never cleared automatically.
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
		})
	}
}

func TestProvableLandedCommitAutoRecovers(t *testing.T) {
	f, b1, _, p := craftLandedCrash(t)
	reopen(t, f)
	snap, err := f.a.Query(f.control)
	must(t, err)
	rec, ok := snap.Attachments[b1.Attachment]
	if !ok || rec.Binding.Prepare != p {
		t.Fatal("provably durable unacknowledged reservation lost")
	}
	if rec.Phase != Retiring {
		t.Fatalf("recovered attachment can admit: %s", rec.Phase)
	}
	journalFileAbsent(t, f, pendingName)
	journalFileAbsent(t, f, commitProofName)
	journalFileAbsent(t, f, quarantineName)
}

func TestProvableRollbackAutoRecovers(t *testing.T) {
	f, b1, b2 := craftRollbackCrash(t)
	reopen(t, f)
	snap, err := f.a.Query(f.control)
	must(t, err)
	if _, ok := snap.Attachments[b2.Attachment]; ok {
		t.Fatal("unacknowledged reservation survived a proven rollback")
	}
	if _, ok := snap.Attachments[b1.Attachment]; !ok {
		t.Fatal("durable predecessor reservation lost")
	}
	journalFileAbsent(t, f, pendingName)
	journalFileAbsent(t, f, commitProofName)
	journalFileAbsent(t, f, quarantineName)
}

// TestRecoveryCleanupFailureQuarantines: any IO failure during recovery
// cleanup quarantines the journal so the partial cleanup is never retried as
// clean crash uncertainty.
func TestRecoveryCleanupFailureQuarantines(t *testing.T) {
	for _, boundary := range []string{"recover-state-parent-sync", "recover-proof-unlink", "recover-proof-sync"} {
		t.Run(boundary, func(t *testing.T) {
			f, _, _, _ := craftLandedCrash(t)
			cfg, err := configured(f.c)
			must(t, err)
			j, err := openJournal(cfg, false)
			must(t, err)
			fired := false
			j.fault = func(stage string) error {
				if stage == boundary && !fired {
					fired = true
					return unix.EIO
				}
				return nil
			}
			err = j.recoverUncertainty()
			wantErr(t, err, ErrRepairRequired)
			j.fault = nil
			j.close()
			if !fired {
				t.Fatal("unreached injection")
			}
			if _, err := os.Stat(registryFile(t, f, quarantineName)); err != nil {
				t.Fatalf("failed recovery left no quarantine marker: %v", err)
			}
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
			if _, err := os.Stat(registryFile(t, f, pendingName)); err != nil {
				t.Fatalf("failed recovery destroyed the marker evidence: %v", err)
			}
		})
	}
}

// TestCleanRecoveryLeavesNoQuarantine: a successful recovery removes exactly
// the marker and proof and nothing else.
func TestCleanRecoveryLeavesNoQuarantine(t *testing.T) {
	f, _, _, _ := craftLandedCrash(t)
	cfg, err := configured(f.c)
	must(t, err)
	j, err := openJournal(cfg, false)
	must(t, err)
	must(t, j.recoverUncertainty())
	j.close()
	journalFileAbsent(t, f, pendingName)
	journalFileAbsent(t, f, commitProofName)
	journalFileAbsent(t, f, quarantineName)
}

func TestMarkerWithoutProofFailsClosedPreservesEvidence(t *testing.T) {
	f := newFixture(t, nil)
	must(t, f.a.Close())
	must(t, os.WriteFile(registryFile(t, f, pendingName), []byte(uncertainMarkerText), 0600))
	_, err := f.openCurrent()
	wantErr(t, err, ErrRepairRequired)
	if _, err := os.Stat(registryFile(t, f, pendingName)); err != nil {
		t.Fatalf("fail-closed recovery destroyed evidence: %v", err)
	}
	journalFileAbsent(t, f, quarantineName)
}

func TestDataAndBarrierMarkersNeverAutoRecover(t *testing.T) {
	for _, marker := range []string{pendingName, quarantineName, dataIOName, barrierName} {
		t.Run(marker, func(t *testing.T) {
			f, _, _, _ := craftLandedCrash(t)
			must(t, os.WriteFile(registryFile(t, f, marker), []byte("unresolved uncertainty"), 0600))
			_, err := f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
			for _, name := range []string{commitProofName, marker, stateName} {
				if _, err := os.Stat(registryFile(t, f, name)); err != nil {
					t.Fatalf("auto recovery touched %s: %v", name, err)
				}
			}
		})
	}
}

func TestReadyCertificateWithPriorImageAutoRecovers(t *testing.T) {
	f, b1, b2 := craftRollbackCrash(t)
	data, err := os.ReadFile(registryFile(t, f, commitProofName))
	must(t, err)
	var proof commitProof
	must(t, json.Unmarshal(data, &proof))
	proof.Ready = true
	data, err = json.Marshal(proof)
	must(t, err)
	must(t, os.WriteFile(registryFile(t, f, commitProofName), data, 0600))
	reopen(t, f)
	if _, ok := f.a.s.Attachments[b1.Attachment]; !ok {
		t.Fatal("durable predecessor lost")
	}
	if _, ok := f.a.s.Attachments[b2.Attachment]; ok {
		t.Fatal("unpublished successor fabricated")
	}
}

func TestReadableProofJSONAloneIsInsufficient(t *testing.T) {
	for _, missing := range []string{"ready", "predecessor"} {
		t.Run(missing, func(t *testing.T) {
			f, _, _, _ := craftLandedCrash(t)
			// Start from an actual producer certificate and remove just one proof.
			raw, err := os.ReadFile(registryFile(t, f, commitProofName))
			must(t, err)
			var proof commitProof
			must(t, json.Unmarshal(raw, &proof))
			if missing == "ready" {
				proof.Ready = false
			} else {
				proof.Prior = ""
			}
			must(t, os.WriteFile(registryFile(t, f, commitProofName), retirementJSON(t, proof), 0600))
			retirementRefusesUnchanged(t, f, expectedStartup(f), ErrRepairRequired)
		})
	}
}

func TestCorruptOrVersionedProofFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, f *fixture)
	}{
		{"garbage", func(t *testing.T, f *fixture) {
			must(t, os.WriteFile(registryFile(t, f, commitProofName), []byte("{"), 0600))
		}},
		{"future-version", func(t *testing.T, f *fixture) {
			var p commitProof
			data, err := os.ReadFile(registryFile(t, f, commitProofName))
			must(t, err)
			must(t, json.Unmarshal(data, &p))
			p.Version++
			data, err = json.Marshal(p)
			must(t, err)
			must(t, os.WriteFile(registryFile(t, f, commitProofName), data, 0600))
		}},
		{"neither-image-matches", func(t *testing.T, f *fixture) {
			// Well-formed certificates cannot authorize unrelated bytes.
			raw, err := os.ReadFile(registryFile(t, f, stateName))
			must(t, err)
			var s diskState
			must(t, json.Unmarshal(raw, &s))
			p := commitProof{commitProofVersion, s.Store.ID, s.Epoch, s.Revision + 1, contentDigest(append(raw, 1)), contentDigest(append(raw, 0)), true}
			data, err := json.Marshal(p)
			must(t, err)
			must(t, os.WriteFile(registryFile(t, f, commitProofName), data, 0600))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _, _ := craftLandedCrash(t)
			tc.mutate(t, f)
			_, err := f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
			if _, err := os.Stat(registryFile(t, f, commitProofName)); err != nil {
				t.Fatalf("evidence destroyed: %v", err)
			}
		})
	}
}

func TestOpenExpectedMismatchLeavesUncertaintyEvidence(t *testing.T) {
	f, _, _, _ := craftLandedCrash(t)
	expected := ExpectedStartup{Store: f.a.s.Store.ID, Epoch: f.a.s.Epoch, Controller: f.a.s.Controller}
	expected.Epoch = mustID(t)
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	_, err := f.openExpected(expected)
	wantErr(t, err, ErrConflict)
	// Expected identity mismatch mutates nothing, including uncertainty evidence.
	assertJournalContents(t, path, before)
}

func TestRecoveryPreservesAckedReceipt(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("acked")
	b, _ := f.runtime(v, ReadWrite)
	receipt := f.retire(b)
	v1, v2 := f.volume("one"), f.volume("two")
	p := mustID(t)
	b1, _ := f.binding(v1, PrepareRole, ReadWrite, p)
	b2, _ := f.binding(v2, PrepareRole, ReadWrite, p)
	data := captureLandedMetadataCommit(t, f, func() {
		must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p, []Binding{b1, b2}}))
	})
	must(t, f.a.Close())
	writeCrashWitness(t, filepath.Join(f.path, registryName), commitProofName, data)
	reopen(t, f)
	snap, err := f.a.Query(f.control)
	must(t, err)
	got, ok := snap.Attachments[b.Attachment]
	if !ok || got.Receipt == nil || *got.Receipt != receipt {
		t.Fatal("recovery lost an acknowledged drain receipt")
	}
	if _, ok := snap.Attachments[b1.Attachment]; !ok {
		t.Fatal("recovery lost the provably durable post-image")
	}
}

func TestRecoveryAdmitsOnlyAfterEpochAdvance(t *testing.T) {
	f, b1, _, _ := craftLandedCrash(t)
	reopen(t, f)
	if _, err := f.a.Admit(nil, b1.Volume, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nil principal admitted after recovery: %v", err)
	}
	// The recovered authority is fully operational: a fresh attachment on an
	// unrelated volume admits and releases normally.
	v := f.volume("live")
	_, p := f.runtime(v, ReadWrite)
	guard, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	guard.Release()
}
