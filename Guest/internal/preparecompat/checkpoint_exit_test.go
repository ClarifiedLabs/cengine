package preparecompat

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// checkpointVector builds the real full-profile claim for one of the seven
// cuts straight from its generated full-vectors row: the physical
// Observation (NORMAL/A7), the early EarlyObservation (A1/A2/A3), or the
// storage StorageObservation (A6/A8). No synthetic physical fixture is ever
// produced for the early cuts.
func checkpointVector(t *testing.T, stage string) WorkerCheckpointExit {
	t.Helper()
	raw, err := os.ReadFile("testdata/full-vectors.json")
	if err != nil {
		t.Skip(err)
	}
	var rows []struct {
		Name        json.RawMessage `json:"name"`
		Arm         Arm             `json:"arm"`
		Observation json.RawMessage `json:"observation"`
	}
	if json.Unmarshal(raw, &rows) != nil {
		t.Fatal("vectors")
	}
	for i := range rows {
		var name string
		if json.Unmarshal(rows[i].Name, &name) != nil || name != stage {
			continue
		}
		e := WorkerCheckpointExit{Arm: rows[i].Arm}
		switch checkpointExitKind(stage) {
		case "physical":
			var o Observation
			if json.Unmarshal(rows[i].Observation, &o) != nil {
				t.Fatal("physical fixture")
			}
			e.Checkpoint = &o
			e.WorkerUUID = rows[i].Arm.RequestID
		case "early":
			var o EarlyObservation
			if json.Unmarshal(rows[i].Observation, &o) != nil {
				t.Fatal("early fixture")
			}
			e.EarlyCheckpoint = &o
			e.WorkerUUID = rows[i].Arm.RequestID
		case "storage":
			var o StorageObservation
			if json.Unmarshal(rows[i].Observation, &o) != nil {
				t.Fatal("storage fixture")
			}
			e.StorageCheckpoint = &o
			e.WorkerUUID = o.WorkerUUID // the observation's own bound worker
		default:
			t.Fatal("no fixture kind", stage)
		}
		return e
	}
	t.Fatal("missing vector row", stage)
	return WorkerCheckpointExit{}
}

func TestWorkerCheckpointExitCutGates(t *testing.T) {
	cuts := []string{"normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "first-child-published", "transaction-published-bind-reply-lost", "drain-durable-reply-lost"}
	for _, stage := range cuts {
		t.Run(stage, func(t *testing.T) {
			e := checkpointVector(t, stage)
			if !CheckpointExitCut(stage) {
				t.Fatal("cut not registered")
			}
			if CurrentProfile() != FullProfile {
				if ValidateWorkerCheckpointExit(e) == nil {
					t.Fatal("activated without full profile")
				}
				return
			}
			if ValidateWorkerCheckpointExit(e) != nil {
				t.Fatal("cut rejected")
			}
			raw, err := CanonicalJSON(e)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeWorkerCheckpointExit(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A4/A5 admission cuts, VM cases and IO cuts stay on their own paths.
	for _, stage := range []string{"full-frame-before-admit", "admitted-queued", "vm-two-volume-drain-reply-gap", "vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed"} {
		e := checkpointVector(t, "normal")
		e.Arm.CaseName = stage // the stage gate rejects before any structural repair
		if CheckpointExitCut(stage) || ValidateWorkerCheckpointExit(e) == nil {
			t.Fatal("non-cut admitted", stage)
		}
	}
	if CurrentProfile() != FullProfile {
		e := checkpointVector(t, "normal")
		if ValidateWorkerCheckpointExit(e) == nil {
			t.Fatal("activated without full profile")
		}
	}
}

func TestWorkerCheckpointExitUnionExactlyOne(t *testing.T) {
	physical := checkpointVector(t, "normal")
	early := checkpointVector(t, "data-partial-frame")
	storage := checkpointVector(t, "transaction-published-bind-reply-lost")
	// Zero or two carriers never validate, whatever the stage.
	zero := physical
	zero.Checkpoint = nil
	if ValidateWorkerCheckpointExit(zero) == nil {
		t.Fatal("empty union admitted")
	}
	dual := physical
	dual.EarlyCheckpoint = early.EarlyCheckpoint
	if ValidateWorkerCheckpointExit(dual) == nil {
		t.Fatal("two carriers admitted")
	}
	// The carrier kind must match the arm's case.
	wrongKind := physical
	wrongKind.Checkpoint, wrongKind.StorageCheckpoint = nil, storage.StorageCheckpoint
	if ValidateWorkerCheckpointExit(wrongKind) == nil {
		t.Fatal("wrong carrier kind admitted")
	}
	earlyWithPhysical := checkpointVector(t, "guest-accepted-before-prepare")
	earlyWithPhysical.Checkpoint = physical.Checkpoint
	if ValidateWorkerCheckpointExit(earlyWithPhysical) == nil {
		t.Fatal("physical carrier on early cut admitted")
	}
}

func TestValidateObservationForArmBindsActualGuestCheckpoint(t *testing.T) {
	e := checkpointVector(t, "normal")
	if ValidateObservationForArm(*e.Checkpoint, e.Arm) != nil {
		t.Fatal("actual checkpoint rejected")
	}
	for name, mutate := range map[string]func(*WorkerCheckpointExit){
		"digest": func(x *WorkerCheckpointExit) { x.Checkpoint.ArmDigest = strings.Repeat("f", 64) },
		"request": func(x *WorkerCheckpointExit) {
			x.Checkpoint.RequestID = strings.Repeat("a", 8) + x.Checkpoint.RequestID[8:]
		},
		"stage": func(x *WorkerCheckpointExit) { x.Checkpoint.Stage = "vm-root-synced-before-cleanup" },
		"target": func(x *WorkerCheckpointExit) {
			x.Checkpoint.TargetAttachment = strings.Repeat("b", 8) + x.Checkpoint.TargetAttachment[8:]
		},
		"count":     func(x *WorkerCheckpointExit) { x.Checkpoint.Count = 2 },
		"root-type": func(x *WorkerCheckpointExit) { x.Checkpoint.Root.FileType = 32768 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := e
			mutate(&bad)
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("unbound checkpoint admitted")
			}
		})
	}
	bad := e
	bad.Arm.TargetAttachment = strings.Repeat("c", 8) + bad.Arm.TargetAttachment[8:]
	if ValidateWorkerCheckpointExit(bad) == nil {
		t.Fatal("arm tamper admitted")
	}
}

func TestValidateEarlyObservationForArmBindsActualEarlyCheckpoint(t *testing.T) {
	for _, stage := range []string{"before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame"} {
		t.Run(stage, func(t *testing.T) {
			e := checkpointVector(t, stage)
			if e.Checkpoint != nil || e.EarlyCheckpoint == nil || ValidateEarlyObservationForArm(*e.EarlyCheckpoint, e.Arm) != nil {
				t.Fatal("early fixture shape")
			}
			if ValidateEarlyObservationForArm(*e.EarlyCheckpoint, e.Arm) != nil {
				t.Fatal("actual early checkpoint rejected")
			}
			if CurrentProfile() != FullProfile {
				return
			}
			if ValidateWorkerCheckpointExit(e) != nil {
				t.Fatal("early claim rejected")
			}
			bad := e
			bad.EarlyCheckpoint.Stage = "normal"
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("early stage mismatch admitted")
			}
			bad = e
			bad.EarlyCheckpoint.ArmDigest = strings.Repeat("f", 64)
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("early digest mismatch admitted")
			}
			bad = e
			bad.EarlyCheckpoint.RequestSequence = 0
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("early sequence mismatch admitted")
			}
			bad = e
			bad.EarlyCheckpoint.DataBytesWritten++
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("early counter tamper admitted")
			}
		})
	}
}

func TestValidateStorageCheckpointBindsActualBoundDrainObservation(t *testing.T) {
	for _, stage := range []string{"transaction-published-bind-reply-lost", "drain-durable-reply-lost"} {
		t.Run(stage, func(t *testing.T) {
			e := checkpointVector(t, stage)
			if e.StorageCheckpoint == nil || ValidateStorageObservationForArm(*e.StorageCheckpoint, StorageArm{Arm: e.Arm, WorkerUUID: e.WorkerUUID}) != nil {
				t.Fatal("storage fixture not arm-bound")
			}
			if CurrentProfile() != FullProfile {
				return
			}
			if ValidateWorkerCheckpointExit(e) != nil {
				t.Fatal("storage claim rejected")
			}
			bad := e
			bad.StorageCheckpoint.Stage = "admitted-queued"
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("admission stage admitted on checkpoint route")
			}
			bad = e
			bad.StorageCheckpoint.ArmDigest = strings.Repeat("f", 64)
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("digest mismatch admitted")
			}
			bad = e
			bad.StorageCheckpoint.Count = 2
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("count tamper admitted")
			}
			bad = e
			bad.StorageCheckpoint.Admission = &AdmissionCut{RequestSequence: 1, Admitted: true, ReleaseToken: strings.Repeat("e", 64)}
			if ValidateWorkerCheckpointExit(bad) == nil {
				t.Fatal("fabricated admission admitted")
			}
		})
	}
}

func TestWorkerCheckpointWaitAndClosedCodec(t *testing.T) {
	for _, stage := range []string{"normal", "data-partial-frame", "drain-durable-reply-lost"} {
		t.Run(stage, func(t *testing.T) {
			e := checkpointVector(t, stage)
			wait := WorkerCheckpointWait{Arm: e.Arm, Checkpoint: e.Checkpoint, EarlyCheckpoint: e.EarlyCheckpoint, StorageCheckpoint: e.StorageCheckpoint, WorkerUUID: e.WorkerUUID, WorkerPID: 42, ExitCode: 74, Reaped: true}
			if CurrentProfile() != FullProfile {
				if ValidateWorkerCheckpointWait(wait) == nil || ValidateWorkerCheckpointWaitForArm(wait, e) == nil {
					t.Fatal("activated without full profile")
				}
				return
			}
			if ValidateWorkerCheckpointWait(wait) != nil || ValidateWorkerCheckpointWaitForArm(wait, e) != nil {
				t.Fatal("valid wait rejected")
			}
			for name, mutate := range map[string]func(*WorkerCheckpointWait){
				"pid-zero":   func(w *WorkerCheckpointWait) { w.WorkerPID = 0 },
				"pid-one":    func(w *WorkerCheckpointWait) { w.WorkerPID = 1 },
				"pid-high":   func(w *WorkerCheckpointWait) { w.WorkerPID = 1 << 31 },
				"code":       func(w *WorkerCheckpointWait) { w.ExitCode = 0 },
				"not-reaped": func(w *WorkerCheckpointWait) { w.Reaped = false },
				"worker":     func(w *WorkerCheckpointWait) { w.WorkerUUID = e.WorkerUUID[:35] + "e" },
				"arm-case":   func(w *WorkerCheckpointWait) { w.Arm.CaseName = "admitted-queued" },
				"claim":      func(w *WorkerCheckpointWait) { w.Checkpoint = nil; w.EarlyCheckpoint = &EarlyObservation{} },
			} {
				t.Run(name, func(t *testing.T) {
					bad := wait
					mutate(&bad)
					if ValidateWorkerCheckpointWait(bad) == nil && ValidateWorkerCheckpointWaitForArm(bad, e) == nil {
						t.Fatal("fabricated wait admitted")
					}
				})
			}
			raw, err := CanonicalJSON(wait)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeWorkerCheckpointWait(raw); err != nil {
				t.Fatal(err)
			}
			// Duplicate, unknown and null JSON keys stay closed.
			wire := bytes.Replace(raw, []byte(`"workerPID":42`), []byte(`"workerPID":42,"workerPID":42`), 1)
			if _, err := DecodeWorkerCheckpointWait(wire); err == nil {
				t.Fatal("duplicate key")
			}
			wire = bytes.Replace(raw, []byte(`"reaped":true`), []byte(`"reaped":true,"extra":1`), 1)
			if _, err := DecodeWorkerCheckpointWait(wire); err == nil {
				t.Fatal("unknown key")
			}
			wire = bytes.Replace(raw, []byte(`"reaped":true`), []byte(`"reaped":null`), 1)
			if _, err := DecodeWorkerCheckpointWait(wire); err == nil {
				t.Fatal("null key")
			}
		})
	}
}
