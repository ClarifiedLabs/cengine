//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
)

// checkpointServiceClaim adapts the generated full-vectors fixture to the
// freshly issued arm: same shape, rebound digest/request/target. Guest cuts
// carry the physical Observation or early EarlyObservation; A6/A8 carry the
// storage StorageObservation. No Admission is ever fabricated.
func checkpointServiceClaim(t *testing.T, arm pc.StorageArm, stage string) pc.WorkerCheckpointExit {
	t.Helper()
	raw, err := os.ReadFile("../preparecompat/testdata/full-vectors.json")
	must(t, err)
	var rows []struct {
		Name        string          `json:"name"`
		Observation json.RawMessage `json:"observation"`
	}
	must(t, json.Unmarshal(raw, &rows))
	for i := range rows {
		if rows[i].Name != stage {
			continue
		}
		digest, err := pc.ArmDigest(arm.Arm)
		must(t, err)
		e := pc.WorkerCheckpointExit{Arm: arm.Arm, WorkerUUID: arm.WorkerUUID}
		switch stage {
		case "normal", "first-child-published":
			var o pc.Observation
			must(t, json.Unmarshal(rows[i].Observation, &o))
			o.ArmDigest, o.RequestID, o.TargetAttachment = digest, arm.Arm.RequestID, arm.Arm.TargetAttachment
			e.Checkpoint = &o
		case "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame":
			var o pc.EarlyObservation
			must(t, json.Unmarshal(rows[i].Observation, &o))
			o.ArmDigest, o.RequestID, o.TargetAttachment = digest, arm.Arm.RequestID, arm.Arm.TargetAttachment
			e.EarlyCheckpoint = &o
		default:
			var o pc.StorageObservation
			must(t, json.Unmarshal(rows[i].Observation, &o))
			e.StorageCheckpoint = &o // fixture worker/digest do not match this arm; A6/A8 claims must fail closed pre-install
		}
		return e
	}
	t.Fatal("missing vector row", stage)
	return pc.WorkerCheckpointExit{}
}

func TestCheckpointExitServiceClaimAuthorityAndOneShot(t *testing.T) {
	for _, stage := range []string{"normal", "data-partial-frame", "transaction-published-bind-reply-lost"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			arm := fullServicePrepare(t, f, stage, true)
			claim := checkpointServiceClaim(t, arm, stage)
			storageCut := stage == "transaction-published-bind-reply-lost"
			if storageCut {
				// No installed compatibility retains an actual Bound/Drain
				// observation: fail closed, never fabricate an admission or
				// advance state. (A positive match requires the real authority
				// copy lifecycle and stays with the authority host tests.)
				if _, err := f.s.ClaimPrepareCompatibilityCheckpointExit(claim); err == nil {
					t.Fatal("unarmed storage claim admitted")
				}
				return
			}
			if pc.ValidateWorkerCheckpointExit(claim) != nil {
				t.Fatal("rebound fixture")
			}
			// Current-identity mismatches reject without consuming the claim.
			for name, mutate := range map[string]func(*pc.WorkerCheckpointExit){
				"worker":     func(e *pc.WorkerCheckpointExit) { e.WorkerUUID = string(id(t)) },
				"key":        func(e *pc.WorkerCheckpointExit) { e.Arm.Credentials[0].Key = strings.Repeat("c", 64) },
				"controller": func(e *pc.WorkerCheckpointExit) { e.Arm.Scope.ControllerEpoch++ },
				"epoch":      func(e *pc.WorkerCheckpointExit) { e.Arm.Scope.ServiceEpoch = string(id(t)) },
				"store":      func(e *pc.WorkerCheckpointExit) { e.Arm.Scope.Store = string(id(t)) },
				"carrier": func(e *pc.WorkerCheckpointExit) {
					e.EarlyCheckpoint = &pc.EarlyObservation{}
					e.Checkpoint = nil
				},
			} {
				t.Run(name, func(t *testing.T) {
					bad := claim
					// deep-copy the arm so slot/credential mutations stay local
					bad.Arm.Credentials = append([]pc.Credential{}, claim.Arm.Credentials...)
					mutate(&bad)
					if _, err := f.s.ClaimPrepareCompatibilityCheckpointExit(bad); err == nil {
						t.Fatal("mismatch admitted")
					}
				})
			}
			ack, err := f.s.ClaimPrepareCompatibilityCheckpointExit(claim)
			if err != nil || !pc.SameWorkerCheckpointClaim(ack, claim) {
				t.Fatal("valid claim rejected", err)
			}
			if _, err := f.s.ClaimPrepareCompatibilityCheckpointExit(claim); err == nil {
				t.Fatal("claim replay admitted")
			}
		})
	}
}
