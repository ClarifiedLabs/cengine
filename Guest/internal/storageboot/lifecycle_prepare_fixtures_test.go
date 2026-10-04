package storageboot

import (
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/storageworker"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func storageArmVector(t *testing.T) pc.StorageArm {
	t.Helper()
	raw, err := os.ReadFile("../preparecompat/testdata/vectors.json")
	must(t, err)
	var v []struct{ Arm pc.Arm }
	must(t, json.Unmarshal(raw, &v))
	arm := v[0].Arm
	arm.Version, arm.Profile, arm.CaseName = 3, pc.FullProfile, "admitted-queued"
	return pc.StorageArm{Arm: arm, WorkerUUID: arm.RequestID}
}
func consumerVector(t *testing.T) cc.Arm {
	a := storageArmVector(t)
	s := a.Arm.Scope
	slot := a.Arm.Slots[0]
	credential := a.Arm.Credentials[0]
	return cc.Arm{Version: 3, Profile: cc.Profile, RequestID: a.Arm.RequestID, ArmDigest: strings.Repeat("a", 64), OperationUUID: a.Arm.RequestID, CaseName: cc.SameE, OriginalBootBinding: cc.BootBinding{ShimLaunchUUID: s.Launch, GuestBootNonce: a.Arm.Binding.GuestBootNonce}, Original: cc.Original{Epoch: s.ServiceEpoch, Binding: cc.RuntimeBinding{Store: s.Store, Volume: slot.Volume, Attachment: slot.Attachment, Container: s.Container, Launch: s.Launch, Key: credential.Key, Role: "runtime", Mode: "read-write"}}, OriginalLeafSHA256: credential.CertificateSHA256, WorkerScope: cc.WorkerScope{StoreUUID: s.Store, ServiceEpoch: s.ServiceEpoch, WorkerUUID: a.WorkerUUID}}
}
func workerExitFramesForStage(t *testing.T, stage string) (*LifecycleFrame, *LifecycleFrame) {
	t.Helper()
	arm := storageArmVector(t)
	q, err := pc.StorageQueryForArm(arm)
	must(t, err)
	accepted, admitted := uint32(0), false
	if stage == "admitted-queued" {
		accepted, admitted = 1, true
	}
	seq := uint64(11)
	request := lifecycleFrame("command", bindingFixture())
	request.Sequence = &seq
	request.ServiceEpoch, request.WorkerUUID = arm.Arm.Scope.ServiceEpoch, q.WorkerUUID
	request.Command = "prepare-compatibility-worker-exit"
	request.PrepareCompatibilityWorkerExit = &pc.StorageRelease{Query: q, Stage: stage, Token: strings.Repeat("e", 64)}
	reply := lifecycleFrame("reply", request.Binding)
	reply.Sequence = &seq
	reply.ServiceEpoch, reply.WorkerUUID = request.ServiceEpoch, request.WorkerUUID
	reply.PrepareCompatibilityStatus = &pc.StorageStatus{Query: q, State: "observed", AcceptedInFlight: accepted, Observation: &pc.StorageObservation{Version: 3, Profile: pc.FullProfile, RequestID: q.RequestID, ArmDigest: q.ArmDigest, WorkerUUID: q.WorkerUUID, Stage: stage, Count: 1, TargetAttachment: arm.Arm.TargetAttachment, Admission: &pc.AdmissionCut{RequestSequence: 37, Admitted: admitted, ReleaseToken: strings.Repeat("e", 64)}}}
	return &request, &reply
}

func workerExitFrames(t *testing.T) (*LifecycleFrame, *LifecycleFrame) {
	return workerExitFramesForStage(t, "admitted-queued")
}

func TestWorkerExitProcess(t *testing.T) {
	switch os.Getenv("CENGINE_GUEST_WORKER_EXIT_TEST") {
	case "74":
		os.Exit(74)
	case "0":
		os.Exit(0)
	}
}

func realWorkerExitResult(t *testing.T, code string) (int, storageworker.WaitResult) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerExitProcess$")
	cmd.Env = append(os.Environ(), "CENGINE_GUEST_WORKER_EXIT_TEST="+code)
	must(t, cmd.Start())
	pid := cmd.Process.Pid
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if cmd.ProcessState == nil || (err != nil && !errors.As(err, &exitErr)) {
		t.Fatal("not real Wait", err)
	}
	return pid, storageworker.WaitResult{Reaped: true, State: cmd.ProcessState, Err: err}
}

func TestWorkerWaitRequiresActualReapedExitAndOwnedPID(t *testing.T) {
	pid, result := realWorkerExitResult(t, "74")
	request, _ := workerExitFrames(t)
	wait, err := projectWorkerWait(*request.PrepareCompatibilityWorkerExit, 37, pid, result, true)
	must(t, err)
	if wait.WorkerPID != uint32(pid) || wait.ExitCode != 74 || !wait.Reaped {
		t.Fatal(wait)
	}
	_, zero := realWorkerExitResult(t, "0")
	for _, bad := range []struct {
		pid      int
		r        storageworker.WaitResult
		observed bool
	}{
		{pid, result, false}, {pid, storageworker.WaitResult{}, true}, {pid, storageworker.WaitResult{State: result.State, Err: result.Err}, true},
		{pid + 1, result, true}, {1, result, true}, {pid, zero, true}, {pid, storageworker.WaitResult{Reaped: true, State: result.State, Err: io.ErrUnexpectedEOF}, true},
	} {
		if _, err := projectWorkerWait(*request.PrepareCompatibilityWorkerExit, 37, bad.pid, bad.r, bad.observed); err == nil {
			t.Fatal("fabricated wait")
		}
	}
}
func checkpointExitFramesForStage(t *testing.T, stage string) (*LifecycleFrame, *LifecycleFrame) {
	t.Helper()
	raw, err := os.ReadFile("../preparecompat/testdata/full-vectors.json")
	must(t, err)
	var rows []struct {
		Name        string          `json:"name"`
		Arm         pc.Arm          `json:"arm"`
		Observation json.RawMessage `json:"observation"`
	}
	must(t, json.Unmarshal(raw, &rows))
	for i := range rows {
		if rows[i].Name != stage {
			continue
		}
		exit := pc.WorkerCheckpointExit{Arm: rows[i].Arm}
		switch {
		case stage == "normal" || stage == "first-child-published":
			var o pc.Observation
			must(t, json.Unmarshal(rows[i].Observation, &o))
			exit.Checkpoint = &o
			exit.WorkerUUID = rows[i].Arm.RequestID
		case stage == "before-prepare-send" || stage == "guest-accepted-before-prepare" || stage == "data-partial-frame":
			var o pc.EarlyObservation
			must(t, json.Unmarshal(rows[i].Observation, &o))
			exit.EarlyCheckpoint = &o
			exit.WorkerUUID = rows[i].Arm.RequestID
		default:
			var o pc.StorageObservation
			must(t, json.Unmarshal(rows[i].Observation, &o))
			exit.StorageCheckpoint = &o
			exit.WorkerUUID = o.WorkerUUID // the observation's own bound worker
		}
		if pc.CurrentProfile() == pc.FullProfile && pc.ValidateWorkerCheckpointExit(exit) != nil {
			t.Fatal("vector claim")
		}
		seq := uint64(11)
		request := lifecycleFrame("command", bindingFixture())
		request.Sequence = &seq
		request.ServiceEpoch, request.WorkerUUID = exit.Arm.Scope.ServiceEpoch, exit.WorkerUUID
		request.Command = "prepare-compatibility-checkpoint-exit"
		request.PrepareCompatibilityCheckpointExit = &exit
		ack := exit // distinct value: ACK mutations must not rewrite the request
		reply := lifecycleFrame("reply", request.Binding)
		reply.Sequence = &seq
		reply.ServiceEpoch, reply.WorkerUUID = request.ServiceEpoch, request.WorkerUUID
		reply.PrepareCompatibilityCheckpointAck = &ack
		return &request, &reply
	}
	t.Fatal("missing vector row", stage)
	return nil, nil
}

func checkpointExitFrames(t *testing.T) (*LifecycleFrame, *LifecycleFrame) {
	return checkpointExitFramesForStage(t, "normal")
}

var checkpointExitStages = []string{"normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "first-child-published", "transaction-published-bind-reply-lost", "drain-durable-reply-lost"}

func checkpointExitTamperValue(e *pc.WorkerCheckpointExit) {
	switch {
	case e.Checkpoint != nil:
		e.Checkpoint.Count = 2
	case e.EarlyCheckpoint != nil:
		e.EarlyCheckpoint.Count = 2
	case e.StorageCheckpoint != nil:
		e.StorageCheckpoint.Count = 2
	}
}

func TestCheckpointWaitRequiresActualReapedExitAndOwnedPID(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile only")
	}
	for _, stage := range []string{"normal", "data-partial-frame", "drain-durable-reply-lost"} {
		t.Run(stage, func(t *testing.T) {
			pid, result := realWorkerExitResult(t, "74")
			request, _ := checkpointExitFramesForStage(t, stage)
			wait, err := projectCheckpointWait(*request.PrepareCompatibilityCheckpointExit, pid, result, true)
			must(t, err)
			if wait.WorkerPID != uint32(pid) || wait.ExitCode != 74 || !wait.Reaped {
				t.Fatal(wait)
			}
			if pc.ValidateWorkerCheckpointWaitForArm(*wait, *request.PrepareCompatibilityCheckpointExit) != nil {
				t.Fatal("wait does not match full request")
			}
			_, zero := realWorkerExitResult(t, "0")
			other := *request.PrepareCompatibilityCheckpointExit
			checkpointExitTamperValue(&other)
			for _, bad := range []struct {
				name     string
				request  pc.WorkerCheckpointExit
				pid      int
				r        storageworker.WaitResult
				observed bool
			}{
				{"unobserved", *request.PrepareCompatibilityCheckpointExit, pid, result, false},
				{"empty", *request.PrepareCompatibilityCheckpointExit, pid, storageworker.WaitResult{}, true},
				{"not-reaped", *request.PrepareCompatibilityCheckpointExit, pid, storageworker.WaitResult{State: result.State, Err: result.Err}, true},
				{"wrong-pid", *request.PrepareCompatibilityCheckpointExit, pid + 1, result, true},
				{"pid-one", *request.PrepareCompatibilityCheckpointExit, 1, result, true},
				{"exit-zero", *request.PrepareCompatibilityCheckpointExit, pid, zero, true},
				{"err-mismatch", *request.PrepareCompatibilityCheckpointExit, pid, storageworker.WaitResult{Reaped: true, State: result.State, Err: io.ErrUnexpectedEOF}, true},
				{"checkpoint-mismatch", other, pid, result, true},
			} {
				t.Run(bad.name, func(t *testing.T) {
					if _, err := projectCheckpointWait(bad.request, bad.pid, bad.r, bad.observed); err == nil {
						t.Fatal("fabricated wait")
					}
				})
			}
		})
	}
}
