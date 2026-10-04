package storageboot

import (
	pc "dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/storageworker"
	"errors"
	"os/exec"
)

// Only the sole actual Wait can provide these observations.
type compatibilityWaitWorker interface {
	workerPID() int
	workerWaitResult() (storageworker.WaitResult, bool)
}

func projectWorkerWait(request pc.StorageRelease, sequence uint64, pid int, result storageworker.WaitResult, observed bool) (*pc.StorageWorkerWait, error) {
	var exitErr *exec.ExitError
	if !observed || !result.Reaped || result.State == nil || !result.State.Exited() || result.State.ExitCode() != 74 || pid <= 1 || uint64(pid) > 1<<31-1 || result.State.Pid() != pid || (result.Err != nil && (!errors.As(result.Err, &exitErr) || exitErr.ProcessState != result.State)) {
		return nil, errFrame
	}
	w := &pc.StorageWorkerWait{Query: request.Query, Stage: request.Stage, Token: request.Token, RequestSequence: sequence, WorkerPID: uint32(pid), ExitCode: 74, Reaped: true}
	if pc.ValidateStorageWorkerWait(*w) != nil {
		return nil, errFrame
	}
	return w, nil
}
func projectCheckpointWait(request pc.WorkerCheckpointExit, pid int, result storageworker.WaitResult, observed bool) (*pc.WorkerCheckpointWait, error) {
	var exitErr *exec.ExitError
	if !observed || !result.Reaped || result.State == nil || !result.State.Exited() || result.State.ExitCode() != 74 || pid <= 1 || uint64(pid) > 1<<31-1 || result.State.Pid() != pid || (result.Err != nil && (!errors.As(result.Err, &exitErr) || exitErr.ProcessState != result.State)) {
		return nil, errFrame
	}
	w := &pc.WorkerCheckpointWait{Arm: request.Arm, Checkpoint: request.Checkpoint, EarlyCheckpoint: request.EarlyCheckpoint, StorageCheckpoint: request.StorageCheckpoint, WorkerUUID: request.WorkerUUID, WorkerPID: uint32(pid), ExitCode: 74, Reaped: true}
	if pc.ValidateWorkerCheckpointWaitForArm(*w, request) != nil {
		return nil, errFrame
	}
	return w, nil
}
