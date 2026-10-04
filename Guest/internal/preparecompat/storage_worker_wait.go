package preparecompat

// StorageWorkerWait is a PID1 projection of an owned, actually reaped worker.
// Decoding this carrier is not process-death or storage-retirement authority.
type StorageWorkerWait struct {
	Query           StorageQuery `json:"query"`
	Stage           string       `json:"stage"`
	Token           string       `json:"token"`
	RequestSequence uint64       `json:"requestSequence"`
	WorkerPID       uint32       `json:"workerPID"`
	ExitCode        uint32       `json:"exitCode"`
	Reaped          bool         `json:"reaped"`
}

func ValidateStorageWorkerWait(w StorageWorkerWait) error {
	if ValidateStorageQuery(w.Query) != nil || (w.Stage != "full-frame-before-admit" && w.Stage != "admitted-queued") || !pin(w.Token) || w.RequestSequence == 0 || w.WorkerPID <= 1 || w.WorkerPID > 1<<31-1 || w.ExitCode != 74 || !w.Reaped {
		return ErrInvalidFrame
	}
	return nil
}
func ValidateStorageWorkerWaitForArm(w StorageWorkerWait, arm StorageArm) error {
	q, err := StorageQueryForArm(arm)
	if err != nil || ValidateStorageWorkerWait(w) != nil || w.Query != q || arm.Arm.CaseName != w.Stage {
		return ErrInvalidFrame
	}
	return nil
}
func DecodeStorageWorkerWait(raw []byte) (StorageWorkerWait, error) {
	var w StorageWorkerWait
	if decode(raw, &w, MaximumStorageFrameBytes) != nil || ValidateStorageWorkerWait(w) != nil {
		return StorageWorkerWait{}, ErrInvalidFrame
	}
	return w, nil
}
