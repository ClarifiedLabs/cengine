package preparecompat

// WorkerCheckpointExit is the RTM098 generic full-profile-only checkpoint exit
// claim for the seven guest-visible cuts: NORMAL/A7 (physical), A1/A2/A3
// (early partial-frame), A6/A8 (storage-owned Bound/Drain). Exactly one of
// Checkpoint/EarlyCheckpoint/StorageCheckpoint must be present, selected by
// the arm's case, and each is bound to the arm by its actual existing
// validator. The host holds the real checkpoint and arm; this carrier binds
// them to one owned worker. It never carries or fabricates a storage
// Admission, release token, or made-up sequence: A4/A5 stay on the distinct
// strict StorageRelease path.
type WorkerCheckpointExit struct {
	Arm               Arm                 `json:"arm"`
	Checkpoint        *Observation        `json:"checkpoint,omitempty"`
	EarlyCheckpoint   *EarlyObservation   `json:"earlyCheckpoint,omitempty"`
	StorageCheckpoint *StorageObservation `json:"storageCheckpoint,omitempty"`
	WorkerUUID        string              `json:"workerUUID"`
}

// WorkerCheckpointWait is PID1's projection of the sole actual Wait of the
// owned worker that acknowledged this exact claim. Decoding it is not
// process-death or PREPARE authority.
type WorkerCheckpointWait struct {
	Arm               Arm                 `json:"arm"`
	Checkpoint        *Observation        `json:"checkpoint,omitempty"`
	EarlyCheckpoint   *EarlyObservation   `json:"earlyCheckpoint,omitempty"`
	StorageCheckpoint *StorageObservation `json:"storageCheckpoint,omitempty"`
	WorkerUUID        string              `json:"workerUUID"`
	WorkerPID         uint32              `json:"workerPID"`
	ExitCode          uint32              `json:"exitCode"`
	Reaped            bool                `json:"reaped"`
}

// CheckpointExitCut is the closed set of cuts claimable through the generic
// checkpoint exit path. NORMAL/A7/A1/A2/A3/A6/A8 only; A4/A5 admission cuts,
// the VM cases and IO cuts stay on their own paths.
func CheckpointExitCut(stage string) bool {
	switch stage {
	case "normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "first-child-published", "transaction-published-bind-reply-lost", "drain-durable-reply-lost":
		return true
	}
	return false
}

// checkpointExitKind selects the single permitted checkpoint carrier.
func checkpointExitKind(stage string) string {
	switch stage {
	case "normal", "first-child-published":
		return "physical"
	case "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame":
		return "early"
	case "transaction-published-bind-reply-lost", "drain-durable-reply-lost":
		return "storage"
	}
	return ""
}

// ValidateObservationForArm binds an actual guest physical observation to its
// arm: immutable digest/request/target identity plus the arm's physical stage.
func ValidateObservationForArm(o Observation, arm Arm) error {
	digest, err := ArmDigest(arm)
	if err != nil || ValidateObservation(o) != nil || o.ArmDigest != digest || o.RequestID != arm.RequestID || o.TargetAttachment != arm.TargetAttachment || o.Stage != physicalStage(arm) {
		return ErrInvalidFrame
	}
	return nil
}

// ValidateEarlyObservationForArm binds an actual early partial-frame
// observation (A1/A2/A3) to its arm. It is the early carrier, never a
// synthetic physical observation.
func ValidateEarlyObservationForArm(o EarlyObservation, arm Arm) error {
	digest, err := ArmDigest(arm)
	if err != nil || ValidateEarlyObservation(o) != nil || o.ArmDigest != digest || o.RequestID != arm.RequestID || o.TargetAttachment != arm.TargetAttachment || o.Stage != arm.CaseName {
		return ErrInvalidFrame
	}
	return nil
}

// SameWorkerCheckpointClaim compares two full claims by canonical bytes.
func SameWorkerCheckpointClaim(a, b WorkerCheckpointExit) bool {
	ca, e1 := CanonicalJSON(a)
	cb, e2 := CanonicalJSON(b)
	return e1 == nil && e2 == nil && string(ca) == string(cb)
}

// SameStorageCheckpoint compares two storage checkpoint observations by
// canonical bytes; the service uses it to require the exact actually
// retained Bound/Drain observation.
func SameStorageCheckpoint(a, b StorageObservation) bool {
	ca, e1 := CanonicalJSON(a)
	cb, e2 := CanonicalJSON(b)
	return e1 == nil && e2 == nil && string(ca) == string(cb)
}

func (w WorkerCheckpointWait) claim() WorkerCheckpointExit {
	return WorkerCheckpointExit{Arm: w.Arm, Checkpoint: w.Checkpoint, EarlyCheckpoint: w.EarlyCheckpoint, StorageCheckpoint: w.StorageCheckpoint, WorkerUUID: w.WorkerUUID}
}

func ValidateWorkerCheckpointExit(e WorkerCheckpointExit) error {
	if CurrentProfile() != FullProfile || e.Arm.Version != 3 || e.Arm.Profile != FullProfile || !CheckpointExitCut(e.Arm.CaseName) || !id(e.WorkerUUID) || ValidateArm(e.Arm) != nil {
		return ErrInvalidFrame
	}
	set := 0
	if e.Checkpoint != nil {
		set++
	}
	if e.EarlyCheckpoint != nil {
		set++
	}
	if e.StorageCheckpoint != nil {
		set++
	}
	if set != 1 {
		return ErrInvalidFrame
	}
	switch checkpointExitKind(e.Arm.CaseName) {
	case "physical":
		if e.Checkpoint == nil || ValidateObservationForArm(*e.Checkpoint, e.Arm) != nil {
			return ErrInvalidFrame
		}
	case "early":
		if e.EarlyCheckpoint == nil || ValidateEarlyObservationForArm(*e.EarlyCheckpoint, e.Arm) != nil {
			return ErrInvalidFrame
		}
	case "storage":
		if e.StorageCheckpoint == nil || ValidateStorageObservationForArm(*e.StorageCheckpoint, StorageArm{Arm: e.Arm, WorkerUUID: e.WorkerUUID}) != nil {
			return ErrInvalidFrame
		}
	default:
		return ErrInvalidFrame
	}
	raw, err := CanonicalJSON(e)
	if err != nil || len(raw) > MaximumStorageFrameBytes {
		return ErrInvalidFrame
	}
	return nil
}

func ValidateWorkerCheckpointWait(w WorkerCheckpointWait) error {
	if ValidateWorkerCheckpointExit(w.claim()) != nil || w.WorkerPID <= 1 || w.WorkerPID > 1<<31-1 || w.ExitCode != 74 || !w.Reaped {
		return ErrInvalidFrame
	}
	return nil
}

// ValidateWorkerCheckpointWaitForArm requires the wait projection to match the
// exact full claim: same arm, same actual checkpoint carrier, same owned
// worker. Canonical comparison covers every sealed union field.
func ValidateWorkerCheckpointWaitForArm(w WorkerCheckpointWait, e WorkerCheckpointExit) error {
	if ValidateWorkerCheckpointExit(e) != nil || ValidateWorkerCheckpointWait(w) != nil || !SameWorkerCheckpointClaim(w.claim(), e) {
		return ErrInvalidFrame
	}
	return nil
}

func DecodeWorkerCheckpointExit(raw []byte) (WorkerCheckpointExit, error) {
	var e WorkerCheckpointExit
	if decode(raw, &e, MaximumStorageFrameBytes) != nil || ValidateWorkerCheckpointExit(e) != nil {
		return WorkerCheckpointExit{}, ErrInvalidFrame
	}
	return e, nil
}

func DecodeWorkerCheckpointWait(raw []byte) (WorkerCheckpointWait, error) {
	var w WorkerCheckpointWait
	if decode(raw, &w, MaximumStorageFrameBytes) != nil || ValidateWorkerCheckpointWait(w) != nil {
		return WorkerCheckpointWait{}, ErrInvalidFrame
	}
	return w, nil
}
