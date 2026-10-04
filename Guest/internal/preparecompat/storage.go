package preparecompat

import a "dev.cengine/guest/internal/storageauthority"

// The storage boot envelope binds current storage boot/S/E/controller. WorkerUUID
// is separate from the immutable Arm digest and checked against the actual worker.
type StorageArm struct {
	Arm        Arm    `json:"arm"`
	WorkerUUID string `json:"workerUUID"`
}
type StorageQuery struct {
	Version    uint32 `json:"version"`
	Profile    string `json:"profile"`
	RequestID  string `json:"requestID"`
	ArmDigest  string `json:"armDigest"`
	WorkerUUID string `json:"workerUUID"`
}
type StorageRelease struct {
	Query StorageQuery `json:"query"`
	Stage string       `json:"stage"`
	Token string       `json:"token"`
}
type AdmissionCut struct {
	RequestSequence uint64 `json:"requestSequence"`
	Admitted        bool   `json:"admitted"`
	ReleaseToken    string `json:"releaseToken"`
}
type BoundCut struct {
	RequestSequence uint64       `json:"requestSequence"`
	Intent          a.CopyIntent `json:"intent"`
}
type DrainCut struct {
	RetireOperation string    `json:"retireOperation"`
	Receipt         a.Receipt `json:"receipt"`
}
type StorageObservation struct {
	Version          uint32        `json:"version"`
	Profile          string        `json:"profile"`
	RequestID        string        `json:"requestID"`
	ArmDigest        string        `json:"armDigest"`
	WorkerUUID       string        `json:"workerUUID"`
	Stage            string        `json:"stage"`
	Count            uint32        `json:"count"`
	TargetAttachment string        `json:"targetAttachment"`
	IO               *IOCut        `json:"io,omitempty"`
	Admission        *AdmissionCut `json:"admission,omitempty"`
	Bound            *BoundCut     `json:"bound,omitempty"`
	Drain            *DrainCut     `json:"drain,omitempty"`
}
type StorageStatus struct {
	Query                 StorageQuery        `json:"query"`
	State                 string              `json:"state"`
	RetirementStarted     bool                `json:"retirementStarted"`
	AcceptedInFlight      uint32              `json:"acceptedInFlight"`
	LateAdmissionRejected bool                `json:"lateAdmissionRejected"`
	ReceiptReplayCount    uint32              `json:"receiptReplayCount"`
	Observation           *StorageObservation `json:"observation,omitempty"`
}

func ValidateStorageArm(s StorageArm) error {
	if s.Arm.Version != 3 || s.Arm.Profile != FullProfile || !storageCase(s.Arm.CaseName) || !id(s.WorkerUUID) || ValidateArm(s.Arm) != nil {
		return ErrInvalidFrame
	}
	s.Arm = normalize(s.Arm)
	b, err := CanonicalJSON(s)
	if err != nil || len(b) > MaximumStorageFrameBytes {
		return ErrInvalidFrame
	}
	return nil
}
func SupportsStorageArm(s StorageArm) bool {
	return CurrentProfile() == FullProfile && ValidateStorageArm(s) == nil
}
func ValidateStorageQuery(q StorageQuery) error {
	if q.Version != 3 || q.Profile != FullProfile || !id(q.RequestID) || !pin(q.ArmDigest) || !id(q.WorkerUUID) {
		return ErrInvalidFrame
	}
	return nil
}
func StorageQueryForArm(s StorageArm) (StorageQuery, error) {
	if ValidateStorageArm(s) != nil {
		return StorageQuery{}, ErrInvalidFrame
	}
	digest, err := ArmDigest(s.Arm)
	if err != nil {
		return StorageQuery{}, err
	}
	return StorageQuery{Version: 3, Profile: FullProfile, RequestID: s.Arm.RequestID, ArmDigest: digest, WorkerUUID: s.WorkerUUID}, nil
}
func ValidateStorageRelease(r StorageRelease) error {
	if ValidateStorageQuery(r.Query) != nil || (r.Stage != "full-frame-before-admit" && r.Stage != "admitted-queued") || !pin(r.Token) {
		return ErrInvalidFrame
	}
	return nil
}
func validBoundIntent(i a.CopyIntent) bool {
	b := i.Owner
	if !id(string(i.ID)) || !id(string(i.Epoch)) || !id(string(b.Store)) || !id(string(b.Volume)) || !id(string(b.Attachment)) || !id(string(b.Prepare)) || !id(string(b.Launch)) || !pin(string(b.Container)) || !pin(string(b.Key)) || b.Role != a.PrepareRole || b.Mode != a.ReadWrite || i.Phase != a.CopyBound || i.Root.Store != b.Store || i.Root.Volume != b.Volume || i.Root.BackingUUID == [16]byte{} || !i.InitialCaptured || i.ManifestDigest != [32]byte{} || i.ManifestSize != 0 || i.Cleanup != (a.CopyCleanupV1{}) {
		return false
	}
	root, e1 := ObjectFromAuthority(i.Root.Root)
	transaction, e2 := ObjectFromAuthority(i.Transaction)
	initial := i.Initial
	return e1 == nil && e2 == nil && root.FileType == 16384 && transaction.FileType == 16384 && root != transaction && initial.Mode & ^uint32(07777) == 0 && initial.UID != ^uint32(0) && initial.GID != ^uint32(0) && initial.ATimeNanos < 1e9 && initial.MTimeNanos < 1e9 && initial.Manifest == (a.Ext4ObjectV1{}) && initial.Staging == (a.Ext4ObjectV1{})
}
func validReceipt(r a.Receipt) bool {
	return r.Schema == a.SchemaVersion && id(string(r.Store)) && id(string(r.Volume)) && id(string(r.Attachment)) && id(string(r.Launch)) && id(string(r.Prepare)) && r.Revision > 0
}
func observationQuery(o StorageObservation) StorageQuery {
	return StorageQuery{Version: o.Version, Profile: o.Profile, RequestID: o.RequestID, ArmDigest: o.ArmDigest, WorkerUUID: o.WorkerUUID}
}
func ValidateStorageObservation(o StorageObservation) error {
	if ValidateStorageQuery(observationQuery(o)) != nil || o.Count != 1 || !id(o.TargetAttachment) {
		return ErrInvalidFrame
	}
	if isStorageIOCase(o.Stage) {
		point, errno, _, _ := ioCase(o.Stage)
		cut := o.IO
		if cut == nil || o.Admission != nil || o.Bound != nil || o.Drain != nil || cut.Point != point || cut.Errno != errno || cut.Occurrence != 1 {
			return ErrInvalidFrame
		}
		if len(point) >= 7 && point[:7] == "retire-" {
			if cut.RequestSequence != 0 || !id(cut.RetireOperation) {
				return ErrInvalidFrame
			}
		} else if cut.RequestSequence == 0 || cut.RetireOperation != "" {
			return ErrInvalidFrame
		}
		return nil
	}
	if o.IO != nil {
		return ErrInvalidFrame
	}
	switch o.Stage {
	case "full-frame-before-admit", "admitted-queued":
		if o.Admission == nil || o.Bound != nil || o.Drain != nil || o.Admission.RequestSequence == 0 || !pin(o.Admission.ReleaseToken) || o.Admission.Admitted != (o.Stage == "admitted-queued") {
			return ErrInvalidFrame
		}
	case "transaction-published-bind-reply-lost", "vm-private-bound", "vm-cleaning-transaction-removed":
		if o.Admission != nil || o.Bound == nil || o.Drain != nil || o.Bound.RequestSequence == 0 || !validCheckpointIntent(o.Stage, o.Bound.Intent) || string(o.Bound.Intent.Owner.Attachment) != o.TargetAttachment {
			return ErrInvalidFrame
		}
	case "drain-durable-reply-lost", "vm-two-volume-drain-reply-gap":
		if o.Admission != nil || o.Bound != nil || o.Drain == nil || !id(o.Drain.RetireOperation) || !validReceipt(o.Drain.Receipt) || string(o.Drain.Receipt.Attachment) != o.TargetAttachment {
			return ErrInvalidFrame
		}
	default:
		return ErrInvalidFrame
	}
	raw, err := CanonicalJSON(o)
	if err != nil || len(raw) > MaximumObservationBytes {
		return ErrInvalidFrame
	}
	return nil
}

// Structural validation is not authentication: the installer must compare live
// authority state/certificates. This helper checks immutable observation binding.
func ValidateStorageObservationForArm(o StorageObservation, s StorageArm) error {
	q, err := StorageQueryForArm(s)
	if err != nil || ValidateStorageObservation(o) != nil || observationQuery(o) != q || o.Stage != s.Arm.CaseName || o.TargetAttachment != s.Arm.TargetAttachment {
		return ErrInvalidFrame
	}
	var slot Slot
	var credential Credential
	for _, v := range s.Arm.Slots {
		if v.Attachment == s.Arm.TargetAttachment {
			slot = v
		}
	}
	for _, v := range s.Arm.Credentials {
		if v.Attachment == s.Arm.TargetAttachment {
			credential = v
		}
	}
	scope := s.Arm.Scope
	expected := a.Binding{Store: a.ID(scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Prepare: a.ID(scope.Prepare), Container: a.ContainerID(scope.Container), Launch: a.ID(scope.Launch), Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.ReadWrite}
	if o.Bound != nil && (o.Bound.Intent.Owner != expected || o.Bound.Intent.Epoch != a.ID(scope.ServiceEpoch)) {
		return ErrInvalidFrame
	}
	if o.Drain != nil {
		r := o.Drain.Receipt
		if r.Store != expected.Store || r.Volume != expected.Volume || r.Attachment != expected.Attachment || r.Launch != expected.Launch || r.Prepare != expected.Prepare {
			return ErrInvalidFrame
		}
	}
	return nil
}
func ValidateStorageStatus(s StorageStatus) error {
	if ValidateStorageQuery(s.Query) != nil {
		return ErrInvalidFrame
	}
	if s.State == "armed" {
		if s.Observation != nil || s.LateAdmissionRejected || s.ReceiptReplayCount != 0 {
			return ErrInvalidFrame
		}
	} else {
		if (s.State != "observed" && s.State != "released" && s.State != "finished" && s.State != "held") || s.Observation == nil || ValidateStorageObservation(*s.Observation) != nil || observationQuery(*s.Observation) != s.Query {
			return ErrInvalidFrame
		}
		stage := s.Observation.Stage
		if stage == "vm-two-volume-drain-reply-gap" {
			if s.State != "held" || !s.RetirementStarted || s.AcceptedInFlight != 0 || s.LateAdmissionRejected || s.ReceiptReplayCount != 0 {
				return ErrInvalidFrame
			}
		} else if s.State == "held" {
			return ErrInvalidFrame
		}
		if (s.Observation.IO != nil || isVMCase(stage)) && (s.State != "observed" || s.LateAdmissionRejected || s.ReceiptReplayCount != 0) {
			return ErrInvalidFrame
		}
		if isVMCase(stage) && (s.RetirementStarted || s.AcceptedInFlight == 0) {
			return ErrInvalidFrame
		}
		if s.State == "released" && stage != "full-frame-before-admit" && stage != "admitted-queued" {
			return ErrInvalidFrame
		}
		if stage == "admitted-queued" && s.State == "observed" && s.RetirementStarted && s.AcceptedInFlight == 0 {
			return ErrInvalidFrame
		}
		if s.LateAdmissionRejected && (stage != "full-frame-before-admit" || !s.RetirementStarted || s.State == "observed") {
			return ErrInvalidFrame
		}
		if s.ReceiptReplayCount > 0 && stage != "drain-durable-reply-lost" {
			return ErrInvalidFrame
		}
	}
	raw, err := CanonicalJSON(s)
	if err != nil || len(raw) > MaximumStorageFrameBytes {
		return ErrInvalidFrame
	}
	return nil
}
func ValidateStorageStatusForArm(status StorageStatus, s StorageArm) error {
	q, err := StorageQueryForArm(s)
	if err != nil || ValidateStorageStatus(status) != nil || status.Query != q {
		return ErrInvalidFrame
	}
	if status.Observation != nil {
		return ValidateStorageObservationForArm(*status.Observation, s)
	}
	return nil
}
func DecodeStorageArm(raw []byte) (StorageArm, error) {
	var s StorageArm
	if decode(raw, &s, MaximumStorageFrameBytes) != nil || ValidateStorageArm(s) != nil {
		return StorageArm{}, ErrInvalidFrame
	}
	return s, nil
}
func DecodeStorageQuery(raw []byte) (StorageQuery, error) {
	var s StorageQuery
	if decode(raw, &s, MaximumStorageFrameBytes) != nil || ValidateStorageQuery(s) != nil {
		return StorageQuery{}, ErrInvalidFrame
	}
	return s, nil
}
func DecodeStorageRelease(raw []byte) (StorageRelease, error) {
	var s StorageRelease
	if decode(raw, &s, MaximumStorageFrameBytes) != nil || ValidateStorageRelease(s) != nil {
		return StorageRelease{}, ErrInvalidFrame
	}
	return s, nil
}
func DecodeStorageObservation(raw []byte) (StorageObservation, error) {
	var s StorageObservation
	if decode(raw, &s, MaximumObservationBytes) != nil || ValidateStorageObservation(s) != nil {
		return StorageObservation{}, ErrInvalidFrame
	}
	return s, nil
}
func DecodeStorageStatus(raw []byte) (StorageStatus, error) {
	var s StorageStatus
	if decode(raw, &s, MaximumStorageFrameBytes) != nil || ValidateStorageStatus(s) != nil {
		return StorageStatus{}, ErrInvalidFrame
	}
	return s, nil
}
func CanonicalStorageArmData(s StorageArm) ([]byte, error) {
	if ValidateStorageArm(s) != nil {
		return nil, ErrInvalidFrame
	}
	s.Arm = normalize(s.Arm)
	return CanonicalJSON(s)
}
