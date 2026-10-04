package storageservice

import (
	"crypto/sha256"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/hex"
)

type issuedPrepareCertificate struct {
	hello  a.DataHello
	sha256 string
}
type servicePrepareCompatibility struct {
	query   pc.StorageQuery
	target  string
	stage   string
	witness *a.PrepareCompatibilityWitness
}

func (s *commonService) BindPrepareCompatibilityWorker(worker string) error {
	// Validate through the existing typed ID vocabulary, without any journal query.
	if !validCompatibilityWorker(worker) {
		return ErrConfiguration
	}
	s.compatibilityMu.Lock()
	defer s.compatibilityMu.Unlock()
	if s.compatibilityWorker != "" && s.compatibilityWorker != worker {
		return ErrConfiguration
	}
	s.compatibilityWorker = worker
	return nil
}
func validCompatibilityWorker(worker string) bool {
	// StorageQuery's codec owns the exact UUID rule; the boot caller already checks
	// the same rule. Keep the independently callable method strict too.
	if len(worker) != 36 || worker[8] != '-' || worker[13] != '-' || worker[18] != '-' || worker[23] != '-' || worker[14] != '4' {
		return false
	}
	if worker[19] != '8' && worker[19] != '9' && worker[19] != 'a' && worker[19] != 'b' {
		return false
	}
	for i, c := range worker {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (s *commonService) rememberPrepareCertificate(h a.DataHello, der []byte) error {
	if pc.CurrentProfile() != pc.FullProfile || h.Binding.Role != a.PrepareRole {
		return nil
	}
	sum := sha256.Sum256(der)
	s.compatibilityMu.Lock()
	defer s.compatibilityMu.Unlock()
	if s.compatibilityInstalling {
		return ErrConfiguration
	}
	if s.compatibility != nil {
		return nil
	} // fresh NORMAL recovery still issues real credentials
	if s.issuedPrepare == nil {
		s.issuedPrepare = map[a.ID]issuedPrepareCertificate{}
	}
	old, exists := s.issuedPrepare[h.Binding.Attachment]
	if (!exists && len(s.issuedPrepare) >= 64) || (exists && old.hello != h) {
		return ErrConfiguration
	}
	s.issuedPrepare[h.Binding.Attachment] = issuedPrepareCertificate{h, hex.EncodeToString(sum[:])}
	return nil
}
func (s *commonService) ArmPrepareCompatibility(wrapper pc.StorageArm) (pc.StorageStatus, error) {
	if pc.CurrentProfile() != pc.FullProfile || pc.ValidateStorageArm(wrapper) != nil {
		return pc.StorageStatus{}, ErrConfiguration
	}
	arm := wrapper.Arm
	s.mu.Lock()
	current := !s.closed && s.generation == (a.Controller{Epoch: arm.Scope.ControllerEpoch, Key: a.Fingerprint(arm.Scope.ControllerKey)})
	s.mu.Unlock()
	if !current {
		return pc.StorageStatus{}, ErrConfiguration
	}
	digest, err := pc.ArmDigest(arm)
	if err != nil {
		return pc.StorageStatus{}, err
	}
	s.compatibilityMu.Lock()
	if s.compatibilityWorker != wrapper.WorkerUUID || s.compatibilityInstalling || s.compatibility != nil {
		s.compatibilityMu.Unlock()
		return pc.StorageStatus{}, ErrConfiguration
	}
	plan := a.PrepareCompatibilityPlan{Stage: arm.CaseName, Epoch: a.ID(arm.Scope.ServiceEpoch), Controller: a.Controller{Epoch: arm.Scope.ControllerEpoch, Key: a.Fingerprint(arm.Scope.ControllerKey)}}
	credentials := map[string]pc.Credential{}
	for _, c := range arm.Credentials {
		credentials[c.Attachment] = c
	}
	for _, slot := range arm.Slots {
		if slot.Role == "runtime" {
			plan.RuntimeAttachments = append(plan.RuntimeAttachments, a.ID(slot.Attachment))
			continue
		}
		credential := credentials[slot.Attachment]
		b := a.Binding{Store: a.ID(arm.Scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Prepare: a.ID(arm.Scope.Prepare), Container: a.ContainerID(arm.Scope.Container), Launch: a.ID(arm.Scope.Launch), Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.Mode(slot.Mode)}
		expected := issuedPrepareCertificate{a.DataHello{Epoch: plan.Epoch, Binding: b}, credential.CertificateSHA256}
		if s.issuedPrepare[b.Attachment] != expected {
			s.compatibilityMu.Unlock()
			return pc.StorageStatus{}, ErrConfiguration
		}
		plan.Bindings = append(plan.Bindings, b)
		if slot.Attachment == arm.TargetAttachment {
			plan.Target = b
		}
	}
	s.compatibilityInstalling = true
	s.compatibilityMu.Unlock()
	witness, err := s.authority.InstallPrepareCompatibility(plan)
	s.compatibilityMu.Lock()
	defer s.compatibilityMu.Unlock()
	s.compatibilityInstalling = false
	if err != nil {
		return pc.StorageStatus{}, err
	}
	s.compatibility = &servicePrepareCompatibility{query: pc.StorageQuery{Version: 3, Profile: pc.FullProfile, RequestID: arm.RequestID, ArmDigest: digest, WorkerUUID: wrapper.WorkerUUID}, target: arm.TargetAttachment, stage: arm.CaseName, witness: witness}
	return s.compatibility.status(), nil
}
func (s *commonService) selectedCompatibility(query pc.StorageQuery) (*servicePrepareCompatibility, error) {
	if pc.CurrentProfile() != pc.FullProfile || pc.ValidateStorageQuery(query) != nil {
		return nil, ErrConfiguration
	}
	s.compatibilityMu.Lock()
	defer s.compatibilityMu.Unlock()
	current := s.compatibility
	if current == nil || current.query != query || query.WorkerUUID != s.compatibilityWorker {
		return nil, ErrConfiguration
	}
	return current, nil
}
func (s *commonService) ObservePrepareCompatibility(query pc.StorageQuery) (pc.StorageStatus, error) {
	current, err := s.selectedCompatibility(query)
	if err != nil {
		return pc.StorageStatus{}, err
	}
	return current.status(), nil
}
func (s *commonService) ReleasePrepareCompatibility(release pc.StorageRelease) (pc.StorageStatus, error) {
	if pc.ValidateStorageRelease(release) != nil {
		return pc.StorageStatus{}, ErrConfiguration
	}
	current, err := s.selectedCompatibility(release.Query)
	if err != nil {
		return pc.StorageStatus{}, err
	}
	if err = current.witness.Release(release.Stage, release.Token); err != nil {
		return pc.StorageStatus{}, err
	}
	return current.status(), nil
}
func (c *servicePrepareCompatibility) status() pc.StorageStatus {
	return c.statusFromSnapshot(c.witness.Snapshot())
}
func (c *servicePrepareCompatibility) statusFromSnapshot(snapshot a.PrepareCompatibilitySnapshot) pc.StorageStatus {
	status := pc.StorageStatus{Query: c.query, State: snapshot.State, RetirementStarted: snapshot.RetirementStarted, AcceptedInFlight: snapshot.AcceptedInFlight, LateAdmissionRejected: snapshot.LateAdmissionRejected, ReceiptReplayCount: snapshot.ReceiptReplayCount}
	if snapshot.State == "armed" {
		return status
	}
	o := pc.StorageObservation{Version: 3, Profile: pc.FullProfile, RequestID: c.query.RequestID, ArmDigest: c.query.ArmDigest, WorkerUUID: c.query.WorkerUUID, Stage: c.stage, Count: 1, TargetAttachment: c.target}
	if snapshot.IO != nil && snapshot.IO.Fired {
		io := snapshot.IO
		o.IO = &pc.IOCut{Point: io.Point, Errno: io.Errno, Occurrence: io.Occurrence, RequestSequence: io.Sequence, RetireOperation: string(io.Operation)}
	}
	switch c.stage {
	case "full-frame-before-admit", "admitted-queued":
		o.Admission = &pc.AdmissionCut{RequestSequence: snapshot.Sequence, Admitted: snapshot.Admitted, ReleaseToken: snapshot.ReleaseToken}
	case "transaction-published-bind-reply-lost", "vm-private-bound", "vm-cleaning-transaction-removed":
		o.Bound = &pc.BoundCut{RequestSequence: snapshot.Sequence, Intent: *snapshot.Bound}
	case "drain-durable-reply-lost", "vm-two-volume-drain-reply-gap":
		o.Drain = &pc.DrainCut{RetireOperation: string(snapshot.RetireOperation), Receipt: *snapshot.Receipt}
	}
	status.Observation = &o
	return status
}
