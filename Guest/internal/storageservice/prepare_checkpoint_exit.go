package storageservice

import (
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
)

// ClaimPrepareCompatibilityCheckpointExit validates the generic RTM098
// checkpoint exit claim against the live authority and binds it one-shot to
// the owned compatibility worker. Every cut re-verifies the issued PREPARE
// credentials exactly like ArmPrepareCompatibility; A6/A8 additionally must
// match the installed compatibility query and its exact actually retained
// Bound/Drain observation (even after natural settle to finished). It grants
// no storage Admission, releases nothing, and advances no state.
func (s *commonService) ClaimPrepareCompatibilityCheckpointExit(request pc.WorkerCheckpointExit) (pc.WorkerCheckpointExit, error) {
	if pc.CurrentProfile() != pc.FullProfile || pc.ValidateWorkerCheckpointExit(request) != nil {
		return pc.WorkerCheckpointExit{}, ErrConfiguration
	}
	arm := request.Arm
	ready, err := s.Ready()
	if err != nil {
		return pc.WorkerCheckpointExit{}, ErrConfiguration
	}
	s.mu.Lock()
	current := !s.closed && s.generation == (a.Controller{Epoch: arm.Scope.ControllerEpoch, Key: a.Fingerprint(arm.Scope.ControllerKey)})
	s.mu.Unlock()
	if !current || string(ready.Store.ID) != arm.Scope.Store || string(ready.ServiceEpoch) != arm.Scope.ServiceEpoch {
		return pc.WorkerCheckpointExit{}, ErrConfiguration
	}
	s.compatibilityMu.Lock()
	defer s.compatibilityMu.Unlock()
	if s.closed || s.compatibilityInstalling || s.compatibilityWorker != request.WorkerUUID || s.compatibilityCheckpoint {
		return pc.WorkerCheckpointExit{}, ErrConfiguration
	}
	// Re-verify every issued PREPARE credential against the recorded issue
	// set, the same comparison ArmPrepareCompatibility performs at install.
	credentials := map[string]pc.Credential{}
	for _, c := range arm.Credentials {
		credentials[c.Attachment] = c
	}
	for _, slot := range arm.Slots {
		if slot.Role != "prepare" {
			continue
		}
		credential := credentials[slot.Attachment]
		b := a.Binding{Store: a.ID(arm.Scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Prepare: a.ID(arm.Scope.Prepare), Container: a.ContainerID(arm.Scope.Container), Launch: a.ID(arm.Scope.Launch), Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.Mode(slot.Mode)}
		expected := issuedPrepareCertificate{a.DataHello{Epoch: a.ID(arm.Scope.ServiceEpoch), Binding: b}, credential.CertificateSHA256}
		if s.issuedPrepare[b.Attachment] != expected {
			return pc.WorkerCheckpointExit{}, ErrConfiguration
		}
	}
	if pc.CheckpointExitCut(arm.CaseName) && checkpointExitStorageCut(arm.CaseName) {
		q, err := pc.StorageQueryForArm(pc.StorageArm{Arm: arm, WorkerUUID: request.WorkerUUID})
		if err != nil {
			return pc.WorkerCheckpointExit{}, ErrConfiguration
		}
		selected, err := s.selectedCompatibilityLocked(q)
		if err != nil || selected.stage != arm.CaseName || request.StorageCheckpoint == nil {
			return pc.WorkerCheckpointExit{}, ErrConfiguration
		}
		observed := selected.status().Observation
		if observed == nil || !pc.SameStorageCheckpoint(*observed, *request.StorageCheckpoint) {
			return pc.WorkerCheckpointExit{}, ErrConfiguration
		}
	}
	s.compatibilityCheckpoint = true
	return request, nil
}

func checkpointExitStorageCut(stage string) bool {
	return stage == "transaction-published-bind-reply-lost" || stage == "drain-durable-reply-lost"
}

// selectedCompatibilityLocked is selectedCompatibility for a caller already
// holding compatibilityMu.
func (s *commonService) selectedCompatibilityLocked(query pc.StorageQuery) (*servicePrepareCompatibility, error) {
	if pc.CurrentProfile() != pc.FullProfile || pc.ValidateStorageQuery(query) != nil {
		return nil, ErrConfiguration
	}
	current := s.compatibility
	if current == nil || current.query != query || query.WorkerUUID != s.compatibilityWorker {
		return nil, ErrConfiguration
	}
	return current, nil
}
