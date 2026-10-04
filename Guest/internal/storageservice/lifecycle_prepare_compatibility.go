package storageservice

import pc "dev.cengine/guest/internal/preparecompat"

// Compatibility uses the same owner, issued credentials and authority as the
// lifecycle workload endpoints.
func (s *LifecycleService) BindPrepareCompatibilityWorker(worker string) error {
	if !s.valid() || pc.CurrentProfile() != pc.FullProfile {
		return ErrConfiguration
	}
	return s.owner.BindPrepareCompatibilityWorker(worker)
}

func (s *LifecycleService) ArmPrepareCompatibility(arm pc.StorageArm) (pc.StorageStatus, error) {
	if !s.valid() {
		return pc.StorageStatus{}, ErrConfiguration
	}
	return s.owner.ArmPrepareCompatibility(arm)
}

func (s *LifecycleService) ObservePrepareCompatibility(query pc.StorageQuery) (pc.StorageStatus, error) {
	if !s.valid() {
		return pc.StorageStatus{}, ErrConfiguration
	}
	return s.owner.ObservePrepareCompatibility(query)
}

func (s *LifecycleService) ReleasePrepareCompatibility(release pc.StorageRelease) (pc.StorageStatus, error) {
	if !s.valid() {
		return pc.StorageStatus{}, ErrConfiguration
	}
	return s.owner.ReleasePrepareCompatibility(release)
}

func (s *LifecycleService) ClaimPrepareCompatibilityWorkerExit(release pc.StorageRelease) (pc.StorageStatus, error) {
	if !s.valid() {
		return pc.StorageStatus{}, ErrConfiguration
	}
	return s.owner.ClaimPrepareCompatibilityWorkerExit(release)
}

func (s *LifecycleService) ClaimPrepareCompatibilityCheckpointExit(claim pc.WorkerCheckpointExit) (pc.WorkerCheckpointExit, error) {
	if !s.valid() {
		return pc.WorkerCheckpointExit{}, ErrConfiguration
	}
	return s.owner.ClaimPrepareCompatibilityCheckpointExit(claim)
}
