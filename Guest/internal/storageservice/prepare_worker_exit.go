package storageservice

import pc "dev.cengine/guest/internal/preparecompat"

func (s *commonService) ClaimPrepareCompatibilityWorkerExit(request pc.StorageRelease) (pc.StorageStatus, error) {
	if pc.ValidateStorageRelease(request) != nil || (request.Stage != "full-frame-before-admit" && request.Stage != "admitted-queued") {
		return pc.StorageStatus{}, ErrConfiguration
	}
	current, err := s.selectedCompatibility(request.Query)
	if err != nil {
		return pc.StorageStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return pc.StorageStatus{}, ErrConfiguration
	}
	snapshot, err := current.witness.ClaimWorkerExit(request.Stage, request.Token)
	if err != nil {
		return pc.StorageStatus{}, err
	}
	return current.statusFromSnapshot(snapshot), nil
}
