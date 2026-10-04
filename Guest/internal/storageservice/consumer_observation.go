package storageservice

import (
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
)

// Current worker binding is fixed by publicReady before protected commands are
// accepted. The service independently compares real persisted S/E, not caller
// metadata. A successor always constructs a fresh recorder with no old state.
func (s *commonService) consumerCurrent(q cc.Arm) bool {
	if pc.CurrentProfile() != pc.FullProfile || cc.ValidateArm(q) != nil {
		return false
	}
	s.compatibilityMu.Lock()
	worker := s.compatibilityWorker
	s.compatibilityMu.Unlock()
	if worker != q.WorkerScope.WorkerUUID {
		return false
	}
	r, err := s.Ready()
	return err == nil && string(r.Store.ID) == q.WorkerScope.StoreUUID && string(r.ServiceEpoch) == q.WorkerScope.ServiceEpoch
}
func (s *commonService) ArmConsumerObservation(q cc.Arm) (cc.Status, error) {
	if !s.consumerCurrent(q) {
		return cc.Status{}, ErrConfiguration
	}
	return s.consumer.Arm(q)
}
func (s *commonService) QueryConsumerObservation(q cc.Query) (cc.Status, error) {
	if !s.consumerCurrent(q) {
		return cc.Status{}, ErrConfiguration
	}
	return s.consumer.Query(q)
}

func (s *commonService) FinalizeConsumerObservation(q cc.Query) (cc.Status, error) {
	if !s.consumerCurrent(q) {
		return cc.Status{}, ErrConfiguration
	}
	return s.consumer.Finalize(q)
}
