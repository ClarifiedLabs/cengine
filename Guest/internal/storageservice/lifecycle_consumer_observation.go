package storageservice

import (
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
)

// Bind observations to the current service's lifecycle metadata.
// The worker binding and DATA recorder remain those of the actual private owner.
func (s *LifecycleService) consumerCurrent(q cc.Arm) bool {
	if !s.valid() || pc.CurrentProfile() != pc.FullProfile || cc.ValidateArm(q) != nil {
		return false
	}
	s.owner.compatibilityMu.Lock()
	worker := s.owner.compatibilityWorker
	s.owner.compatibilityMu.Unlock()
	if worker != q.WorkerScope.WorkerUUID {
		return false
	}
	r, err := s.Ready()
	return err == nil && string(r.Store.ID) == q.WorkerScope.StoreUUID && string(r.ServiceEpoch) == q.WorkerScope.ServiceEpoch
}
func (s *LifecycleService) ArmConsumerObservation(q cc.Arm) (cc.Status, error) {
	if !s.consumerCurrent(q) {
		return cc.Status{}, ErrConfiguration
	}
	return s.owner.consumer.Arm(q)
}

func (s *LifecycleService) QueryConsumerObservation(q cc.Query) (cc.Status, error) {
	if !s.consumerCurrent(q) {
		return cc.Status{}, ErrConfiguration
	}
	return s.owner.consumer.Query(q)
}

func (s *LifecycleService) FinalizeConsumerObservation(q cc.Query) (cc.Status, error) {
	if !s.consumerCurrent(q) {
		return cc.Status{}, ErrConfiguration
	}
	return s.owner.consumer.Finalize(q)
}
