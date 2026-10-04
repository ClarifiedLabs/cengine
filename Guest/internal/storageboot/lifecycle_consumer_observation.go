package storageboot

import (
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	s "dev.cengine/guest/internal/storageservice"
)

func lifecycleConsumerCommand(command string) bool {
	switch command {
	case "consumer-observation-arm", "consumer-observation-query", "consumer-observation-finalize":
		return true
	}
	return false
}

func lifecycleConsumerRequest(f *LifecycleFrame) *cc.Arm {
	switch f.Command {
	case "consumer-observation-arm":
		return f.ConsumerObservationArm
	case "consumer-observation-query", "consumer-observation-finalize":
		return f.ConsumerObservationQuery
	}
	return nil
}

func lifecycleConsumerScope(f *LifecycleFrame, q *cc.Arm) bool {
	return q != nil && cc.ValidateArm(*q) == nil && q.WorkerScope.ServiceEpoch == f.ServiceEpoch && q.WorkerScope.WorkerUUID == f.WorkerUUID
}

func validLifecycleConsumerRequest(f *LifecycleFrame) bool {
	return f != nil && lifecycleConsumerScope(f, lifecycleConsumerRequest(f))
}

func validLifecycleConsumerReply(request, reply *LifecycleFrame) bool {
	if !validLifecycleConsumerRequest(request) || reply == nil || reply.validate() != nil || reply.Operation != "reply" || reply.Binding != request.Binding || request.Sequence == nil || reply.Sequence == nil || *reply.Sequence != *request.Sequence || reply.ServiceEpoch != request.ServiceEpoch || reply.WorkerUUID != request.WorkerUUID {
		return false
	}
	status := reply.ConsumerObservationStatus
	if status == nil || status.Query != *lifecycleConsumerRequest(request) {
		return false
	}
	// Finalization cannot be substituted with an unsealed observation.
	return request.Command != "consumer-observation-finalize" || status.State == "finalized"
}

func lifecycleConsumerDispatch(service *s.LifecycleService, request, reply *LifecycleFrame) error {
	if pc.CurrentProfile() != pc.FullProfile || request == nil || request.validate() != nil || !validLifecycleConsumerRequest(request) {
		return errFrame
	}
	q := *lifecycleConsumerRequest(request)
	var status cc.Status
	var err error
	switch request.Command {
	case "consumer-observation-arm":
		status, err = service.ArmConsumerObservation(q)
	case "consumer-observation-query":
		status, err = service.QueryConsumerObservation(q)
	case "consumer-observation-finalize":
		status, err = service.FinalizeConsumerObservation(q)
	default:
		return errFrame
	}
	if err != nil {
		return err
	}
	reply.ConsumerObservationStatus = &status
	if !validLifecycleConsumerReply(request, reply) {
		return errFrame
	}
	return nil
}
