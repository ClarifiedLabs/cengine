package storageboot

import pc "dev.cengine/guest/internal/preparecompat"

// The lifecycle service must forward these calls to its retained resource owner;
// never construct a second coordinator or unwrap/cast to the v1 Service.
type lifecycleCompatibilityService interface {
	BindPrepareCompatibilityWorker(string) error
	ArmPrepareCompatibility(pc.StorageArm) (pc.StorageStatus, error)
	ObservePrepareCompatibility(pc.StorageQuery) (pc.StorageStatus, error)
	ReleasePrepareCompatibility(pc.StorageRelease) (pc.StorageStatus, error)
	ClaimPrepareCompatibilityWorkerExit(pc.StorageRelease) (pc.StorageStatus, error)
	ClaimPrepareCompatibilityCheckpointExit(pc.WorkerCheckpointExit) (pc.WorkerCheckpointExit, error)
}

func lifecycleCompatibilityCommand(command string) bool {
	switch command {
	case "prepare-compatibility-arm", "prepare-compatibility-observe", "prepare-compatibility-release", "prepare-compatibility-worker-exit", "prepare-compatibility-checkpoint-exit":
		return true
	}
	return false
}

func lifecycleCompatibilityQuery(f *LifecycleFrame) (pc.StorageQuery, error) {
	switch f.Command {
	case "prepare-compatibility-arm":
		return pc.StorageQueryForArm(*f.PrepareCompatibilityArm)
	case "prepare-compatibility-observe":
		return *f.PrepareCompatibilityQuery, nil
	case "prepare-compatibility-release":
		return f.PrepareCompatibilityRelease.Query, nil
	}
	return pc.StorageQuery{}, errFrame
}

func lifecycleCompatibilityDispatch(service any, request, reply *LifecycleFrame) error {
	if pc.CurrentProfile() != pc.FullProfile || request.validate() != nil {
		return errFrame
	}
	owner, ok := service.(lifecycleCompatibilityService)
	if !ok {
		return errFrame
	}
	var status pc.StorageStatus
	var err error
	switch request.Command {
	case "prepare-compatibility-arm":
		status, err = owner.ArmPrepareCompatibility(*request.PrepareCompatibilityArm)
	case "prepare-compatibility-observe":
		status, err = owner.ObservePrepareCompatibility(*request.PrepareCompatibilityQuery)
	case "prepare-compatibility-release":
		status, err = owner.ReleasePrepareCompatibility(*request.PrepareCompatibilityRelease)
	case "prepare-compatibility-worker-exit":
		status, err = owner.ClaimPrepareCompatibilityWorkerExit(*request.PrepareCompatibilityWorkerExit)
	case "prepare-compatibility-checkpoint-exit":
		var ack pc.WorkerCheckpointExit
		ack, err = owner.ClaimPrepareCompatibilityCheckpointExit(*request.PrepareCompatibilityCheckpointExit)
		if err == nil {
			reply.PrepareCompatibilityCheckpointAck = &ack
		}
		return err
	default:
		return errFrame
	}
	if err == nil {
		reply.PrepareCompatibilityStatus = &status
	}
	return err
}

func lifecycleExitACK(request, reply *LifecycleFrame) (uint64, error) {
	if reply == nil || reply.validate() != nil || reply.Operation != "reply" || reply.Binding != request.Binding || reply.Sequence == nil || *reply.Sequence != *request.Sequence || reply.ServiceEpoch != request.ServiceEpoch || reply.WorkerUUID != request.WorkerUUID || reply.Code != "" {
		return 0, errFrame
	}
	if r := request.PrepareCompatibilityCheckpointExit; r != nil {
		ack := reply.PrepareCompatibilityCheckpointAck
		if ack == nil || !pc.SameWorkerCheckpointClaim(*r, *ack) {
			return 0, errFrame
		}
		return 0, nil
	}
	r, status := request.PrepareCompatibilityWorkerExit, reply.PrepareCompatibilityStatus
	if r == nil || status == nil || pc.ValidateStorageStatus(*status) != nil {
		return 0, errFrame
	}
	admitted := r.Stage == "admitted-queued"
	if status.Query != r.Query || status.State != "observed" || status.RetirementStarted || (status.AcceptedInFlight == 0) == admitted || status.Observation == nil || status.Observation.Stage != r.Stage || status.Observation.Admission == nil {
		return 0, errFrame
	}
	cut := status.Observation.Admission
	if cut.Admitted != admitted || cut.RequestSequence == 0 || cut.ReleaseToken != r.Token {
		return 0, errFrame
	}
	return cut.RequestSequence, nil
}

// Called with mu held. Preserve the original active owner across both ACK and
// the sole Wait. No timeout, signal, EOF, close or replacement proves death.
func (s *lifecycleSupervisor) compatibilityExitLocked(request *LifecycleFrame) (*LifecycleFrame, string) {
	worker := s.worker
	owner, ok := worker.(compatibilityWaitWorker)
	if !ok || owner.workerPID() <= 1 || uint64(owner.workerPID()) > 1<<31-1 {
		s.mu.Unlock()
		return nil, "command"
	}
	pid := owner.workerPID()
	s.active = true
	s.mu.Unlock()
	reply, err := worker.exchange(request)
	response := lifecycleFrame("reply", request.Binding)
	response.Sequence, response.ServiceEpoch, response.WorkerUUID = request.Sequence, request.ServiceEpoch, request.WorkerUUID
	if err == nil && reply != nil && reply.Code == "" {
		var sequence uint64
		sequence, err = lifecycleExitACK(request, reply)
		if err == nil {
			<-worker.done()
			result, observed := owner.workerWaitResult()
			if request.PrepareCompatibilityCheckpointExit != nil {
				response.PrepareCompatibilityCheckpointWait, err = projectCheckpointWait(*request.PrepareCompatibilityCheckpointExit, pid, result, observed)
			} else {
				response.PrepareCompatibilityWorkerWait, err = projectWorkerWait(*request.PrepareCompatibilityWorkerExit, sequence, pid, result, observed)
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	if s.closed {
		return nil, "worker-lost"
	}
	if err == nil && reply != nil && reply.Code != "" && reply.Operation == "reply" && reply.validate() == nil && reply.Binding == request.Binding && reply.Sequence != nil && *reply.Sequence == *request.Sequence && reply.ServiceEpoch == request.ServiceEpoch && reply.WorkerUUID == request.WorkerUUID {
		return reply, ""
	}
	s.lost = true // retain the original worker, including uncertain Wait failures
	if err != nil || response.validate() != nil {
		return nil, "worker-unreaped"
	}
	return &response, ""
}
