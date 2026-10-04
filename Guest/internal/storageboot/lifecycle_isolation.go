package storageboot

import (
	pc "dev.cengine/guest/internal/preparecompat"
	s "dev.cengine/guest/internal/storageservice"
)

func lifecycleIsolationCommand(command string) bool {
	switch command {
	case "isolation-state", "legacy-connection", "second-service-exclusivity":
		return true
	}
	return false
}

func validLifecycleIsolationProof(f *LifecycleFrame) bool {
	p := f.IsolationProof
	if p == nil || !validIsolationRequest(&p.Request) || !id(p.WorkerUUID) || p.WorkerUUID != f.WorkerUUID ||
		!id(p.Store) || !id(p.ServiceEpoch) || p.ServiceEpoch != f.ServiceEpoch || p.Revision == 0 || !pin(p.RegistrySHA256) {
		return false
	}
	switch p.CaseName {
	case "isolation-state":
		return p.Result == "registry-state"
	case "legacy-connection":
		return p.Result == "legacy-tls-header-rejected"
	case "second-service-exclusivity":
		return p.Result == "second-owner-locked"
	}
	return false
}

func validLifecycleIsolationReply(request, reply *LifecycleFrame) bool {
	return request != nil && request.IsolationRequest != nil && reply != nil && reply.validate() == nil &&
		reply.Operation == "reply" && reply.Binding == request.Binding && reply.Sequence != nil && request.Sequence != nil &&
		*reply.Sequence == *request.Sequence && reply.WorkerUUID == request.WorkerUUID && reply.ServiceEpoch == request.ServiceEpoch &&
		reply.IsolationProof != nil && reply.IsolationProof.Request == *request.IsolationRequest && reply.IsolationProof.CaseName == request.Command
}

// Only the actual lifecycle service supplies observations; the private worker
// binds the authenticated request and worker identity, neither supplied by DATA.
// Exclusivity is never implemented by the original worker.
func lifecycleIsolationDispatch(service *s.LifecycleService, request, reply *LifecycleFrame) error {
	if pc.CurrentProfile() != pc.FullProfile || request == nil || request.validate() != nil ||
		(request.Command != "isolation-state" && request.Command != "legacy-connection") {
		return errFrame
	}
	proof, err := service.ProbeIsolation(request.Command)
	if err != nil {
		return err
	}
	if proof == nil {
		return errFrame
	}
	bound := *proof
	bound.Request, bound.WorkerUUID = *request.IsolationRequest, request.WorkerUUID
	reply.IsolationProof = &bound
	if !validLifecycleIsolationReply(request, reply) {
		reply.IsolationProof = nil
		return errFrame
	}
	return nil
}
