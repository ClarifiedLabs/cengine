package storageboot

import (
	"errors"
	"os"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	s "dev.cengine/guest/internal/storageservice"
)

// lifecycleWorkerConstruct runs only in the separately owned worker, after its
// credentials, ancestry and held root identity were authenticated. Initialize
// is admitted only with PID1's VerifiedFresh evidence; otherwise ReopenLifecycle
// with the predecessor's expected startup (incl. OpenRevision).
func lifecycleWorkerConstruct(root *os.File, h *lifecycleWorkerStart) (*s.LifecycleService, error) {
	if root == nil || !validLifecycleWorkerStart(h) {
		return nil, errFrame
	}
	fresh := func() error { return errors.New("configuration") }
	if h.VerifiedFresh && h.Configuration.Action == "initialize" {
		fresh = func() error { return nil } // PID1 already consumed the one-shot capability
	}
	return lifecycleConstruct(root, h.Binding, h.Configuration, fresh)
}

// serveLifecycleWorker owns the LifecycleService and its endpoints for the
// worker process lifetime. startServices must acquire every listener before
// Ready; its failure fails this worker, never PID1. stop must close transports
// and join handlers, returning ErrBusy on an incomplete join. ErrBusy skips
// service.Close, leaving the service owned by the exiting worker process; other
// stop errors permit Close only after the join. Close itself refuses active work
// under the service/authority locks and may block acquiring those locks.
// Neither returning here nor closing transports proves drain or process death:
// the executable exits on return, and PID1 must still kill/reap the predecessor
// through its sole Wait owner before admitting a replacement writer.
func serveLifecycleWorker(root *os.File, h *lifecycleWorkerStart, startServices func(*s.LifecycleService) (func() error, error), send func([]byte) error, receive func() ([]byte, error)) (err error) {
	if send == nil || receive == nil {
		return errFrame
	}
	service, err := lifecycleWorkerConstruct(root, h)
	if err != nil {
		return err
	}
	if compat, ok := any(service).(lifecycleCompatibilityService); ok && pc.CurrentProfile() == pc.FullProfile {
		if err = compat.BindPrepareCompatibilityWorker(h.WorkerUUID); err != nil {
			_ = service.Close()
			return err
		}
	}
	var stop func() error
	defer func() {
		if stop != nil {
			if stopErr := stop(); stopErr != nil {
				err = errors.Join(err, stopErr)
				if errors.Is(stopErr, a.ErrBusy) {
					return
				}
			}
		}
		err = errors.Join(err, service.Close())
	}()
	if startServices != nil {
		if stop, err = startServices(service); err != nil {
			return err
		}
	}
	ready := lifecycleFrame("ready", h.Binding)
	if ready.Ready, err = lifecyclePublicReady(service, h.WorkerUUID); err != nil {
		return err
	}
	payload, err := lifecycleFramePacket(&ready)
	if err != nil {
		return err
	}
	if err = send(payload); err != nil {
		return err
	}
	for sequence := uint64(1); sequence != 0; sequence++ {
		raw, e := receive()
		if e != nil {
			return e
		}
		request, e := readLifecycleFramePacket(raw)
		if e != nil || request.Operation != "command" || request.Binding != h.Binding || *request.Sequence != sequence ||
			request.ServiceEpoch != ready.Ready.ServiceEpoch || request.WorkerUUID != h.WorkerUUID {
			return errFrame
		}
		reply := lifecycleWorkerCommand(service, request)
		claimed := reply.Code == "" && (request.Command == "prepare-compatibility-worker-exit" && reply.PrepareCompatibilityStatus != nil || request.Command == "prepare-compatibility-checkpoint-exit" && reply.PrepareCompatibilityCheckpointAck != nil)
		payload, e := lifecycleFramePacket(reply)
		if e == nil {
			e = send(payload)
		}
		if claimed {
			if e != nil {
				select {}
			} // retain the claim; never run drain/Close on a failed ACK
			os.Exit(74) // fixed full-profile cut, deliberately bypass every defer
		}
		if e != nil {
			return e
		}
	}
	return errFrame
}

// lifecycleWorkerCommand answers one forwarded command. Admission (current pair,
// successor retention, reconcile grant) is the supervisor's; failures here are
// the closed "command" code, except typed fence contention ("worker-busy").
func lifecycleWorkerCommand(service *s.LifecycleService, request *LifecycleFrame) *LifecycleFrame {
	reply := lifecycleFrame("reply", request.Binding)
	reply.Sequence, reply.ServiceEpoch, reply.WorkerUUID = request.Sequence, request.ServiceEpoch, request.WorkerUUID
	var err error
	switch request.Command {
	case "isolation-state", "legacy-connection":
		err = lifecycleIsolationDispatch(service, request, &reply)
	case "consumer-observation-arm", "consumer-observation-query", "consumer-observation-finalize":
		err = lifecycleConsumerDispatch(service, request, &reply)
	case "prepare-compatibility-arm", "prepare-compatibility-observe", "prepare-compatibility-release", "prepare-compatibility-worker-exit", "prepare-compatibility-checkpoint-exit":
		err = lifecycleCompatibilityDispatch(service, request, &reply)
	case "issue-controller":
		cert, e := service.IssueController(request.CSR)
		if err = e; e == nil {
			reply.Certificate = cert.DER()
		}
	case "authorize-successor":
		cert, e := service.AuthorizeSuccessor(*request.Signed, request.CSR)
		if err = e; e == nil {
			reply.Certificate = cert.DER()
		}
	case "authorize-retirement":
		if err = service.AuthorizeRetirement(*request.Signed); err == nil {
			yes := true
			reply.OK = &yes
		}
	case "reconcile-controller":
		c, g := request.Controller, request.Signed.Grant
		if c.Epoch != g.ExpectedEpoch+1 || c.Key != g.NewKey {
			err = errFrame
		} else if err = service.ReconcileController(*c); err == nil {
			reply.Ready, err = lifecyclePublicReady(service, request.WorkerUUID)
		}
	case "fence-handoff":
		if request.validate() != nil {
			err = errFrame
			break
		}
		result, e := service.FenceLifecycleHandoff(*request.Handoff, request.Nonce)
		if err = e; e == nil {
			var ready *LifecycleReady
			if ready, err = lifecyclePublicReady(service, request.WorkerUUID); err == nil {
				reply.HandoffResult = &LifecycleHandoffReply{Result: result, Ready: ready}
			}
		}
	case "query":
		reply.Ready, err = lifecyclePublicReady(service, request.WorkerUUID)
	case "notifications":
		notifications := make([]a.DataHello, 0, lifecycleMaxNotifications)
	drain:
		for len(notifications) < lifecycleMaxNotifications {
			select {
			case n, ok := <-service.Notifications():
				if !ok {
					break drain
				}
				notifications = append(notifications, n.Hello)
			default:
				break drain
			}
		}
		reply.Notifications = &notifications
	default:
		err = errFrame // supervisor-owned or unknown: never forwarded
	}
	if err != nil {
		reply = lifecycleFrame("reply", request.Binding)
		reply.Sequence, reply.ServiceEpoch, reply.WorkerUUID = request.Sequence, request.ServiceEpoch, request.WorkerUUID
		reply.Code = "command"
		if request.Command == "fence-handoff" && errors.Is(err, a.ErrBusy) {
			reply.Code = "worker-busy"
		}
	}
	return &reply
}
