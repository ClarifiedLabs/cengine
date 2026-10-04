//go:build linux

package storageboot

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	pc "dev.cengine/guest/internal/preparecompat"
	s "dev.cengine/guest/internal/storageservice"
	"dev.cengine/guest/internal/storageworker"
	"dev.cengine/guest/internal/vsock"
)

// processLifecycleStarter is PID1's v2 launcher. PID1 retains the held root and
// the 4106 session; each start launches a separately owned storageworker child
// (birth pidfd, sole cmd.Wait, FD3 per-packet credentials, FD4 verified root)
// that owns the LifecycleService and all endpoints.
func processLifecycleStarter(root *os.File, binding diskbootstrap.StorageBinding, address string, fresh func() error) (lifecycleWorkerStarter, error) {
	return processLifecycleStarterWithResume(root, binding, address, fresh, &lifecycleResumeGate{}, nil)
}

func processLifecycleStarterWithResume(root *os.File, binding diskbootstrap.StorageBinding, address string, fresh func() error, resume *lifecycleResumeGate, promotedRoot func() (*os.File, error)) (lifecycleWorkerStarter, error) {
	if !validBinding(binding) || !validManagementAddress(address) || fresh == nil || resume == nil {
		return nil, errors.New("configuration")
	}
	var identity workerRootIdentity
	if resume.probe {
		// No RO descriptor may survive into promotion. The new journaled
		// mount is pinned only after the real lease has completed the swap.
		if root != nil || promotedRoot == nil {
			return nil, errors.New("configuration")
		}
	} else {
		var err error
		identity, err = heldWorkerRoot(root)
		if err != nil {
			return nil, err
		}
	}
	gate := &lifecycleFreshGate{fresh: fresh}
	return func(cfg LifecycleConfiguration, workerID string, startGate workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
		// Verify before any filesystem mutation or fresh consumption.
		if cfg.validate() != nil || !lifecycleRootSigned(cfg.RootPublicKey, cfg.Signed) {
			return nil, nil, errors.New("configuration")
		}
		if !lifecycleColdBindingValid(cfg, binding) {
			return nil, nil, errors.New("configuration")
		}
		verifiedResume, err := resume.take(cfg)
		if err != nil {
			return nil, nil, err
		}
		if verifiedResume {
			root, err = promotedRoot()
			if err != nil {
				return nil, nil, err
			}
			identity, err = heldWorkerRoot(root)
			if err != nil {
				return nil, nil, err
			}
		}
		verifiedFresh, err := gate.take(cfg.Action) // open/replacement never consumes
		if err != nil {
			return nil, nil, err
		}
		// Revalidate the SAME held root before every child launch. Never reopen a path.
		current, err := heldWorkerRoot(root)
		if err != nil || current != identity {
			return nil, nil, errors.New("configuration")
		}
		raw, err := encodeLifecycleWorkerStart(lifecycleWorkerStart{Version: 2, Type: lifecycleWorkerType, Operation: "start", WorkerUUID: workerID,
			Binding: binding, Root: identity, Configuration: copyLifecycleConfiguration(cfg), ManagementAddress: address, VerifiedFresh: verifiedFresh, VerifiedResume: verifiedResume})
		if err != nil {
			return nil, nil, err
		}
		owner, err := storageworker.StartLifecycle(root)
		if owner == nil {
			return nil, nil, err
		}
		worker := &lifecyclePacketWorker{pidf: owner.PID, waitf: owner.Result, binding: binding, killf: owner.Kill, doneCh: owner.Done(), closef: owner.Close,
			reapedf:        func() bool { r, observed := owner.Result(); return observed && r.Reaped },
			receivePending: owner.ReceivePending,
			sendFence:      owner.Exchange,
			send: func(payload []byte) ([]byte, error) {
				return owner.Exchange(payload, time.Now().Add(workerCommandBudget))
			}}
		worker.challengeStart = func(h lifecycleWorkerChallenge, gate workerStartGate) (lifecycleWorker, error) {
			return launchLifecycleChallenge(root, identity, binding, h, gate)
		}
		if err != nil {
			return worker, nil, err
		}
		// Only the handoff send is bounded; durable opening has no disk deadline.
		reply, err := owner.ExchangeWithGate(raw, time.Now().Add(workerCommandBudget), func(send func() error) error {
			if err := startGate(send); err != nil {
				return err
			}
			return owner.SetDeadline(time.Time{})
		})
		if err != nil {
			return worker, nil, err
		}
		ready, err := readLifecycleWorkerReady(reply, binding, workerID)
		if err != nil {
			return worker, nil, err
		}
		return worker, ready, nil
	}, nil
}

// RunLifecycleWorker is reachable only from the executable's fixed
// --managed-lifecycle-worker dispatch. Channel credentials/ancestry (Accept),
// the held ext4 identity and the closed start packet all precede construction.
// Endpoint failure cancels this worker (closing its channel) and never PID1.
func RunLifecycleWorker() error {
	child, err := storageworker.Accept()
	if err != nil {
		return err
	}
	defer child.Close()
	raw, err := child.Receive()
	if err != nil {
		return err
	}
	// Accept/Receive above authenticate PID1 before inspecting either closed
	// variant. The held-root check precedes all challenge constructor IO.
	if challenge, decodeErr := decodeLifecycleWorkerChallenge(raw); decodeErr == nil {
		if pc.CurrentProfile() != pc.FullProfile {
			return errFrame
		}
		identity, err := heldWorkerRoot(child.Root)
		if err != nil || identity != challenge.Root {
			return errors.New("configuration")
		}
		refusal, err := lifecycleServiceLockRefusal(child.Root, *challenge)
		if err != nil {
			return err
		}
		return child.Send(refusal)
	}
	h, err := decodeLifecycleWorkerStart(raw)
	if err != nil {
		return err
	}
	identity, err := heldWorkerRoot(child.Root)
	if err != nil || identity != h.Root {
		return errors.New("configuration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unwatch := context.AfterFunc(ctx, func() { _ = child.Channel.Close() })
	defer unwatch()
	return serveLifecycleWorker(child.Root, h, func(service *s.LifecycleService) (func() error, error) {
		return startLifecycleServices(ctx, cancel, service, net.JoinHostPort(h.ManagementAddress, "2049"), vsock.Listen, net.Listen, 5*time.Second)
	}, child.Send, child.Receive)
}
