//go:build linux

package storageboot

import (
	"bytes"
	"os"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	pc "dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/storageworker"
)

func launchLifecycleChallenge(root *os.File, identity workerRootIdentity, binding diskbootstrap.StorageBinding, h lifecycleWorkerChallenge, gate workerStartGate) (lifecycleWorker, error) {
	// Refuse ordinary builds before even inspecting a descriptor or launching.
	if pc.CurrentProfile() != pc.FullProfile || gate == nil || h.Binding != binding {
		return nil, errFrame
	}
	h.Root = identity
	if !validLifecycleWorkerChallenge(&h) {
		return nil, errFrame
	}
	current, err := heldWorkerRoot(root)
	if err != nil || current != identity {
		return nil, errFrame
	}
	raw, err := encodeLifecycleWorkerChallenge(h)
	if err != nil {
		return nil, err
	}
	owner, err := storageworker.StartLifecycle(root)
	if owner == nil {
		return nil, err
	}
	child := &lifecyclePacketWorker{pidf: owner.PID, waitf: owner.Result, binding: binding, killf: owner.Kill, doneCh: owner.Done(), closef: owner.Close,
		reapedf: func() bool { result, observed := owner.Result(); return observed && result.Reaped }}
	if err != nil {
		return child, err
	}
	// ExchangeWithGate uses the pinned birth pidfd and per-packet kernel
	// credentials. EOF, deadlines and arbitrary bytes are never a refusal.
	reply, err := owner.ExchangeWithGate(raw, time.Now().Add(workerCommandBudget), gate)
	if err != nil {
		return child, err
	}
	expected, err := lifecycleLockRefusalPacket(h)
	if err != nil || !bytes.Equal(reply, expected) {
		return child, errFrame
	}
	return child, nil // supervisor must still observe sole Done + positive reap
}
