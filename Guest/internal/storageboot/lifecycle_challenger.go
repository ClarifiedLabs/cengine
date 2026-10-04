package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"
	"unicode/utf8"

	"dev.cengine/guest/internal/diskbootstrap"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	service "dev.cengine/guest/internal/storageservice"
	"golang.org/x/sys/unix"
)

// Separate closed private variant: not a LifecycleConfiguration/action=open,
// not a replacement authorization, and never a source of Ready or listeners.
type lifecycleWorkerChallenge struct {
	Version          uint32                       `json:"version"`
	Type             string                       `json:"type"`
	Operation        string                       `json:"operation"`
	WorkerUUID       string                       `json:"workerUUID"`
	Binding          diskbootstrap.StorageBinding `json:"binding"`
	Root             workerRootIdentity           `json:"root"`
	RootPublicKey    []byte                       `json:"rootPublicKey"`
	Current          a.SignedLifecycleGrant       `json:"current"`
	NowUnixSeconds   uint64                       `json:"nowUnixSeconds"`
	LifetimeSeconds  uint64                       `json:"lifetimeSeconds"`
	Predecessor      p.LifecycleServiceState      `json:"predecessor"`
	IsolationRequest service.IsolationRequest     `json:"isolationRequest"`
}

func validLifecycleWorkerChallenge(h *lifecycleWorkerChallenge) bool {
	if h == nil || h.Version != 2 || h.Type != lifecycleWorkerType || h.Operation != "challenge" || !id(h.WorkerUUID) ||
		!validBinding(h.Binding) || h.Root.Device == 0 || h.Root.Inode == 0 || h.Root.MountID == 0 ||
		!validIsolationRequest(&h.IsolationRequest) || h.NowUnixSeconds == 0 || h.NowUnixSeconds > 253402214399 ||
		h.LifetimeSeconds == 0 || h.LifetimeSeconds > 86400 || h.Predecessor.Validate() != nil ||
		h.Current.Grant != h.Predecessor.Grant || !lifecycleRootSigned(h.RootPublicKey, h.Current) {
		return false
	}
	root, err := p.PublicKeyFingerprint(ed25519.PublicKey(h.RootPublicKey))
	return err == nil && root.String() == h.Predecessor.Boot.BootstrapKey
}

func decodeLifecycleWorkerChallenge(raw []byte) (*lifecycleWorkerChallenge, error) {
	if len(raw) == 0 || len(raw) > lifecyclePacketMax || !utf8.Valid(raw) {
		return nil, errFrame
	}
	h := new(lifecycleWorkerChallenge)
	if json.Unmarshal(raw, h) != nil || !validLifecycleWorkerChallenge(h) {
		return nil, errFrame
	}
	canonical, err := lifecycleCanonical(h)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errFrame
	}
	return h, nil
}

func encodeLifecycleWorkerChallenge(h lifecycleWorkerChallenge) ([]byte, error) {
	raw, err := lifecycleCanonical(&h)
	if err != nil {
		return nil, err
	}
	if _, err = decodeLifecycleWorkerChallenge(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Byte-exact echo binds refusal to the entire authenticated challenge packet.
func lifecycleLockRefusalPacket(h lifecycleWorkerChallenge) ([]byte, error) {
	if !validLifecycleWorkerChallenge(&h) {
		return nil, errFrame
	}
	h.Operation = "locked"
	return lifecycleCanonical(&h)
}

// Linux verifies mount identity/ext4 and kernel channel provenance before entry.
// Portable fstat additionally checks this actual descriptor before construction.
func lifecycleServiceLockRefusal(root *os.File, h lifecycleWorkerChallenge) ([]byte, error) {
	if pc.CurrentProfile() != pc.FullProfile || root == nil || !validLifecycleWorkerChallenge(&h) {
		return nil, errFrame
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(root.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != h.Root.Device || st.Ino != h.Root.Inode {
		return nil, errFrame
	}
	bootstrap, err := p.NewBootstrapPublicKey(ed25519.PublicKey(h.RootPublicKey))
	if err != nil {
		return nil, err
	}
	cfg := service.Config{Root: root, DeviceUUID: h.Binding.Ext4UUID, Store: h.Current.Grant.Identity.Store, Bootstrap: bootstrap,
		Now: time.Unix(int64(h.NowUnixSeconds), 0), Lifetime: time.Duration(h.LifetimeSeconds) * time.Second}
	prior := h.Predecessor
	owner, err := service.ReopenLifecycle(cfg, h.Current.Grant.Identity, h.Current, a.ExpectedLifecycleStartup{
		ExpectedStartup: a.ExpectedStartup{Store: prior.Grant.Identity.Store, Epoch: a.ID(prior.Context.ServiceEpoch), Controller: a.Controller{Epoch: prior.Context.ControllerEpoch, Key: a.Fingerprint(prior.Context.ControllerKey)}}, OpenRevision: prior.OpenRevision})
	if owner != nil {
		return nil, errors.Join(a.ErrConflict, owner.Close())
	}
	if !errors.Is(err, a.ErrLocked) {
		return nil, errors.Join(a.ErrConflict, err)
	}
	return lifecycleLockRefusalPacket(h)
}

type lifecycleServiceChallenger interface {
	challenge(lifecycleWorkerChallenge, workerStartGate) (lifecycleWorker, error)
}

// Caller holds mu. Reserve ownership before unlocking: close must join even a
// launcher which has not returned its partially started owner yet.
func (s *lifecycleSupervisor) challengeLocked(request *LifecycleFrame) (*LifecycleFrame, string) {
	launcher, ok := s.worker.(lifecycleServiceChallenger)
	if !ok || pc.CurrentProfile() != pc.FullProfile || request.validate() != nil || s.challenger != nil || s.successor != nil {
		s.mu.Unlock()
		return nil, "command"
	}
	workerID, err := newWorkerUUID()
	if err != nil || workerID == s.ready.WorkerUUID {
		s.mu.Unlock()
		return nil, "command"
	}
	original, ready := s.worker, copyLifecycleReady(s.ready)
	// Snapshot CURRENT reconciled grant, never the original startup configuration.
	h := lifecycleWorkerChallenge{Version: 2, Type: lifecycleWorkerType, Operation: "challenge", WorkerUUID: workerID, Binding: request.Binding,
		RootPublicKey: bytes.Clone(s.root), Current: copyLifecycleSigned(s.signed), NowUnixSeconds: s.now, LifetimeSeconds: s.lifetime,
		Predecessor: lifecycleServiceState(ready, s.signed.Grant), IsolationRequest: *request.IsolationRequest}
	stateRequest := *request
	isolation := *request.IsolationRequest
	sequence := *request.Sequence
	stateRequest.IsolationRequest, stateRequest.Sequence, stateRequest.Command = &isolation, &sequence, "isolation-state"
	s.active = true
	s.joining.Add(1)
	s.mu.Unlock()
	defer s.joining.Done()
	child, launchErr := launcher.challenge(h, s.startGate)
	s.mu.Lock()
	s.challenger = child // retain even a failed/partial launcher result
	closed := s.closed
	s.mu.Unlock()
	if child != nil && (launchErr != nil || closed) {
		_ = child.kill()
	}
	joined := false
	if child != nil {
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-child.done():
			joined = child.reaped()
		case <-timer.C:
		}
		timer.Stop()
	}
	s.mu.Lock()
	if !joined {
		if child != nil {
			_ = child.kill()
		}
		s.active, s.failed = false, true
		s.mu.Unlock()
		if child == nil {
			return nil, "command"
		}
		return nil, "worker-unreaped"
	}
	// close waits joining, so only this operation may release the reaped child.
	if err := child.close(); err != nil {
		s.active, s.failed = false, true
		s.mu.Unlock()
		return nil, "worker-unreaped"
	}
	s.challenger = nil
	if launchErr != nil || s.closed || lifecycleWorkerExited(original) {
		s.active, s.failed = false, true
		s.mu.Unlock()
		return nil, "command"
	}
	s.mu.Unlock()
	// Only authenticated exact refusal AND positive sole Wait permit observation
	// on the original. Neither timeout/EOF nor kill/reap can stand in for refusal.
	reply, err := original.exchange(&stateRequest)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	if err != nil || s.closed || lifecycleWorkerExited(original) || !validLifecycleIsolationReply(&stateRequest, reply) ||
		reply.IsolationProof.Store != string(ready.Identity.Store) || reply.IsolationProof.Revision < ready.Revision {
		s.failed = true
		return nil, "command"
	}
	out := *reply
	proof := *reply.IsolationProof
	proof.CaseName, proof.Result = "second-service-exclusivity", "second-owner-locked"
	out.IsolationProof = &proof
	return &out, ""
}
