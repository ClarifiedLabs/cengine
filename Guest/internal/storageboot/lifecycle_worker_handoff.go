package storageboot

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"dev.cengine/guest/internal/diskbootstrap"
	"dev.cengine/guest/internal/storageworker"
)

// lifecycleWorkerType names the closed v2 worker start packet. It is accepted
// only over storageworker's per-packet kernel-credential channel (FD3), never
// vsock or argv/environment. Binding and root identity come from PID1's held
// VerifiedBootResult. VerifiedFresh is PID1-private evidence: it is set only
// after PID1 itself consumed FreshInitialization for the initial initialize.
const lifecycleWorkerType = "storage-lifecycle-worker.v2"

// storageworker.MaxPayload; duplicated so the codec stays portable.
const lifecyclePacketMax = 65536

type lifecycleWorkerStart struct {
	Version           uint32                       `json:"version"`
	Type              string                       `json:"type"`
	Operation         string                       `json:"operation"`
	WorkerUUID        string                       `json:"workerUUID"`
	Binding           diskbootstrap.StorageBinding `json:"binding"`
	Root              workerRootIdentity           `json:"root"`
	Configuration     LifecycleConfiguration       `json:"configuration"`
	ManagementAddress string                       `json:"managementAddress"`
	VerifiedFresh     bool                         `json:"verifiedFresh"`
	VerifiedResume    bool                         `json:"verifiedResume"`
}

func validLifecycleWorkerStart(h *lifecycleWorkerStart) bool {
	return h != nil && h.Version == 2 && h.Type == lifecycleWorkerType && h.Operation == "start" && id(h.WorkerUUID) &&
		validBinding(h.Binding) && h.Root.Device != 0 && h.Root.Inode != 0 && h.Root.MountID != 0 &&
		h.Configuration.validate() == nil && lifecycleColdBindingValid(h.Configuration, h.Binding) && lifecycleRootSigned(h.Configuration.RootPublicKey, h.Configuration.Signed) &&
		validManagementAddress(h.ManagementAddress) &&
		// Initialize requires PID1's fresh evidence; open (incl. replacement) never carries it.
		h.VerifiedFresh == (h.Configuration.Action == "initialize") &&
		// Resume evidence is PID1-private, set only after the opaque RO lease
		// passed signed admission/census and journaled RW promotion under
		// the same device lock; Root identifies the newly pinned mount.
		h.VerifiedResume == (h.Configuration.Action == "resume-open-takeover")
}

// Strict closed decode: canonical bytes only, so unknown/duplicate/reordered
// fields and trailing data are all rejected.
func decodeLifecycleWorkerStart(data []byte) (*lifecycleWorkerStart, error) {
	if len(data) == 0 || len(data) > lifecyclePacketMax || !utf8.Valid(data) {
		return nil, errFrame
	}
	h := new(lifecycleWorkerStart)
	if json.Unmarshal(data, h) != nil || !validLifecycleWorkerStart(h) {
		return nil, errFrame
	}
	canonical, err := lifecycleCanonical(h)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, errFrame
	}
	return h, nil
}
func encodeLifecycleWorkerStart(h lifecycleWorkerStart) ([]byte, error) {
	data, err := lifecycleCanonical(&h)
	if err != nil {
		return nil, errFrame
	}
	if _, err = decodeLifecycleWorkerStart(data); err != nil {
		return nil, err
	}
	return data, nil
}

func lifecycleFramePacket(f *LifecycleFrame) ([]byte, error) {
	raw, err := EncodeLifecycleFrame(f)
	if err != nil || len(raw) > lifecyclePacketMax {
		return nil, errFrame
	}
	return raw, nil
}
func readLifecycleFramePacket(raw []byte) (*LifecycleFrame, error) {
	r := bytes.NewReader(raw)
	f, err := ReadLifecycleFrame(r)
	if err != nil || r.Len() != 0 {
		return nil, errFrame
	}
	return f, nil
}

// The caller must first authenticate the packet's kernel credentials.
func readLifecycleWorkerReady(raw []byte, binding diskbootstrap.StorageBinding, workerID string) (*LifecycleReady, error) {
	f, err := readLifecycleFramePacket(raw)
	if err != nil || f.Operation != "ready" || f.Binding != binding || f.Ready.WorkerUUID != workerID {
		return nil, errFrame
	}
	return f.Ready, nil
}

// lifecycleFreshGate is PID1's single consumer of FreshInitialization. Only an
// initialize start (the initial configure) consumes it, exactly once; open and
// replacement starts never touch it.
type lifecycleFreshGate struct {
	mu    sync.Mutex
	fresh func() error
	used  bool
}

func (g *lifecycleFreshGate) take(action string) (bool, error) {
	if action != "initialize" {
		return false, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used || g.fresh == nil {
		return false, errors.New("configuration")
	}
	g.used = true
	if err := g.fresh(); err != nil {
		return false, err
	}
	return true, nil
}

// lifecyclePacketWorker is the portable PID1-side handle: exchange rewrites the
// host sequence to a private per-worker sequence and restores it on the reply.
// Process ownership (kill/done/reaped/close) is supplied by the launcher.
type lifecyclePacketWorker struct {
	challengeStart func(lifecycleWorkerChallenge, workerStartGate) (lifecycleWorker, error)
	pidf           func() int
	waitf          func() (storageworker.WaitResult, bool)
	mu             sync.Mutex
	sequence       uint64
	binding        diskbootstrap.StorageBinding
	send           func([]byte) ([]byte, error)
	sendFence      func([]byte, time.Time) ([]byte, error)
	receivePending func(time.Time) ([]byte, error)
	pendingFence   *LifecycleFrame // one canonical private sequence/original nonce
	killf          func() error
	doneCh         <-chan struct{}
	reapedf        func() bool
	closef         func() error
}

func (w *lifecyclePacketWorker) challenge(h lifecycleWorkerChallenge, gate workerStartGate) (lifecycleWorker, error) {
	if w.challengeStart == nil {
		return nil, errFrame
	}
	return w.challengeStart(h, gate)
}

func (w *lifecyclePacketWorker) workerPID() int {
	if w.pidf == nil {
		return 0
	}
	return w.pidf()
}
func (w *lifecyclePacketWorker) workerWaitResult() (storageworker.WaitResult, bool) {
	if w.waitf == nil {
		return storageworker.WaitResult{}, false
	}
	return w.waitf()
}
func (w *lifecyclePacketWorker) kill() error           { return w.killf() }
func (w *lifecyclePacketWorker) done() <-chan struct{} { return w.doneCh }
func (w *lifecyclePacketWorker) reaped() bool          { return w.reapedf() }
func (w *lifecyclePacketWorker) close() error          { return w.closef() }

// Each receive has two seconds: drain plus fresh exchange remains below the
// outer five-second control deadline, with room to return worker-busy.
const lifecycleFenceReplyBudget = 2 * time.Second

type lifecycleFencePendingError struct{}

func (*lifecycleFencePendingError) Error() string { return "fence reply pending" }

func sameLifecycleFence(x, y *LifecycleFrame) bool {
	if x == nil || y == nil || x.Command != "fence-handoff" || y.Command != x.Command ||
		x.Binding != y.Binding || x.ServiceEpoch != y.ServiceEpoch || x.WorkerUUID != y.WorkerUUID || y.validate() != nil {
		return false
	}
	xb, xe := lifecycleCanonical(x.Handoff)
	yb, ye := lifecycleCanonical(y.Handoff)
	return xe == nil && ye == nil && bytes.Equal(xb, yb)
}

func (w *lifecyclePacketWorker) exchange(request *LifecycleFrame) (*LifecycleFrame, error) {
	return w.exchangeValidated(request, nil)
}

func (w *lifecyclePacketWorker) exchangeValidated(request *LifecycleFrame, validate func(*LifecycleFrame, *LifecycleFrame) bool) (*LifecycleFrame, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if request == nil || request.Sequence == nil || request.Binding != w.binding || w.sequence == ^uint64(0) {
		return nil, errFrame
	}
	deadline := time.Now().Add(lifecycleFenceReplyBudget)
	if w.pendingFence != nil {
		if !sameLifecycleFence(w.pendingFence, request) {
			return nil, &lifecycleFencePendingError{}
		}
		if w.receivePending == nil || validate == nil {
			return nil, errFrame
		}
		raw, err := w.receivePending(deadline)
		if err != nil {
			var pending *storageworker.ReplyPendingError
			if errors.As(err, &pending) {
				return nil, &lifecycleFencePendingError{}
			}
			return nil, err
		}
		old := w.pendingFence
		reply, err := readLifecycleFramePacket(raw)
		if err != nil || !validLifecyclePacketReply(old, reply) || !validate(old, reply) {
			return nil, errFrame
		}
		// This receipt is correlated ONLY to the original nonce and sequence.
		// Discard it, then ask the same worker for a fresh correlated receipt.
		w.pendingFence = nil
		deadline = time.Now().Add(lifecycleFenceReplyBudget)
	}
	w.sequence++
	f := *request
	sequence := w.sequence
	f.Sequence = &sequence
	payload, err := lifecycleFramePacket(&f)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if request.Command == "fence-handoff" && w.sendFence != nil {
		raw, err = w.sendFence(payload, deadline)
	} else {
		raw, err = w.send(payload)
	}
	if err != nil {
		var pending *storageworker.ReplyPendingError
		if request.Command == "fence-handoff" && validate != nil && w.receivePending != nil && errors.As(err, &pending) {
			// Decode our canonical bytes to own every retained slice and pointer.
			retained, decodeErr := readLifecycleFramePacket(payload)
			if decodeErr != nil {
				return nil, decodeErr
			}
			w.pendingFence = retained
			return nil, &lifecycleFencePendingError{}
		}
		return nil, err
	}
	reply, err := readLifecycleFramePacket(raw)
	if err != nil || !validLifecyclePacketReply(&f, reply) {
		return nil, errFrame
	}
	reply.Sequence = request.Sequence
	return reply, nil
}

func validLifecyclePacketReply(request, reply *LifecycleFrame) bool {
	return reply != nil && reply.Operation == "reply" && reply.Binding == request.Binding && reply.Sequence != nil &&
		*reply.Sequence == *request.Sequence && reply.ServiceEpoch == request.ServiceEpoch && reply.WorkerUUID == request.WorkerUUID
}
