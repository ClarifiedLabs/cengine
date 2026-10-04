package workloadstorage

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	cc "dev.cengine/guest/internal/consumercompat"
	w "dev.cengine/guest/internal/storagewire"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	p "dev.cengine/guest/internal/storagepki"
	"dev.cengine/guest/internal/storageserver"
)

const originalConsumerBudget = 10 * time.Second
const originalCiphertextLimit = 128 << 10

// These DTOs carry observations, never storage authority or a private identity.
type OriginalConsumerArm struct {
	Version          uint32      `json:"version"`
	Profile          string      `json:"profile"`
	RequestID        string      `json:"requestID"`
	OperationUUID    string      `json:"operationUUID"`
	CaseName         string      `json:"caseName"`
	Binding          BootBinding `json:"binding"`
	Scope            Scope       `json:"scope"`
	TargetAttachment string      `json:"targetAttachment"`
	LeafSHA256       string      `json:"leafSHA256"`
}
type OriginalConsumerProbe struct {
	Arm   OriginalConsumerArm `json:"arm"`
	Scope Scope               `json:"scope"`
	Peer  Peer                `json:"peer"`
}
type OriginalConsumerPrefix struct {
	Arm                OriginalConsumerArm `json:"arm"`
	ServerPrefixBytes  uint64              `json:"serverPrefixBytes"`
	ServerPrefixSHA256 string              `json:"serverPrefixSHA256"`
}

// OriginalOperation is an owner-local operation, never a wire sequence or an
// authority admission receipt. TLS localError remains independently meaningful.
type OriginalOperation struct {
	Kind       string `json:"kind"`
	Sequence   uint64 `json:"sequence"`
	ErrorClass string `json:"errorClass"`
}
type OriginalRootRequest struct {
	Node            uint64 `json:"node"`
	RequestSequence uint64 `json:"requestSequence"`
}

type OriginalConsumerEvidence struct {
	Roots                 *OriginalRootEvidence     `json:"roots,omitempty"`
	Writable              *OriginalWritableEvidence `json:"writable,omitempty"`
	RootRequest           *OriginalRootRequest      `json:"rootRequest,omitempty"`
	Hello                 *a.DataHello              `json:"hello,omitempty"`
	Arm                   OriginalConsumerArm       `json:"arm"`
	Stage                 string                    `json:"stage"`
	Scope                 Scope                     `json:"scope"`
	KeySHA256             string                    `json:"keySHA256"`
	MountIdentitySHA256   string                    `json:"mountIdentitySHA256"`
	ServerDER_SHA256      string                    `json:"serverDERSHA256"`
	SignCount             uint64                    `json:"signCount"`
	SignInputSHA256       string                    `json:"signInputSHA256"`
	BytesWrittenAfterSign uint64                    `json:"bytesWrittenAfterSign"`
	ClientWrittenBytes    uint64                    `json:"clientWrittenBytes"`
	ClientPrefixBytes     uint64                    `json:"clientPrefixBytes"`
	ClientPrefixSHA256    string                    `json:"clientPrefixSHA256"`
	LocalError            string                    `json:"localError"`
	FDOperation           string                    `json:"fdOperation"`
	FDSequence            uint64                    `json:"fdSequence"`
	OriginalOperation     OriginalOperation         `json:"originalOperation"`
}

func originalConsumerEnabled() bool {
	return preparecompat.CurrentProfile() == preparecompat.FullProfile
}
func (a OriginalConsumerArm) valid() bool {
	if (a.Version != 1 && a.Version != 2 && a.Version != 3 && a.Version != 4 && a.Version != 5 && a.Version != 6 && a.Version != 7) || a.Profile != preparecompat.FullProfile || !id(a.RequestID) || !id(a.OperationUUID) || !id(a.Binding.ShimLaunchUUID) || !id(a.Binding.GuestBootNonce) || !validScope(a.Scope) || a.Scope.Launch != a.Binding.ShimLaunchUUID || !id(a.TargetAttachment) || !pin(a.LeafSHA256) {
		return false
	}
	if a.Version == 7 {
		return a.CaseName == "same-e-retained-fd"
	}
	if a.Version == 6 {
		return rootOriginalCase(a.CaseName)
	}
	if a.Version == 5 {
		return writableOriginalCase(a.CaseName)
	}
	if a.Version == 4 {
		return sameEOriginalCase(a.CaseName)
	}
	if a.Version == 3 {
		return a.CaseName == "cross-e-existing-data"
	}
	if a.Version == 2 {
		return cc.WrongHelloCase(a.CaseName)
	}
	switch a.CaseName {
	case "cross-e-existing-data", "cross-e-retained-fd", "cross-e-old-leaf-reconnect":
		return true
	}
	return false
}

func sameEOriginalCase(name string) bool {
	return name == cc.SameE || name == cc.SameEReconnect || registrationOriginalCase(name)
}

func registrationOriginalCase(name string) bool {
	return name == "attachment-key-reuse" || name == "delayed-registration"
}

type originalRootAttemptAttachment interface {
	OriginalConsumerRootAttempt(context.Context, a.DataHello) (c.OriginalConsumerRootRequest, error)
}

// Native factory is the only production implementer. No exported constructor,
// credential injection, path, address or caller deadline is accepted.
type originalConsumerFactory interface {
	originalConsumerObserver() *originalConsumer
	openOriginalMount(Attachment) (*os.File, string, error)
}

type originalPositiveDataAttachment interface {
	OriginalConsumerPositiveRoot(context.Context, a.DataHello) error
}

type originalDataAttachment interface {
	OriginalConsumerClosedRoot(context.Context, a.DataHello) error
}

type originalConsumer struct {
	operations                            sync.Mutex
	mu                                    sync.Mutex
	once                                  sync.Once
	arm                                   OriginalConsumerArm
	identity                              p.Identity
	peer                                  Peer
	file                                  *os.File
	writable                              *retainedFDOwner
	roots                                 *originalRootPair
	stopErr                               error
	attachment                            Attachment
	authority                             a.DataHello
	selectedHello                         a.DataHello
	evidence                              OriginalConsumerEvidence
	ctx                                   context.Context
	cancel                                context.CancelFunc
	timer                                 *time.Timer
	conn                                  net.Conn
	done                                  chan struct{}
	capture                               *originalCapture
	used, begun, probed, queried, stopped bool
}

// Reject duplicates, aliases, unknown fields, nulls and trailing data before
// ordinary json decoding. The existing workload tree scanner handles byte blobs.
func originalDecode(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > 64<<10 || !validUnicode(raw) {
		return ErrInvalidFrame
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tree, err := workloadValue(d, 0)
	if err != nil {
		return ErrInvalidFrame
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInvalidFrame
	}
	// JSON []byte fields are base64 strings, unlike ordinary workload arrays.
	if !originalShape(tree, reflect.TypeOf(value).Elem()) {
		return ErrInvalidFrame
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return ErrInvalidFrame
	}
	return nil
}
func originalShape(v any, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		return v != nil && originalShape(v, typ.Elem())
	}
	if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
		_, ok := v.(string)
		return ok
	}
	if typ.Kind() != reflect.Struct {
		return exactWorkloadShape(v, typ)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	known := 0
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")
		x, ok := m[tag[0]]
		if !ok && len(tag) == 2 && tag[1] == "omitempty" {
			continue
		}
		known++
		if !ok || !originalShape(x, f.Type) {
			return false
		}
	}
	return known == len(m)
}
func (s *Session) originalConsumerControl(operation string, raw []byte) ([]byte, error) {
	f, ok := s.factory.(originalConsumerFactory)
	if !originalConsumerEnabled() || !ok || f.originalConsumerObserver() == nil {
		return nil, ErrInvalidFrame
	}
	o := f.originalConsumerObserver()
	var arm OriginalConsumerArm
	var probe OriginalConsumerProbe
	var prefix OriginalConsumerPrefix
	switch operation {
	case "original-consumer-arm", "original-consumer-begin", "original-consumer-release", "original-consumer-positive", "original-consumer-resume":
		if originalDecode(raw, &arm) != nil {
			o.stop()
			return nil, ErrInvalidFrame
		}
	case "original-consumer-probe":
		if originalDecode(raw, &probe) != nil {
			o.probeFailure("decode", ErrInvalidFrame, ErrInvalidFrame)
			o.stop()
			return nil, ErrInvalidFrame
		}
		arm = probe.Arm
	case "original-consumer-result":
		if originalDecode(raw, &prefix) != nil {
			o.stop()
			return nil, ErrInvalidFrame
		}
		arm = prefix.Arm
	default:
		return nil, ErrInvalidFrame
	}
	if !arm.valid() {
		if operation == "original-consumer-probe" {
			o.probeFailure("arm", ErrInvalidFrame, ErrInvalidFrame)
		}
		o.stop()
		return nil, ErrInvalidFrame
	}
	if operation == "original-consumer-release" {
		o.mu.Lock()
		matches := o.used && o.arm == arm
		o.mu.Unlock()
		if !matches {
			o.stop()
			return nil, ErrInvalidFrame
		}
		if err := o.stop(); err != nil {
			return nil, err
		} // No released ACK for unjoined work.
		return json.Marshal(struct {
			Arm   OriginalConsumerArm `json:"arm"`
			Stage string              `json:"stage"`
		}{arm, "released"})
	}
	o.operations.Lock()
	result, err := func() (OriginalConsumerEvidence, error) {
		o.mu.Lock()
		invalid := o.stopped || (o.used && o.arm != arm)
		o.mu.Unlock()
		if invalid {
			if operation == "original-consumer-probe" {
				o.probeFailure("admission", ErrInvalidFrame, ErrInvalidFrame)
			}
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		switch operation {
		case "original-consumer-arm":
			return s.armOriginalConsumer(f, o, arm)
		case "original-consumer-begin", "original-consumer-resume":
			// Arm alone is not a lease, and a naturally retired session cannot
			// become ready again merely because the original identity survived.
			s.originalMu.Lock()
			defer s.originalMu.Unlock()
			s.mu.Lock()
			entry := s.entries[arm.TargetAttachment]
			live := !s.stopped && s.phase == "running" && s.scope == arm.Scope && s.binding == arm.Binding && entry != nil && entry.installed && entry.mounted && entry.attachment != nil
			s.mu.Unlock()
			if !live || entry.attachment.Err() != nil {
				return OriginalConsumerEvidence{}, ErrInvalidFrame
			}
			o.mu.Lock()
			defer o.mu.Unlock()
			if !o.used || o.begun || (arm.Version == 6 && !o.roots.live()) {
				return OriginalConsumerEvidence{}, ErrInvalidFrame
			}
			if operation == "original-consumer-resume" {
				// The surviving Session, not a shim's cached Arm, confirms the
				// exact retained original. No fresh client, FD, lease or timer.
				if arm.Version != 4 || arm.CaseName != cc.SameE || o.probed || o.queried ||
					entry.attachment != o.attachment || entry.identity.Certificate().Binding() != o.identity.Certificate().Binding() ||
					!bytes.Equal(entry.identity.Certificate().DER(), o.identity.Certificate().DER()) || o.file == nil ||
					o.evidence.Stage != "armed-mounted-positive" || o.evidence.RootRequest == nil {
					return OriginalConsumerEvidence{}, ErrInvalidFrame
				}
				select {
				case <-entry.attachment.Done():
					return OriginalConsumerEvidence{}, ErrInvalidFrame
				default:
				}
				return o.evidence, nil
			}
			o.begun = true
			o.ctx, o.cancel = context.WithTimeout(context.Background(), originalConsumerBudget)
			o.timer = time.AfterFunc(originalConsumerBudget, func() { _ = o.stop() })
			result := o.evidence
			result.Stage = "begun"
			return result, nil
		case "original-consumer-positive":
			return o.positive()
		case "original-consumer-probe":
			return o.probe(probe)
		case "original-consumer-result":
			return o.prefix(prefix)
		}
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}()
	o.operations.Unlock()
	if err != nil {
		o.stop()
		return nil, ErrInvalidFrame
	}
	return json.Marshal(result)
}

func (s *Session) armOriginalConsumer(f originalConsumerFactory, o *originalConsumer, arm OriginalConsumerArm) (_ OriginalConsumerEvidence, failure error) {
	stage := "arm-session"
	defer func() { originalArmFailure(arm, stage, failure) }()
	s.originalMu.Lock()
	defer s.originalMu.Unlock()
	o.mu.Lock()
	used := o.used
	o.mu.Unlock()
	if used || s.phase != "running" || s.activeRole != "runtime" || s.binding != arm.Binding || s.scope != arm.Scope {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	s.mu.Lock()
	e := s.entries[arm.TargetAttachment]
	valid := !s.stopped && e != nil && e.installed && e.mounted && e.attachment != nil && e.slot.Role == "runtime"
	s.mu.Unlock()
	if !valid {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	stage = "arm-issued-identity"
	binding, err := sessionBinding(s.scope, e.slot)
	if err != nil || e.binding != binding || e.identity.Certificate().Binding() != binding || SpecificationDigest(e.identity.Certificate().DER()) != arm.LeafSHA256 {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	key, err := e.key.Fingerprint()
	if err != nil {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	cert, err := p.ParseCertificateDER(e.identity.Certificate().DER(), binding)
	if err != nil {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	if _, err = cert.WithKey(e.key); err != nil {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	if _, err = verifySessionChain(cert.DER(), s.root, false); err != nil {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	if arm.Version == 6 {
		stage = "arm-root"
		return s.armOriginalRoot(f, o, arm, e, key.String())
	}
	if arm.Version == 5 || arm.Version == 7 {
		stage = "arm-writable"
		return s.armOriginalWritable(f, o, arm, e, key.String())
	}
	file, mountHash, err := f.openOriginalMount(e.attachment)
	if err != nil {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped || e.attachment.Err() != nil {
		_ = file.Close()
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		_ = file.Close()
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	if arm.CaseName == "cross-e-existing-data" {
		if _, ok := e.attachment.(originalDataAttachment); !ok {
			_ = file.Close()
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
	}
	o.used, o.arm, o.identity, o.file, o.attachment = true, arm, e.identity, file, e.attachment
	o.authority = a.DataHello{Epoch: a.ID(s.scope.ServiceEpoch), Binding: a.Binding{Store: a.ID(s.scope.Store), Volume: a.ID(e.slot.Volume), Attachment: a.ID(e.slot.Attachment), Container: a.ContainerID(s.scope.Container), Launch: a.ID(s.scope.Launch), Key: a.Fingerprint(key.String()), Role: a.RuntimeRole, Mode: a.Mode(e.slot.Mode)}}
	if cc.WrongHelloCase(arm.CaseName) {
		h, err := s.selectOriginalHello(arm.CaseName, o.authority)
		if err != nil {
			_ = file.Close()
			o.file = nil
			return OriginalConsumerEvidence{}, err
		}
		o.selectedHello = h
	}
	o.peer = s.peer
	o.peer.TLSRootDER = bytes.Clone(s.peer.TLSRootDER)
	o.peer.ServerDER = bytes.Clone(s.peer.ServerDER)
	o.evidence = OriginalConsumerEvidence{Arm: arm, Stage: "armed-mounted-positive", Scope: s.scope, KeySHA256: key.String(), MountIdentitySHA256: mountHash, FDOperation: "fsync-directory", FDSequence: 1}
	if arm.Version == 4 {
		owner, ok := e.attachment.(originalRootAttemptAttachment)
		if !ok {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		ctx, cancel := context.WithTimeout(context.Background(), originalConsumerBudget)
		defer cancel()
		o.cancel = cancel
		o.mu.Unlock()
		request, positiveErr := owner.OriginalConsumerRootAttempt(ctx, o.authority)
		o.mu.Lock()
		if positiveErr != nil || ctx.Err() != nil || o.stopped || e.attachment.Err() != nil || request.Node == 0 || request.RequestSequence == 0 {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		o.evidence.RootRequest = &OriginalRootRequest{Node: uint64(request.Node), RequestSequence: request.RequestSequence}
		o.evidence.OriginalOperation = OriginalOperation{Kind: "data-getattr-root", Sequence: 1, ErrorClass: "ok"}
	}
	if arm.Version == 3 {
		owner, ok := e.attachment.(originalPositiveDataAttachment)
		if !ok {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		ctx, cancel := context.WithTimeout(context.Background(), originalConsumerBudget)
		defer cancel()
		o.cancel = cancel
		o.mu.Unlock() // release must be able to cancel, then join via operations
		positiveErr := owner.OriginalConsumerPositiveRoot(ctx, o.authority)
		o.mu.Lock()
		if positiveErr != nil || ctx.Err() != nil || o.stopped || e.attachment.Err() != nil {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		o.evidence.OriginalOperation = OriginalOperation{Kind: "data-getattr-root", Sequence: 1, ErrorClass: "ok"}
	}
	return o.evidence, nil
}

// stop never equates a timeout with completed drain. It closes the exact owned
// socket, joins the actual probe, then releases the FD and all private references.
func (o *originalConsumer) stop() error {
	o.once.Do(func() {
		o.mu.Lock()
		// Seal publication and snapshot the owner atomically with Arm's gate.
		// Otherwise Arm can publish after stop chose the legacy cleanup path.
		o.stopped = true
		writable := o.writable
		roots := o.roots
		o.mu.Unlock()
		if roots != nil {
			o.stopErr = o.stopRoots(roots)
			return
		}
		if writable != nil {
			o.stopErr = o.stopWritable(writable)
			return
		}
		o.mu.Lock()
		o.stopped = true
		if o.cancel != nil {
			o.cancel()
		}
		if o.timer != nil {
			o.timer.Stop()
		}
		if o.conn != nil {
			_ = o.conn.Close()
		}
		done := o.done
		o.mu.Unlock()
		if done != nil {
			<-done
		}
		o.operations.Lock()
		defer o.operations.Unlock()
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.file != nil {
			_ = o.file.Close()
			o.file = nil
		}
		o.identity = p.Identity{}
		o.conn = nil
		o.attachment = nil
		if o.capture != nil {
			o.capture.clear()
			o.capture = nil
		}
	})
	return o.stopErr
}
func (o *originalConsumer) validTrust(q OriginalConsumerProbe) bool {
	if !validScope(q.Scope) || !validPeer(&q.Peer) || q.Peer.DataAddress != o.peer.DataAddress {
		return false
	}
	if rootOriginalCase(o.arm.CaseName) || cc.WrongHelloCase(o.arm.CaseName) || sameEOriginalCase(o.arm.CaseName) || o.arm.CaseName == "same-e-retained-fd" {
		return q.Scope == o.arm.Scope && q.Peer.ServerKey == o.peer.ServerKey && bytes.Equal(q.Peer.TLSRootDER, o.peer.TLSRootDER) && bytes.Equal(q.Peer.ServerDER, o.peer.ServerDER)
	}
	original, current := o.arm.Scope, q.Scope
	if current.ServiceEpoch == original.ServiceEpoch {
		return false
	}
	// Only the adopted service and its controller may differ; same launch/boot,
	// store and selected runtime slot remain pinned by the exact original arm.
	current.ServiceEpoch, current.ControllerEpoch, current.ControllerKey = original.ServiceEpoch, original.ControllerEpoch, original.ControllerKey
	return current == original
}

// A controller takeover preserves DATA authority. Re-run GETATTR through the
// exact retained Client/FIFO; the cached Arm cannot stand in for this operation.
// Uses the original Begin context and the same one-shot probe/join ownership.
func (o *originalConsumer) positive() (OriginalConsumerEvidence, error) {
	o.mu.Lock()
	if !o.begun || o.probed || o.stopped || o.ctx == nil || o.ctx.Err() != nil || o.arm.Version != 4 || o.arm.CaseName != cc.SameE || o.evidence.RootRequest == nil {
		o.mu.Unlock()
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	o.probed = true
	o.done = make(chan struct{})
	done, ctx := o.done, o.ctx
	result := o.evidence
	o.mu.Unlock()
	defer close(done)
	owner, ok := o.attachment.(originalRootAttemptAttachment)
	if !ok || o.attachment.Err() != nil {
		return result, ErrInvalidFrame
	}
	request, err := owner.OriginalConsumerRootAttempt(ctx, o.authority)
	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil || ctx.Err() != nil || o.stopped || o.attachment.Err() != nil || uint64(request.Node) != result.RootRequest.Node || request.RequestSequence <= result.RootRequest.RequestSequence {
		return result, ErrInvalidFrame
	}
	result.RootRequest = &OriginalRootRequest{Node: uint64(request.Node), RequestSequence: request.RequestSequence}
	result.OriginalOperation = OriginalOperation{Kind: "data-getattr-root", Sequence: 2, ErrorClass: "ok"}
	result.Stage = "original-data-positive"
	o.evidence = result
	return result, nil
}

func (o *originalConsumer) probe(q OriginalConsumerProbe) (OriginalConsumerEvidence, error) {
	o.mu.Lock()
	if !o.begun || o.probed || o.stopped || o.ctx.Err() != nil {
		o.mu.Unlock()
		return OriginalConsumerEvidence{}, o.probeFailure("admission", ErrInvalidFrame, ErrInvalidFrame)
	}
	if !o.validTrust(q) {
		o.mu.Unlock()
		return OriginalConsumerEvidence{}, o.probeFailure("trust", ErrInvalidFrame, ErrInvalidFrame)
	}
	o.probed = true
	o.done = make(chan struct{})
	done, ctx := o.done, o.ctx
	o.mu.Unlock()
	defer close(done)
	result := o.evidence
	result.Scope = q.Scope
	result.ServerDER_SHA256 = SpecificationDigest(q.Peer.ServerDER)
	sameE := sameEOriginalCase(o.arm.CaseName)
	if sameE && (o.arm.Version != 4 || result.RootRequest == nil || result.RootRequest.Node == 0 || result.RootRequest.RequestSequence == 0 || result.OriginalOperation != (OriginalOperation{Kind: "data-getattr-root", Sequence: 1, ErrorClass: "ok"})) {
		return result, ErrInvalidFrame
	}
	if o.arm.Version == 6 {
		var err error
		result, err = o.probeRoots(ctx, result)
		if err == nil {
			o.evidence = result
		}
		return result, err
	}
	if o.arm.Version == 5 || o.arm.Version == 7 {
		var err error
		result, err = o.probeWritable(ctx, result)
		if err != nil {
			return result, err
		}
		if o.arm.CaseName == "same-e-retained-fd" {
			o.evidence = result
			return result, nil
		}
	}
	if o.arm.CaseName == cc.SameE || registrationOriginalCase(o.arm.CaseName) {
		owner, ok := o.attachment.(originalRootAttemptAttachment)
		if !ok {
			return result, ErrInvalidFrame
		}
		request, attemptErr := owner.OriginalConsumerRootAttempt(ctx, o.authority)
		var timeout net.Error
		if !errors.Is(attemptErr, c.ErrClosed) || ctx.Err() != nil || errors.Is(attemptErr, context.Canceled) || errors.Is(attemptErr, context.DeadlineExceeded) || (errors.As(attemptErr, &timeout) && timeout.Timeout()) || errors.Is(attemptErr, c.ErrProtocol) || request.Node == 0 || uint64(request.Node) != result.RootRequest.Node || request.RequestSequence <= result.RootRequest.RequestSequence {
			return result, ErrInvalidFrame
		}
		// ErrClosed after an actual serialized request is transport loss, not
		// proof of blocked Admit. The owner must correlate the server recorder.
		result.RootRequest = &OriginalRootRequest{Node: uint64(request.Node), RequestSequence: request.RequestSequence}
		result.OriginalOperation = OriginalOperation{Kind: "data-getattr-root", Sequence: 2, ErrorClass: "transport-failed"}
		result.Stage = "original-data-attempt"
		o.evidence = result
		return result, nil
	}
	wrongHello := cc.WrongHelloCase(o.arm.CaseName)
	if wrongHello && !cc.WrongHelloMatches(o.arm.CaseName, cc.OriginalFor(o.authority), o.selectedHello) {
		return result, ErrInvalidFrame
	}
	if o.arm.Version != 5 && !sameE && !wrongHello && o.arm.CaseName != "cross-e-old-leaf-reconnect" {
		// Never send a potentially blocked FUSE syscall to an active mount.
		// Native Done is an actual Serve/abort join, not a caller retirement flag.
		select {
		case <-o.attachment.Done():
		case <-ctx.Done():
			return result, ErrInvalidFrame
		}
		if o.attachment.Err() == nil || ctx.Err() != nil {
			return result, ErrInvalidFrame
		}
		if o.arm.CaseName == "cross-e-existing-data" {
			owner, ok := o.attachment.(originalDataAttachment)
			if !ok || !errors.Is(owner.OriginalConsumerClosedRoot(ctx, o.authority), c.ErrClosed) || ctx.Err() != nil {
				return result, ErrInvalidFrame
			}
			sequence := uint64(1)
			if o.arm.Version == 3 {
				if o.evidence.OriginalOperation != (OriginalOperation{Kind: "data-getattr-root", Sequence: 1, ErrorClass: "ok"}) {
					return result, ErrInvalidFrame
				}
				sequence = 2
			}
			result.OriginalOperation = OriginalOperation{Kind: "data-getattr-root", Sequence: sequence, ErrorClass: "client-closed-joined"}
		} else {
			err := o.file.Sync()
			if ctx.Err() != nil || err == nil || originalFDError(err) == "other" {
				return result, ErrInvalidFrame
			}
			result.FDSequence = 2
			result.OriginalOperation = OriginalOperation{Kind: "fsync-directory", Sequence: 2, ErrorClass: originalFDError(err)}
		}
		// Both local negatives still require the unchanged old-leaf TLS flight
		// and independently attributed worker prefix correlation below.
	}
	cfg, witness, err := originalTLSConfig(o.identity, q.Scope, q.Peer)
	if err != nil {
		return result, o.probeFailure("tls-config", err, err)
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(o.peer.DataAddress, "2049"))
	if err != nil {
		return result, o.probeFailure("dial", err, ErrInvalidFrame)
	}
	o.mu.Lock()
	if o.stopped || ctx.Err() != nil {
		o.mu.Unlock()
		_ = raw.Close()
		return result, o.probeFailure("dial-state", ctx.Err(), ErrInvalidFrame)
	}
	capture := &originalCapture{Conn: raw, signer: witness}
	o.conn, o.capture = raw, capture
	o.mu.Unlock()
	defer raw.Close()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return result, o.probeFailure("deadline", err, ErrInvalidFrame)
	}
	conn := tls.Client(capture, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return result, o.probeFailure("tls-handshake", err, ErrInvalidFrame)
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.DidResume || state.Version != tls.VersionTLS13 {
		return result, o.probeFailure("tls-state", ErrInvalidFrame, ErrInvalidFrame)
	}
	if wrongHello || o.arm.CaseName == cc.SameEReconnect {
		var greeting w.ServerHello
		if w.ReadFrame(conn, &greeting) != nil || greeting.Epoch != o.authority.Epoch || greeting.Version != w.Version || greeting.Profile != w.RequiredProfile() {
			return result, ErrInvalidFrame
		}
		hello := o.selectedHello
		if o.arm.CaseName == cc.SameEReconnect {
			hello = o.authority
		}
		if w.WriteFrame(conn, &w.ClientHello{Authority: hello, Profile: w.RequiredProfile()}) != nil {
			return result, ErrInvalidFrame
		}
		h := hello
		result.Hello = &h
		result.OriginalOperation = OriginalOperation{Kind: "data-wrong-hello", Sequence: 1, ErrorClass: "peer-closed-before-root"}
		if o.arm.CaseName == cc.SameEReconnect {
			result.OriginalOperation = OriginalOperation{Kind: "data-original-hello", Sequence: 2, ErrorClass: "peer-closed-before-root"}
		}
	}
	// Wrong-Hello and same-E reconnect send the fixed Hello above; all cases now read
	// closure/alert only. EOF is a local class, never server rejection by itself.
	var one [1]byte
	n, readErr := conn.Read(one[:])
	var timeout net.Error
	if n != 0 || readErr == nil || ctx.Err() != nil || (sameE && ((errors.As(readErr, &timeout) && timeout.Timeout()) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded))) {
		return result, o.probeFailure("read", readErr, ErrInvalidFrame)
	}
	result.LocalError = "tls-alert-or-transport"
	if errors.Is(readErr, io.EOF) {
		result.LocalError = "eof"
	}
	witness.mu.Lock()
	result.SignCount, result.SignInputSHA256 = witness.count, witness.digest
	witness.mu.Unlock()
	capture.mu.Lock()
	result.BytesWrittenAfterSign, result.ClientWrittenBytes = capture.afterSign, uint64(len(capture.bytes))
	overflow := capture.overflow
	capture.mu.Unlock()
	if result.SignCount != 1 {
		return result, o.probeFailure("signature-count", ErrInvalidFrame, ErrInvalidFrame)
	}
	if result.BytesWrittenAfterSign == 0 {
		return result, o.probeFailure("post-sign-bytes", ErrInvalidFrame, ErrInvalidFrame)
	}
	if overflow {
		return result, o.probeFailure("capture-overflow", ErrInvalidFrame, ErrInvalidFrame)
	}
	result.Stage = "original-owner-signed-flight"
	o.evidence = result
	return result, nil
}
func (o *originalConsumer) prefix(q OriginalConsumerPrefix) (OriginalConsumerEvidence, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if sameEOriginalCase(o.arm.CaseName) || o.arm.CaseName == "same-e-retained-fd" || !o.probed || o.queried || o.stopped || o.ctx.Err() != nil || o.capture == nil || o.evidence.Stage != "original-owner-signed-flight" || q.ServerPrefixBytes == 0 || !pin(q.ServerPrefixSHA256) {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	o.queried = true
	c := o.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow || q.ServerPrefixBytes > uint64(len(c.bytes)) {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	h := sha256.New()
	_, _ = h.Write([]byte(storageserver.TLSFailurePrefixDomain))
	_, _ = h.Write(c.bytes[:int(q.ServerPrefixBytes)])
	digest := hex.EncodeToString(h.Sum(nil))
	if digest != q.ServerPrefixSHA256 {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	result := o.evidence
	result.Stage = "original-owner-prefix-correlated"
	result.ClientPrefixBytes, result.ClientPrefixSHA256 = q.ServerPrefixBytes, digest
	return result, nil
}

type originalSigner struct {
	crypto.Signer
	mu     sync.Mutex
	count  uint64
	digest string
}

func (s *originalSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count != 0 {
		return nil, ErrInvalidFrame
	}
	// crypto/tls supplies the TLS 1.3 CertificateVerify context. No arbitrary
	// public signing operation is exposed by this wrapper.
	if !bytes.Contains(digest, []byte("TLS 1.3, client CertificateVerify\x00")) {
		return nil, ErrInvalidFrame
	}
	signature, err := s.Signer.Sign(random, digest, opts)
	if err == nil {
		s.count = 1
		s.digest = SpecificationDigest(digest)
	}
	return signature, err
}

type originalCapture struct {
	net.Conn
	mu        sync.Mutex
	signer    *originalSigner
	bytes     []byte
	afterSign uint64
	overflow  bool
}

func (c *originalCapture) Write(b []byte) (int, error) {
	c.signer.mu.Lock()
	signed := c.signer.count == 1
	c.signer.mu.Unlock()
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if n < 0 || n > len(b) {
		c.overflow = true
		return n, err
	}
	if len(c.bytes)+n > originalCiphertextLimit {
		c.overflow = true
	} else {
		c.bytes = append(c.bytes, b[:n]...)
	}
	if signed && n > 0 {
		c.afterSign += uint64(n)
	}
	return n, err
}
func (c *originalCapture) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.bytes)
	c.bytes = nil
	c.signer = nil
}
func originalTLSConfig(identity p.Identity, scope Scope, peer Peer) (*tls.Config, *originalSigner, error) {
	root, err := p.ParseRootDER(peer.TLSRootDER)
	if err != nil {
		return nil, nil, ErrInvalidFrame
	}
	binding, err := p.NewServerBinding(p.StoreID(scope.Store), p.ServiceEpoch(scope.ServiceEpoch))
	if err != nil {
		return nil, nil, ErrInvalidFrame
	}
	rawPin, err := hex.DecodeString(peer.ServerKey)
	if err != nil || len(rawPin) != sha256.Size {
		return nil, nil, ErrInvalidFrame
	}
	var pin p.Fingerprint
	copy(pin[:], rawPin)
	cfg, err := p.ClientTLSConfig(identity, root, binding, pin)
	if err != nil {
		return nil, nil, ErrInvalidFrame
	}
	cert := cfg.Certificates[0]
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, ErrInvalidFrame
	}
	witness := &originalSigner{Signer: signer}
	cert.PrivateKey = witness
	cfg.Certificates = nil
	// Force the actual old leaf even when the successor advertises its new CA.
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
	verify := cfg.VerifyConnection
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verify(state); err != nil {
			return err
		}
		if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, peer.ServerDER) {
			return ErrInvalidFrame
		}
		return nil
	}
	cfg.ClientSessionCache = nil
	cfg.SessionTicketsDisabled = true
	return cfg, witness, nil
}

func (s *Session) selectOriginalHello(name string, original a.DataHello) (a.DataHello, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := original
	switch name {
	case cc.WrongMode:
		if h.Binding.Mode != a.ReadOnly {
			return a.DataHello{}, ErrInvalidFrame
		}
		h.Binding.Mode = a.ReadWrite
	case cc.WrongEpoch:
		e := []byte(h.Epoch)
		if e[0] == '0' {
			e[0] = '1'
		} else {
			e[0] = '0'
		}
		h.Epoch = a.ID(e)
	case cc.WrongVolume:
		// Exactly two installed runtime credentials; no convenient fallback past
		// an unmounted, dead or conflicting issued entry. PREPARE is independent.
		var entries []*sessionAttachment
		for id, e := range s.entries {
			if e == nil || !e.installed || e.slot.Role != "runtime" {
				continue
			}
			if id != e.slot.Attachment || !e.mounted || e.attachment == nil || e.attachment.Err() != nil {
				return a.DataHello{}, ErrInvalidFrame
			}
			select {
			case <-e.attachment.Done():
				return a.DataHello{}, ErrInvalidFrame
			default:
			}
			binding, err := sessionBinding(s.scope, e.slot)
			if err != nil || e.binding != binding || e.identity.Certificate().Binding() != binding {
				return a.DataHello{}, ErrInvalidFrame
			}
			if _, err = verifySessionChain(e.identity.Certificate().DER(), s.root, false); err != nil {
				return a.DataHello{}, ErrInvalidFrame
			}
			if _, err = e.identity.Certificate().WithKey(e.key); err != nil {
				return a.DataHello{}, ErrInvalidFrame
			}
			entries = append(entries, e)
		}
		if len(entries) != 2 {
			return a.DataHello{}, ErrInvalidFrame
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].slot.Attachment < entries[j].slot.Attachment })
		first, other := entries[0], entries[1]
		key, err := first.key.Fingerprint()
		otherKey, otherErr := other.key.Fingerprint()
		if err != nil || otherErr != nil || a.ID(first.slot.Attachment) != h.Binding.Attachment || a.ID(first.slot.Volume) != h.Binding.Volume || a.Fingerprint(key.String()) != h.Binding.Key || a.Mode(first.slot.Mode) != h.Binding.Mode || first.slot.Volume == other.slot.Volume || key == otherKey || bytes.Equal(first.identity.Certificate().DER(), other.identity.Certificate().DER()) {
			return a.DataHello{}, ErrInvalidFrame
		}
		h.Binding.Volume = a.ID(other.slot.Volume)
	case cc.WrongKey, cc.WrongRole:
		ids := make([]string, 0, len(s.entries))
		for id := range s.entries {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		found := false
		for _, id := range ids {
			e := s.entries[id]
			if e == nil || !e.installed {
				continue
			}
			binding, err := sessionBinding(s.scope, e.slot)
			if err != nil || e.binding != binding || e.identity.Certificate().Binding() != binding {
				continue
			}
			if _, err = verifySessionChain(e.identity.Certificate().DER(), s.root, false); err != nil {
				continue
			}
			if _, err = e.identity.Certificate().WithKey(e.key); err != nil {
				continue
			}
			key, err := e.key.Fingerprint()
			if err != nil {
				continue
			}
			if name == cc.WrongRole {
				if e.slot.Role != "prepare" || a.ID(e.slot.Volume) != h.Binding.Volume || !cc.ID(s.scope.Prepare) {
					continue
				}
				h.Binding.Role, h.Binding.Prepare = a.PrepareRole, a.ID(s.scope.Prepare)
			} else {
				if a.ID(e.slot.Attachment) == h.Binding.Attachment {
					continue
				}
				if e.slot.Role != "prepare" && (e.slot.Role != "runtime" || !e.mounted || e.attachment == nil || e.attachment.Err() != nil) {
					continue
				}
				if a.Fingerprint(key.String()) == h.Binding.Key {
					continue
				}
				h.Binding.Key = a.Fingerprint(key.String())
			}
			found = true
			break
		}
		if !found {
			return a.DataHello{}, ErrInvalidFrame
		}
	default:
		return a.DataHello{}, ErrInvalidFrame
	}
	if !cc.WrongHelloMatches(name, cc.OriginalFor(original), h) {
		return a.DataHello{}, ErrInvalidFrame
	}
	return h, nil
}
