package workloadstorage

import (
	"bytes"
	"context"
	"encoding/json"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	p "dev.cengine/guest/internal/storagepki"
)

// Writable evidence reports actual syscalls and original-client serialization.
// It is not a retirement receipt, admission denial, or backing-store snapshot.
type OriginalWritableEvidence struct {
	IdentitySHA256 string                       `json:"identitySHA256"`
	Written        int                          `json:"written"`
	WriteError     string                       `json:"writeError"`
	SyncError      string                       `json:"syncError"`
	Completed      bool                         `json:"completed"`
	Trace          *c.OriginalConsumerFileTrace `json:"trace,omitempty"`
}

type originalWritableFactory interface {
	newOriginalWritableFD(Attachment) *retainedFDOwner
}
type originalWritableAttachment interface {
	BeginOriginalConsumerFile(a.DataHello, bool) error
	EndOriginalConsumerFile(a.DataHello) (c.OriginalConsumerFileTrace, error)
}

type originalCapabilityAttachment interface {
	BeginOriginalConsumerCapabilityFile(a.DataHello) error
}

func writableOriginalCase(name string) bool {
	return name == "same-e-retained-fd" || name == "cross-e-retained-fd"
}
func writableIdentity(identity retainedFDIdentity) string {
	raw, _ := json.Marshal(struct{ Device, Inode, Mount uint64 }{identity.device, identity.inode, identity.mount})
	return SpecificationDigest(raw)
}
func writableError(err error) string {
	if err == nil {
		return "ok"
	}
	return originalFDError(err)
}
func writableOutcome(result retainedFDResult) *OriginalWritableEvidence {
	return &OriginalWritableEvidence{IdentitySHA256: writableIdentity(result.identity), Written: result.written,
		WriteError: writableError(result.writeErr), SyncError: writableError(result.syncErr), Completed: result.completed}
}
func writableDeniedError(value string) bool {
	return value == "eio" || value == "enotconn" || value == "estale" || value == "eacces"
}

func waitOriginalDeniedMount(ctx context.Context, attachment Attachment) error {
	select {
	case <-attachment.Done():
	case <-ctx.Done():
		return ctx.Err()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if attachment.Err() == nil {
		return ErrInvalidFrame
	}
	return nil
}

// Called only after Session has validated the actual issued identity and exact
// installed RUNNING slot. The owner is published before any acquisition syscall.
func (s *Session) armOriginalWritable(factory originalConsumerFactory, o *originalConsumer, arm OriginalConsumerArm, e *sessionAttachment, key string) (_ OriginalConsumerEvidence, failure error) {
	stage := "writable-owner"
	defer func() { originalArmFailure(arm, stage, failure) }()
	f, ok := factory.(originalWritableFactory)
	traceOwner, traceOK := e.attachment.(originalWritableAttachment)
	if !ok || !traceOK || e.slot.Mode != "read-write" {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	ctx, cancel := context.WithTimeout(context.Background(), originalConsumerBudget)
	defer cancel()
	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	owner := f.newOriginalWritableFD(e.attachment)
	if owner == nil {
		o.mu.Unlock()
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	o.used, o.arm, o.identity, o.attachment, o.writable, o.cancel = true, arm, e.identity, e.attachment, owner, cancel
	o.authority = a.DataHello{Epoch: a.ID(s.scope.ServiceEpoch), Binding: a.Binding{Store: a.ID(s.scope.Store), Volume: a.ID(e.slot.Volume), Attachment: a.ID(e.slot.Attachment), Container: a.ContainerID(s.scope.Container), Launch: a.ID(s.scope.Launch), Key: a.Fingerprint(key), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	o.peer = s.peer
	o.peer.TLSRootDER = bytes.Clone(s.peer.TLSRootDER)
	o.peer.ServerDER = bytes.Clone(s.peer.ServerDER)
	o.mu.Unlock()
	stage = "writable-open"
	acquired, err := owner.execute(ctx, "open")
	if err != nil {
		return OriginalConsumerEvidence{}, err
	}
	stage = "writable-trace-begin"
	if err = traceOwner.BeginOriginalConsumerFile(o.authority, true); err != nil {
		return OriginalConsumerEvidence{}, err
	}
	stage = "writable-positive"
	positive, err := owner.execute(ctx, "positive")
	trace, traceErr := traceOwner.EndOriginalConsumerFile(o.authority)
	if err != nil || ctx.Err() != nil || !positive.completed || positive.written != 1 || positive.writeErr != nil || positive.syncErr != nil || positive.identity != acquired.identity {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	stage = "writable-positive-trace"
	if traceErr != nil || !validPositiveFileTrace(trace) {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	stage = "writable-return"
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if stopped || o.stopped || e.attachment.Err() != nil {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	// Arm has completed; Begin installs the distinct observation cancellation.
	o.cancel = nil
	writable := writableOutcome(positive)
	writable.Trace = &trace
	o.evidence = OriginalConsumerEvidence{Arm: arm, Stage: "armed-mounted-positive", Scope: s.scope, KeySHA256: key, MountIdentitySHA256: writable.IdentitySHA256,
		FDOperation: "write-file-fsync", FDSequence: 1, OriginalOperation: OriginalOperation{Kind: "write-file-fsync", Sequence: 1, ErrorClass: "ok"}, Writable: writable}
	return o.evidence, nil
}
func validPositiveFileTrace(t c.OriginalConsumerFileTrace) bool {
	return t.Capability == nil && t.Write != nil && t.Sync != nil && t.WriteOK && t.SyncOK && t.Write.Node != 0 && t.Write.Handle != 0 && t.Write.RequestSequence != 0 && t.Sync.Node == t.Write.Node && t.Sync.Handle == t.Write.Handle && t.Sync.RequestSequence > t.Write.RequestSequence
}
func validNegativeFileTrace(t c.OriginalConsumerFileTrace, positive c.OriginalConsumerFileTrace) bool {
	if !validPositiveFileTrace(positive) || t.Capability != nil || t.Write == nil || t.WriteOK || t.SyncOK || t.Write.Node != positive.Write.Node || t.Write.Handle != positive.Write.Handle || t.Write.RequestSequence <= positive.Sync.RequestSequence {
		return false
	}
	return t.Sync == nil || (t.Sync.Node == t.Write.Node && t.Sync.Handle == t.Write.Handle && t.Sync.RequestSequence > t.Write.RequestSequence)
}
func validNegativeCapabilityFileTrace(t c.OriginalConsumerFileTrace, positive c.OriginalConsumerFileTrace) bool {
	return validPositiveFileTrace(positive) && t.Capability != nil && t.Write == nil && t.Sync == nil && !t.WriteOK && !t.SyncOK && t.Capability.Node == positive.Write.Node && t.Capability.RequestSequence > positive.Sync.RequestSequence
}
func (o *originalConsumer) probeWritable(ctx context.Context, result OriginalConsumerEvidence) (_ OriginalConsumerEvidence, failure error) {
	stage := "writable-probe-positive"
	reported := false
	defer func() {
		if !reported {
			originalArmFailure(o.arm, stage, failure)
		}
	}()
	positive := o.evidence.Writable
	if o.writable == nil || positive == nil || positive.Trace == nil || !validPositiveFileTrace(*positive.Trace) || !positive.Completed || positive.Written != 1 || positive.WriteError != "ok" || positive.SyncError != "ok" {
		return result, ErrInvalidFrame
	}
	sameE := o.arm.CaseName == "same-e-retained-fd"
	stage = "writable-probe-owner"
	traceOwner, ok := o.attachment.(originalWritableAttachment)
	if !ok {
		return result, ErrInvalidFrame
	}
	if sameE {
		stage = "writable-probe-begin"
		if o.arm.Version == 7 {
			capabilityOwner, ok := o.attachment.(originalCapabilityAttachment)
			if !ok {
				return result, ErrInvalidFrame
			}
			if err := capabilityOwner.BeginOriginalConsumerCapabilityFile(o.authority); err != nil {
				return result, err
			}
		} else if err := traceOwner.BeginOriginalConsumerFile(o.authority, false); err != nil {
			return result, err
		}
	} else {
		stage = "writable-probe-mount-join"
		select {
		case <-o.attachment.Done():
		case <-ctx.Done():
			return result, ctx.Err()
		}
		stage = "writable-probe-mount-error"
		if o.attachment.Err() == nil {
			return result, ErrInvalidFrame
		}
	}
	attempt, err := o.writable.execute(ctx, "attempt")
	var trace c.OriginalConsumerFileTrace
	var traceErr error
	if sameE {
		trace, traceErr = traceOwner.EndOriginalConsumerFile(o.authority)
	}
	writable := writableOutcome(attempt)
	for _, check := range []struct {
		stage  string
		failed bool
		cause  error
	}{
		{"writable-probe-execute", err != nil, err},
		{"writable-probe-trace", traceErr != nil, traceErr},
		{"writable-probe-context", ctx.Err() != nil, ctx.Err()},
		{"writable-probe-completion", !attempt.completed, ErrInvalidFrame},
		{"writable-probe-count", attempt.written != 0, ErrInvalidFrame},
		{"writable-probe-write", !writableDeniedError(writable.WriteError), attempt.writeErr},
		{"writable-probe-sync", !writableDeniedError(writable.SyncError), attempt.syncErr},
		{"writable-probe-identity", writable.IdentitySHA256 != positive.IdentitySHA256, ErrInvalidFrame},
	} {
		if check.failed {
			reported = true
			originalProbeFailure(originalArmFailureEnabled(o.arm), check.stage, check.cause, ErrInvalidFrame, emitOriginalProbeFailure)
			return result, ErrInvalidFrame
		}
	}
	if sameE {
		stage = "writable-probe-negative"
		valid := validNegativeFileTrace(trace, *positive.Trace)
		if o.arm.Version == 7 {
			valid = validNegativeCapabilityFileTrace(trace, *positive.Trace)
		}
		if !valid {
			return result, ErrInvalidFrame
		}
		// The actual denial terminates the DATA client asynchronously. Join that
		// exact mount before release can close its retained FD; a terminal flag
		// alone cannot justify Linux's disconnected FLUSH outcome.
		stage = "writable-probe-denied-mount-join"
		if err := waitOriginalDeniedMount(ctx, o.attachment); err != nil {
			return result, err
		}
		writable.Trace = &trace
		result.Stage = "original-file-attempt"
		result.OriginalOperation = OriginalOperation{Kind: "write-file-fsync", Sequence: 2, ErrorClass: "transport-failed"}
	} else {
		result.OriginalOperation = OriginalOperation{Kind: "write-file-fsync", Sequence: 2, ErrorClass: "mount-closed-joined"}
	}
	result.Writable = writable
	result.FDSequence = 2
	return result, nil
}

// Failed joins preserve all references and produce NO released ACK. Host sealed
// containment must retain this guest generation; cancellation is never completion.
func (o *originalConsumer) stopWritable(owner *retainedFDOwner) (failure error) {
	stage := "writable-stop-busy"
	defer func() { originalArmFailure(o.arm, stage, failure) }()
	ctx, cancel := context.WithTimeout(context.Background(), originalConsumerBudget)
	defer cancel()
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
	o.mu.Unlock()
	if !o.operations.TryLock() {
		owner.fail(context.Canceled)
		return errRetainedFDBusy
	}
	defer o.operations.Unlock()
	owner.mu.Lock()
	failed := owner.failed
	owner.mu.Unlock()
	if failed {
		stage = "writable-stop-failed"
		return owner.joinFailure(ctx)
	}
	stage = "writable-stop-close"
	if _, err := owner.execute(ctx, "close"); err != nil {
		owner.mu.Lock()
		closeFailure := owner.closeFailure
		owner.mu.Unlock()
		originalProbeFailure(originalArmFailureEnabled(o.arm), stage, closeFailure, err, emitOriginalProbeFailure)
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.writable = nil
	o.attachment = nil
	o.identity = p.Identity{}
	o.conn = nil
	if o.capture != nil {
		o.capture.clear()
		o.capture = nil
	}
	return nil
}
