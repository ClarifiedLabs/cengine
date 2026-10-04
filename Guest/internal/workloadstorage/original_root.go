package workloadstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"

	cc "dev.cengine/guest/internal/consumercompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	p "dev.cengine/guest/internal/storagepki"
)

func rootOriginalCase(name string) bool {
	return name == "cross-mount-root-grant" || name == "retired-root-grant-replay"
}

type originalReadFactory interface {
	newOriginalReadFD(Attachment) *retainedFDOwner
}
type originalReadAttachment interface {
	originalRootAttemptAttachment
	BeginOriginalConsumerRead(a.DataHello) error
	EndOriginalConsumerRead(a.DataHello) (*c.OriginalConsumerReadGrant, error)
	ReplayOriginalConsumerRead(context.Context, a.DataHello, *c.OriginalConsumerReadGrant, *c.OriginalConsumerReadGrant) (c.OriginalConsumerRootReplay, error)
}

type OriginalRootPositive struct {
	IdentitySHA256 string                        `json:"identitySHA256"`
	LeafSHA256     string                        `json:"leafSHA256"`
	RootRequest    OriginalRootRequest           `json:"rootRequest"`
	Read           c.OriginalConsumerReadWitness `json:"read"`
}

// These are original-owner observations only. In particular transport-failed
// does NOT attest retirement or blocked server Admit. Swift must independently
// join the exact persisted receipt and actual worker recorder before acceptance.
type OriginalRootEvidence struct {
	Source OriginalRootPositive          `json:"source"`
	Target OriginalRootPositive          `json:"target"`
	Replay *c.OriginalConsumerRootReplay `json:"replay,omitempty"`
}
type originalRootPair struct {
	owners      [2]*retainedFDOwner
	attachments [2]Attachment
	readers     [2]originalReadAttachment
	authority   [2]a.DataHello
	grants      [2]*c.OriginalConsumerReadGrant
	positive    OriginalRootEvidence
}

// Begin must pin both original mounts, not merely the source selected by the
// generic carrier. A terminal notification or failed worker cannot be re-armed.
func (pair *originalRootPair) live() bool {
	if pair == nil {
		return false
	}
	for i, attachment := range pair.attachments {
		if attachment == nil || attachment.Err() != nil || pair.owners[i] == nil || pair.grants[i] == nil {
			return false
		}
		select {
		case <-attachment.Done():
			return false
		default:
		}
		owner := pair.owners[i]
		owner.mu.Lock()
		invalid := owner.failed || owner.released
		owner.mu.Unlock()
		if invalid {
			return false
		}
		select {
		case <-owner.done:
			return false
		default:
		}
	}
	return true
}

// Reuses the production exact-two-installed-runtime validation, including actual
// issued chain/key, mounted+live attachment and deterministic source selection.
func (s *Session) originalRootTarget(source a.DataHello) (*sessionAttachment, error) {
	hello, err := s.selectOriginalHello(cc.WrongVolume, source)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, ErrInvalidFrame
	}
	var target *sessionAttachment
	for _, entry := range s.entries {
		if entry != nil && entry.installed && entry.slot.Role == "runtime" && a.ID(entry.slot.Volume) == hello.Binding.Volume {
			if target != nil {
				return nil, ErrInvalidFrame
			}
			target = entry
		}
	}
	if target == nil {
		return nil, ErrInvalidFrame
	}
	return target, nil
}

func (s *Session) armOriginalRoot(factory originalConsumerFactory, o *originalConsumer, arm OriginalConsumerArm, source *sessionAttachment, key string) (_ OriginalConsumerEvidence, failure error) {
	stage := "root-target"
	defer func() { originalArmFailure(arm, stage, failure) }()
	f, ok := factory.(originalReadFactory)
	if !ok {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	hello := a.DataHello{Epoch: a.ID(s.scope.ServiceEpoch), Binding: a.Binding{Store: a.ID(s.scope.Store), Volume: a.ID(source.slot.Volume), Attachment: a.ID(source.slot.Attachment), Container: a.ContainerID(s.scope.Container), Launch: a.ID(s.scope.Launch), Key: a.Fingerprint(key), Role: a.RuntimeRole, Mode: a.Mode(source.slot.Mode)}}
	target, err := s.originalRootTarget(hello)
	if err != nil {
		return OriginalConsumerEvidence{}, err
	}
	otherKey, err := target.key.Fingerprint()
	if err != nil {
		return OriginalConsumerEvidence{}, err
	}
	other := hello
	other.Binding.Volume = a.ID(target.slot.Volume)
	other.Binding.Attachment = a.ID(target.slot.Attachment)
	other.Binding.Key = a.Fingerprint(otherKey.String())
	other.Binding.Mode = a.Mode(target.slot.Mode)
	pair := &originalRootPair{attachments: [2]Attachment{source.attachment, target.attachment}, authority: [2]a.DataHello{hello, other}}
	for i, attachment := range pair.attachments {
		reader, ok := attachment.(originalReadAttachment)
		if !ok {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		pair.readers[i] = reader
	}
	stage = "root-owners"
	ctx, cancel := context.WithTimeout(context.Background(), originalConsumerBudget)
	defer cancel()
	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	// Publish both ownership slots BEFORE any acquisition, including a failure
	// to construct the second owner. stop must never lose the first worker.
	o.used, o.arm, o.identity, o.attachment, o.authority, o.roots, o.cancel = true, arm, source.identity, source.attachment, hello, pair, cancel
	o.peer = s.peer
	o.peer.TLSRootDER = bytes.Clone(s.peer.TLSRootDER)
	o.peer.ServerDER = bytes.Clone(s.peer.ServerDER)
	for i, attachment := range pair.attachments {
		pair.owners[i] = f.newOriginalReadFD(attachment)
		if pair.owners[i] == nil {
			o.mu.Unlock()
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
	}
	o.mu.Unlock()
	values := [2]OriginalRootPositive{}
	entries := [2]*sessionAttachment{source, target}
	for i, owner := range pair.owners {
		stage = "root-getattr"
		root, err := pair.readers[i].OriginalConsumerRootAttempt(ctx, pair.authority[i])
		if err != nil || root.Node == 0 || root.RequestSequence == 0 {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		stage = "root-open"
		acquired, err := owner.execute(ctx, "read-open")
		if err != nil {
			return OriginalConsumerEvidence{}, err
		}
		stage = "root-read-begin"
		if err = pair.readers[i].BeginOriginalConsumerRead(pair.authority[i]); err != nil {
			return OriginalConsumerEvidence{}, err
		}
		stage = "root-read"
		read, readErr := owner.execute(ctx, "read")
		grant, traceErr := pair.readers[i].EndOriginalConsumerRead(pair.authority[i])
		if readErr != nil || !read.completed || read.readErr != nil || read.readBytes != 32 || read.identity != acquired.identity || !pin(read.readSHA256) {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		stage = "root-read-trace"
		if traceErr != nil {
			originalArmFailure(arm, stage, traceErr)
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		stage = "root-read-witness"
		witness, err := grant.Witness(pair.authority[i])
		if err != nil || witness.ContentSHA256 != read.readSHA256 || witness.RootNode != uint64(root.Node) || witness.RequestSequence <= root.RequestSequence || witness.Node == 0 || witness.Handle == 0 {
			return OriginalConsumerEvidence{}, ErrInvalidFrame
		}
		pair.grants[i] = grant
		values[i] = OriginalRootPositive{IdentitySHA256: writableIdentity(read.identity), LeafSHA256: SpecificationDigest(entries[i].identity.Certificate().DER()), RootRequest: OriginalRootRequest{uint64(root.Node), root.RequestSequence}, Read: witness}
	}
	stage = "root-pair"
	if values[0].IdentitySHA256 == values[1].IdentitySHA256 || values[0].Read.ContentSHA256 == values[1].Read.ContentSHA256 || values[0].Read.Size != values[1].Read.Size || values[0].Read.IOFlags != values[1].Read.IOFlags {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	stage = "root-return"
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if stopped || o.stopped || ctx.Err() != nil || pair.attachments[0].Err() != nil || pair.attachments[1].Err() != nil {
		return OriginalConsumerEvidence{}, ErrInvalidFrame
	}
	pair.positive = OriginalRootEvidence{Source: values[0], Target: values[1]}
	encoded, _ := json.Marshal(struct{ Source, Target string }{values[0].IdentitySHA256, values[1].IdentitySHA256})
	o.cancel = nil
	o.evidence = OriginalConsumerEvidence{Arm: arm, Stage: "armed-mounted-positive", Scope: s.scope, KeySHA256: key, MountIdentitySHA256: SpecificationDigest(encoded), FDOperation: "read-file-root-grant", FDSequence: 1, OriginalOperation: OriginalOperation{Kind: "read-file-root-grant", Sequence: 1, ErrorClass: "ok"}, RootRequest: &values[0].RootRequest, Roots: &pair.positive}
	return o.evidence, nil
}

func (o *originalConsumer) probeRoots(ctx context.Context, result OriginalConsumerEvidence) (_ OriginalConsumerEvidence, failure error) {
	stage := "root-probe-pair"
	defer func() { originalArmFailure(o.arm, stage, failure) }()
	pair := o.roots
	if pair == nil || result.Roots == nil || pair.grants[0] == nil || pair.grants[1] == nil || pair.attachments[1].Err() != nil {
		return result, ErrInvalidFrame
	}
	// For the retired case both operations follow the host's receipt. Replay on B
	// first: A's subsequent real blocked request terminates its mount, and the
	// production Session then closes every peer. Requiring B to survive that
	// cascade races shutdown rather than testing root-local grant isolation.
	stage = "root-probe-replay"
	replay, err := pair.readers[1].ReplayOriginalConsumerRead(ctx, pair.authority[1], pair.grants[0], pair.grants[1])
	if err != nil {
		return result, err
	}
	stage = "root-probe-replay-return"
	if ctx.Err() != nil || replay.Source != pair.authority[0] || replay.Target != pair.authority[1] || replay.ContentSHA256 != pair.positive.Target.Read.ContentSHA256 {
		return result, ErrInvalidFrame
	}
	stage = "root-probe-source"
	request, err := pair.readers[0].OriginalConsumerRootAttempt(ctx, pair.authority[0])
	var timeout net.Error
	retired := o.arm.CaseName == "retired-root-grant-replay"
	if ctx.Err() != nil || uint64(request.Node) != pair.positive.Source.RootRequest.Node || request.RequestSequence <= pair.positive.Source.Read.RequestSequence {
		return result, ErrInvalidFrame
	}
	stage = "root-probe-source-outcome"
	if retired {
		if !errors.Is(err, c.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, c.ErrProtocol) || (errors.As(err, &timeout) && timeout.Timeout()) {
			return result, ErrInvalidFrame
		}
	} else if err != nil || pair.attachments[0].Err() != nil {
		return result, ErrInvalidFrame
	}
	if retired {
		stage = "root-probe-denied-mount-join"
		for _, attachment := range pair.attachments {
			if err := waitOriginalDeniedMount(ctx, attachment); err != nil {
				return result, err
			}
		}
	}
	roots := pair.positive
	roots.Replay = &replay
	result.Roots = &roots
	result.RootRequest = &OriginalRootRequest{uint64(request.Node), request.RequestSequence}
	result.Stage = "original-root-scope-replay"
	outcome := "ok"
	if retired {
		outcome = "transport-failed"
	}
	result.OriginalOperation = OriginalOperation{Kind: "read-file-root-grant", Sequence: 2, ErrorClass: outcome}
	result.FDSequence = 2
	return result, nil
}

func (o *originalConsumer) stopRoots(pair *originalRootPair) error {
	ctx, cancel := context.WithTimeout(context.Background(), originalConsumerBudget)
	defer cancel()
	o.mu.Lock()
	if o.cancel != nil {
		o.cancel()
	}
	if o.timer != nil {
		o.timer.Stop()
	}
	o.mu.Unlock()
	if !o.operations.TryLock() {
		for _, owner := range pair.owners {
			if owner != nil {
				owner.fail(context.Canceled)
			}
		}
		return errRetainedFDBusy
	}
	defer o.operations.Unlock()
	var joined error
	for _, owner := range pair.owners {
		if owner == nil {
			continue
		}
		owner.mu.Lock()
		failed := owner.failed
		owner.mu.Unlock()
		var err error
		if failed {
			err = owner.joinFailure(ctx)
		} else {
			_, err = owner.execute(ctx, "close")
		}
		if err != nil {
			owner.mu.Lock()
			closeFailure := owner.closeFailure
			owner.mu.Unlock()
			originalProbeFailure(originalArmFailureEnabled(o.arm), "root-stop-close", closeFailure, err, emitOriginalProbeFailure)
			originalArmFailure(o.arm, "root-stop-join", err)
			owner.fail(err)
			joined = errors.Join(joined, err)
		}
	}
	if joined != nil {
		return joined
	} // preserve pair on every failed/unjoined close
	o.mu.Lock()
	defer o.mu.Unlock()
	o.roots = nil
	o.attachment = nil
	o.identity = p.Identity{}
	return nil
}
