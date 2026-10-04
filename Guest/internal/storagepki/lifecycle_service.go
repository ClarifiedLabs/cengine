package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"

	a "dev.cengine/guest/internal/storageauthority"
)

// LifecycleServiceContext and the related service DTOs mirror Swift's lifecycle
// value contract. They are not authentication capabilities or proof of drain.
type LifecycleServiceContext struct {
	ServiceEpoch    string `json:"service_epoch"`
	ControllerEpoch uint64 `json:"controller_epoch"`
	ControllerKey   string `json:"controller_key"`
}

func (c LifecycleServiceContext) Validate() error {
	if !uuid(c.ServiceEpoch) || c.ControllerEpoch == 0 || !container(c.ControllerKey) {
		return ErrInvalid
	}
	return nil
}

// LifecycleServiceState is comparable and retains no caller-owned storage.
type LifecycleServiceState struct {
	Grant        a.LifecycleGrant         `json:"grant"`
	Context      LifecycleServiceContext  `json:"context"`
	OpenRevision uint64                   `json:"open_revision"`
	Boot         LifecycleBootTrustFields `json:"boot"`
}

func (s LifecycleServiceState) Validate() error {
	if s.Grant.Validate() != nil || s.Context.Validate() != nil || s.Boot.Validate() != nil ||
		s.Grant.Operation == a.LifecycleRetire || s.Context.ControllerEpoch != s.Grant.ExpectedEpoch+1 ||
		s.Context.ControllerKey != string(s.Grant.NewKey) || s.OpenRevision == 0 ||
		s.Boot.Identity != s.Grant.Identity || s.Boot.ServiceEpoch != s.Context.ServiceEpoch ||
		s.Boot.BootstrapKey == s.Context.ControllerKey {
		return ErrInvalid
	}
	return nil
}

func LifecycleServiceStateFromResult(result a.LifecycleServiceResult, boot LifecycleBootTrustFields) (LifecycleServiceState, error) {
	if result.Validate() != nil {
		return LifecycleServiceState{}, ErrInvalid
	}
	state := LifecycleServiceState{Grant: result.Grant,
		Context:      LifecycleServiceContext{ServiceEpoch: string(result.ServiceEpoch), ControllerEpoch: result.ControllerEpoch, ControllerKey: string(result.ControllerKey)},
		OpenRevision: result.OpenRevision, Boot: boot}
	if err := state.Validate(); err != nil {
		return LifecycleServiceState{}, err
	}
	return state, nil
}

type LifecycleServiceChangeRequest struct {
	OperationID string                `json:"operation_id"`
	Predecessor LifecycleServiceState `json:"predecessor"`
}

func (r LifecycleServiceChangeRequest) Validate() error {
	if !uuid(r.OperationID) || r.Predecessor.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// LifecycleServiceChangeSigningBytes is the ROOT-signed authorization for a
// service change: domain || json.Marshal(request) in Go declaration order.
func LifecycleServiceChangeSigningBytes(r LifecycleServiceChangeRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle-service-change.v2\x00"), b...), nil
}

// SignedLifecycleServiceChange is a service-change request authorized by the
// predecessor's bootstrap ROOT. Shape validity is not authorization; callers
// must Verify before any kill, start, or disk mutation.
type SignedLifecycleServiceChange struct {
	Request   LifecycleServiceChangeRequest `json:"request"`
	Signature []byte                        `json:"signature"`
}

func (s SignedLifecycleServiceChange) Validate() error {
	if s.Request.Validate() != nil || len(s.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

// Verify requires root to be the predecessor's recorded bootstrap key and the
// signature to cover the exact request bytes.
func (s SignedLifecycleServiceChange) Verify(root ed25519.PublicKey) error {
	if s.Validate() != nil || len(root) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	fp, err := PublicKeyFingerprint(root)
	if err != nil || fp.String() != s.Request.Predecessor.Boot.BootstrapKey {
		return ErrInvalid
	}
	msg, err := LifecycleServiceChangeSigningBytes(s.Request)
	if err != nil || !ed25519.Verify(root, msg, s.Signature) {
		return ErrInvalid
	}
	return nil
}

// Clone returns a copy retaining no caller-owned signature storage.
func (s *SignedLifecycleServiceChange) Clone() *SignedLifecycleServiceChange {
	if s == nil {
		return nil
	}
	copy := *s
	copy.Signature = bytes.Clone(s.Signature)
	return &copy
}

// ValidateSuccessorBoot requires a new service epoch, CA and server key while
// preserving the full store identity and bootstrap authority.
func (r LifecycleServiceChangeRequest) ValidateSuccessorBoot(boot LifecycleBootTrustFields) error {
	if r.Validate() != nil || boot.Validate() != nil {
		return ErrInvalid
	}
	old := r.Predecessor.Boot
	if boot.Identity != old.Identity || boot.BootstrapKey != old.BootstrapKey ||
		boot.ServiceEpoch == old.ServiceEpoch || boot.TLSRootSHA256 == old.TLSRootSHA256 || boot.ServerSPKI == old.ServerSPKI {
		return ErrInvalid
	}
	return nil
}

type LifecycleServiceChangeConfirmation struct {
	Request   LifecycleServiceChangeRequest `json:"request"`
	Successor LifecycleServiceState         `json:"successor"`
}

func (c LifecycleServiceChangeConfirmation) Validate() error {
	if c.Request.Validate() != nil || c.Successor.Validate() != nil || c.Request.ValidateSuccessorBoot(c.Successor.Boot) != nil {
		return ErrInvalid
	}
	prior := c.Request.Predecessor
	if c.Successor.Grant != prior.Grant || c.Successor.Context.ControllerEpoch != prior.Context.ControllerEpoch ||
		c.Successor.Context.ControllerKey != prior.Context.ControllerKey || c.Successor.OpenRevision <= prior.OpenRevision {
		return ErrInvalid
	}
	return nil
}

func cloneLifecycleServiceChangeRequest(r *LifecycleServiceChangeRequest) *LifecycleServiceChangeRequest {
	if r == nil {
		return nil
	}
	copy := *r
	return &copy
}

func cloneLifecycleServiceChangeConfirmation(c *LifecycleServiceChangeConfirmation) *LifecycleServiceChangeConfirmation {
	if c == nil {
		return nil
	}
	copy := *c
	return &copy
}
