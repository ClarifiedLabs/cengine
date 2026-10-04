package storageauthority

import (
	"crypto/ed25519"
	"encoding/json"
)

// LifecycleHandoffRequest is ROOT's authorization to fence one abandoned live
// takeover and observe its actual outcome. It neither applies a takeover nor
// authorizes a cold open. Declaration order is the cross-language signing wire.
type LifecycleHandoffRequest struct {
	OperationID  ID             `json:"operation_id"`
	Predecessor  LifecycleGrant `json:"predecessor"`
	Pending      LifecycleGrant `json:"pending"`
	ServiceEpoch ID             `json:"service_epoch"`
	OpenRevision uint64         `json:"open_revision"`
}

type SignedLifecycleHandoff struct {
	Request   LifecycleHandoffRequest `json:"request"`
	Signature []byte                  `json:"signature"`
}

func (r LifecycleHandoffRequest) Validate() error {
	p, g := r.Predecessor, r.Pending
	if !validID(r.OperationID) || r.OperationID == p.ID || r.OperationID == g.ID ||
		p.Validate() != nil || p.Operation == LifecycleRetire ||
		g.Validate() != nil || g.Operation != LifecycleTakeover || g.Identity != p.Identity ||
		g.ExpectedEpoch != p.ExpectedEpoch+1 || g.Serial <= p.Serial || g.ID == p.ID || g.NewKey == p.NewKey ||
		!validID(r.ServiceEpoch) || r.OpenRevision == 0 {
		return ErrInvalid
	}
	return nil
}

func LifecycleHandoffSigningBytes(r LifecycleHandoffRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle-handoff.v1\x00"), b...), nil
}

func VerifyLifecycleHandoff(root ed25519.PublicKey, signed SignedLifecycleHandoff) error {
	b, err := LifecycleHandoffSigningBytes(signed.Request)
	if err != nil {
		return err
	}
	if len(root) != ed25519.PublicKeySize || len(signed.Signature) != ed25519.SignatureSize || !ed25519.Verify(root, b, signed.Signature) {
		return ErrUnauthorized
	}
	return nil
}

// LifecycleHandoffResult must arrive over a freshly authenticated private Guest
// channel, correlated to ROOT's challenge. A HOST-supplied DTO proves nothing.
// AppliedRevision is the immutable original grant receipt, NOT the mutable query
// revision or the fence commit revision. ServiceEpoch/OpenRevision are in Request.
type LifecycleHandoffResult struct {
	Request             LifecycleHandoffRequest `json:"request"`
	Nonce               []byte                  `json:"nonce"`
	AppliedGrant        LifecycleGrant          `json:"applied_grant"`
	AppliedServiceEpoch ID                      `json:"applied_service_epoch"`
	AppliedRevision     uint64                  `json:"applied_revision"`
	FenceRevision       uint64                  `json:"fence_revision"`
}

func (r LifecycleHandoffResult) Validate() error {
	if r.Request.Validate() != nil || len(r.Nonce) != 32 ||
		(r.AppliedGrant != r.Request.Predecessor && r.AppliedGrant != r.Request.Pending) ||
		!validID(r.AppliedServiceEpoch) || r.AppliedRevision == 0 || r.AppliedRevision >= r.FenceRevision ||
		r.Request.OpenRevision >= r.FenceRevision ||
		(r.AppliedGrant == r.Request.Pending && (r.AppliedServiceEpoch != r.Request.ServiceEpoch || r.AppliedRevision <= r.Request.OpenRevision)) {
		return ErrInvalid
	}
	return nil
}

func LifecycleHandoffResultSigningBytes(r LifecycleHandoffResult) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle-handoff-result.v1\x00"), b...), nil
}
