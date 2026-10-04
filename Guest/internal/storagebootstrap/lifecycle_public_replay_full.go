//go:build cengine_prepare_full_compat

package storagebootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

const lifecyclePublicReplayLimit = 4096

type lifecyclePublicReplayRequest struct {
	Version   uint32                 `json:"version"`
	RequestID string                 `json:"requestID"`
	Old       a.SignedLifecycleGrant `json:"old"`
}
type lifecyclePublicReplayObservation struct {
	Version       uint32                 `json:"version"`
	RequestID     string                 `json:"requestID"`
	Old           a.SignedLifecycleGrant `json:"old"`
	Pending       a.SignedLifecycleGrant `json:"pending"`
	IncarnationID string                 `json:"incarnationID"`
	Error         c.Code                 `json:"error"`
}

// Public bytes only. The host must source old from its validated current checkpoint,
// not external probe input. No old controller key or stream is retained here.
func (s *lifecycleSession) publicTakeoverReplay(ctx context.Context, raw []byte) ([]byte, error) {
	var q lifecyclePublicReplayRequest
	if pc.CurrentProfile() != pc.FullProfile || lifecycleCanonical(raw, &q, lifecyclePublicReplayLimit) != nil || q.Version != 1 {
		return nil, ErrProtocol
	}
	if _, err := p.NewServerBinding(p.StoreID(s.greeting.Fields().Store), p.ServiceEpoch(q.RequestID)); err != nil {
		return nil, ErrProtocol
	}
	if err := s.acquireOperation(ctx); err != nil {
		return nil, err
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	pending, old := s.owner, q.Old
	g, o := pending.Grant, old.Grant
	message, err := a.LifecycleGrantSigningBytes(o)
	if s.revoked || s.client == nil || s.pendingRebind != nil || s.latestRebind != nil || s.retirement.Grant != (a.LifecycleGrant{}) || s.normalTakeoverAttempted || s.publicTakeoverReplayUsed ||
		g.Operation != a.LifecycleTakeover || g != s.candidateOwner || !s.validGrant(pending) || err != nil || !ed25519.Verify(s.root.PublicKey(), message, old.Signature) ||
		o.Operation != a.LifecycleTakeover || o.Identity != g.Identity || o.ExpectedEpoch+1 != g.ExpectedEpoch || o.ID == g.ID || o.Serial >= g.Serial || o.NewKey == g.NewKey {
		s.mu.Unlock()
		return nil, ErrProtocol
	}
	// Consume before IO, including cancellation/transport failure. Never retry a probe.
	s.publicTakeoverReplayUsed = true
	client := s.client
	pending.Signature = bytes.Clone(pending.Signature)
	s.mu.Unlock()
	if err := c.ReplaySignedLifecycleTakeover(ctx, client, pending, old); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || ctx.Err() != nil {
		return nil, errLifecycleSession
	}
	result, err := canonicalBytes(lifecyclePublicReplayObservation{1, q.RequestID, old, pending, s.greeting.Fields().IncarnationID, c.Unauthorized})
	if err != nil || len(result) > lifecyclePublicReplayLimit {
		return nil, ErrProtocol
	}
	return result, nil
}
