package storageboot

import (
	"bytes"

	a "dev.cengine/guest/internal/storageauthority"
)

// LifecycleHandoffReply keeps the immutable authority receipt and actual live
// Ready in one closed private reply. It is not an ordinary Query authorization.
type LifecycleHandoffReply struct {
	Result a.LifecycleHandoffResult `json:"result"`
	Ready  *LifecycleReady          `json:"ready"`
}

func validLifecycleHandoffReply(r *LifecycleHandoffReply) bool {
	if r == nil || r.Result.Validate() != nil || !lifecycleReadyValid(r.Ready) {
		return false
	}
	g, ready := r.Result.AppliedGrant, r.Ready
	return ready.Identity == g.Identity && ready.ServiceEpoch == string(r.Result.Request.ServiceEpoch) &&
		ready.OpenRevision == r.Result.Request.OpenRevision && ready.ControllerEpoch == g.ExpectedEpoch+1 &&
		ready.ControllerKey == string(g.NewKey) && ready.Revision >= r.Result.FenceRevision
}

func sameLifecycleSignedHandoff(x, y *a.SignedLifecycleHandoff) bool {
	return x != nil && y != nil && x.Request == y.Request && bytes.Equal(x.Signature, y.Signature)
}

func (s *lifecycleSupervisor) admitHandoffLocked(f *LifecycleFrame) bool {
	if f.validate() != nil || f.Handoff == nil || a.VerifyLifecycleHandoff(s.root, *f.Handoff) != nil {
		return false
	}
	r := f.Handoff.Request
	return r.Predecessor.Identity == s.ready.Identity && r.OpenRevision == s.ready.OpenRevision &&
		(r.Predecessor == s.signed.Grant || r.Pending == s.signed.Grant) &&
		(s.successor == nil || s.successor.Grant == r.Pending)
}

func (s *lifecycleSupervisor) acceptHandoffLocked(request, reply *LifecycleFrame) bool {
	r := reply.HandoffResult
	if reply.validate() != nil || reply.Binding != request.Binding || !validLifecycleHandoffReply(r) ||
		r.Result.Request != request.Handoff.Request || !bytes.Equal(r.Result.Nonce, request.Nonce) {
		return false
	}
	old, next := s.ready, r.Ready
	if next.WorkerUUID != old.WorkerUUID || next.Identity != old.Identity || next.ServiceEpoch != old.ServiceEpoch ||
		next.OpenRevision != old.OpenRevision || next.BootstrapKey != old.BootstrapKey || next.ServerSPKI != old.ServerSPKI ||
		!bytes.Equal(next.TLSRootDER, old.TLSRootDER) || !bytes.Equal(next.ServerDER, old.ServerDER) || next.Revision < old.Revision {
		return false
	}
	// The handoff carries raw grant tuples, NOT ordinary grant signatures. Only
	// retain an exact already-ROOT-signed grant; never manufacture a signature.
	actual := s.signed
	if actual.Grant != r.Result.AppliedGrant {
		if s.successor == nil || s.successor.Grant != r.Result.AppliedGrant {
			return false
		}
		actual = *s.successor
	}
	s.signed, s.successor, s.ready = copyLifecycleSigned(actual), nil, copyLifecycleReady(next)
	s.logicalHandoff = nil // Only the fully validated result resolves the logical fence.
	return true
}
