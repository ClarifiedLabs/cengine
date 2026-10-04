package storagebootstrap

import (
	"context"
	p "dev.cengine/guest/internal/storagepki"
	"encoding/base64"
	"time"
)

// ROOT-authenticated native channel only. Identity never touches provisional or
// committed grants, retirement, boot or service state; only shared replay state.
func (s *lifecycleSession) identityProof(ctx context.Context, c p.LifecycleChildIdentityChallenge) (p.LifecycleChildIdentityReply, error) {
	if ctx == nil || c.Fields().ExpiresUnixMS > uint64(^uint64(0)>>1) {
		return p.LifecycleChildIdentityReply{}, errLifecycleSession
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(int64(c.Fields().ExpiresUnixMS)))
	defer cancel()
	if e := s.acquireOperation(ctx); e != nil {
		return p.LifecycleChildIdentityReply{}, e
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	defer s.mu.Unlock()
	f := c.Fields()
	now := time.Now().UnixMilli()
	if s.revoked || ctx.Err() != nil || now < 0 || !c.IsFresh(uint64(now)) || f.Greeting != s.greeting.Fields() || f.ChildUniqueID != s.processes.childUniqueID || f.ChildAudit != base64.StdEncoding.EncodeToString(s.processes.childAudit[:]) || f.DaemonAudit != base64.StdEncoding.EncodeToString(s.processes.daemonAudit[:]) || f.Counter <= s.highWater {
		return p.LifecycleChildIdentityReply{}, errLifecycleSession
	}
	s.highWater = f.Counter
	return s.key.SignLifecycleChildIdentityReply(c)
}

// No fallback between identity and grant-bearing challenge families.
func (s *lifecycleSession) rootProof(ctx context.Context, raw []byte) ([]byte, error) {
	version, e := p.LifecycleChildProofVersion(raw)
	if e != nil {
		return nil, e
	}
	switch version {
	case p.LifecycleChildIdentityVersion:
		c, e := p.DecodeLifecycleChildIdentityChallenge(raw)
		if e != nil {
			return nil, e
		}
		r, e := s.identityProof(ctx, c)
		if e != nil {
			return nil, e
		}
		return r.Canonical(), nil
	case p.LifecycleChildVersion:
		c, e := p.DecodeLifecycleChildChallenge(raw)
		if e != nil {
			return nil, e
		}
		r, e := s.proof(ctx, c)
		if e != nil {
			return nil, e
		}
		return r.Canonical(), nil
	default:
		return nil, errLifecycleSession
	}
}
