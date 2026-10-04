package storagebootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

// A parent may stage TLS inputs, never authorize their use as current trust.
// This bounded slot is not a receipt cache. Only ROOT proof may set proven.
type lifecyclePendingRebind struct {
	change p.LifecycleServiceChangeRequest
	trust  p.LifecycleBootTrust
	config c.LifecycleClientConfig
	raw    net.Conn
	client *c.LifecycleClient
	proven *p.LifecycleServiceState
}

// Own raw even on rejection. No new key, greeting, process identity, boot attempt
// or ROOT counter is created by rebind. A failed staged connection is terminal.
func (s *lifecycleSession) stageServiceRebind(ctx context.Context, raw net.Conn, change p.LifecycleServiceChangeRequest, boot lifecycleBoot) (err error) {
	defer func() {
		if err != nil && raw != nil {
			raw.Close()
		}
	}()
	if err = s.acquireOperation(ctx); err != nil {
		return err
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	if s.revoked || raw == nil || s.pendingRebind != nil || s.client == nil || !s.rootBootSeen || s.serviceState == nil ||
		s.retirement.Grant != (a.LifecycleGrant{}) || change.Validate() != nil || change.Predecessor != *s.serviceState ||
		(s.latestRebind != nil && change.OperationID == s.latestRebind.Request.OperationID) {
		s.mu.Unlock()
		return errLifecycleSession
	}
	cfg, err := s.bootConfig(boot)
	trust, trustErr := s.deriveBootTrust(boot)
	oldCA, oldErr := x509.ParseCertificate(s.privateBootConfig.ServerRoot.DER())
	newCA, newErr := x509.ParseCertificate(boot.root.DER())
	if err != nil || trustErr != nil || change.ValidateSuccessorBoot(trust.Fields()) != nil || oldErr != nil || newErr != nil ||
		bytes.Equal(oldCA.RawSubjectPublicKeyInfo, newCA.RawSubjectPublicKeyInfo) {
		s.mu.Unlock()
		return errLifecycleSession
	}
	pending := &lifecyclePendingRebind{change: change, trust: trust, config: cfg, raw: raw}
	s.pendingRebind = pending
	oldClient, oldRaw := s.client, s.raw
	work, workRaw, attachment := s.workload, s.workloadRaw, s.attachmentRaw
	s.workload, s.workloadRaw, s.attachmentRaw = nil, nil, nil
	s.mu.Unlock()
	// Fence all previous streams before attempting the new handshake. No fallback.
	if workRaw != nil {
		workRaw.Close()
	}
	if work != nil {
		work.Close()
	}
	if attachment != nil {
		attachment.Close()
	}
	if oldRaw != nil {
		oldRaw.Close()
	}
	if oldClient != nil {
		oldClient.Close()
	}
	client, err := c.NewLifecycleClient(ctx, raw, cfg)
	if err != nil {
		s.close()
		return err
	}
	s.mu.Lock()
	if s.revoked || ctx.Err() != nil || s.pendingRebind != pending || s.owner.Grant != change.Predecessor.Grant {
		s.mu.Unlock()
		client.Close()
		s.close()
		return errLifecycleSession
	}
	pending.client = client
	s.mu.Unlock()
	return nil
}

// Called with the operation gate held, only after an authenticated ROOT message
// has passed process/greeting/freshness checks and consumed its ordered counter.
func (s *lifecycleSession) serviceProof(ctx context.Context, challenge p.LifecycleChildChallenge) (reply p.LifecycleChildReply, err error) {
	s.mu.Lock()
	f := challenge.Fields()
	pending := s.pendingRebind
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	client, cfg, trust := s.client, s.privateBootConfig, s.bootTrust
	valid := !s.revoked && s.retirement.Grant == (a.LifecycleGrant{}) && f.Grant == s.owner.Grant && f.Boot != nil
	if pending != nil {
		client, cfg, trust = pending.client, pending.config, pending.trust
		if f.Purpose == p.LifecycleChildServiceResult {
			valid = valid && f.ChangeRequest != nil && *f.ChangeRequest == pending.change
		} else {
			valid = valid && f.Confirmation != nil && f.Confirmation.Request == pending.change && pending.proven != nil && f.Confirmation.Successor == *pending.proven
		}
	} else if f.Purpose == p.LifecycleChildServiceCommit {
		valid = valid && s.latestRebind != nil && f.Confirmation != nil && *f.Confirmation == *s.latestRebind && s.serviceState != nil && f.Confirmation.Successor == *s.serviceState
	} else {
		valid = valid && f.ChangeRequest == nil
	}
	if !valid || client == nil || *f.Boot != trust.Fields() {
		s.mu.Unlock()
		s.close()
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	s.mu.Unlock()
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil {
		return p.LifecycleChildReply{}, err
	}
	live, err := client.ServiceResult(ctx, f.Grant, nonce)
	if err != nil {
		return p.LifecycleChildReply{}, err
	}
	state, err := p.LifecycleServiceStateFromResult(live, trust.Fields())
	if err != nil {
		return p.LifecycleChildReply{}, err
	}
	if state.Grant != f.Grant || state.Context.ControllerEpoch != cfg.Hello.ControllerEpoch || state.Context.ServiceEpoch != string(cfg.Hello.ServiceEpoch) {
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || ctx.Err() != nil || s.pendingRebind != pending || s.owner.Grant != f.Grant || s.retirement.Grant != (a.LifecycleGrant{}) {
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	if pending == nil && (s.client != client || s.privateBootConfig != cfg || s.bootTrust != trust || (s.serviceState != nil && *s.serviceState != state)) {
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	if f.Confirmation != nil && f.Confirmation.Successor != state {
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	if pending != nil {
		confirmation := p.LifecycleServiceChangeConfirmation{Request: pending.change, Successor: state}
		if confirmation.Validate() != nil || (pending.proven != nil && *pending.proven != state) {
			return p.LifecycleChildReply{}, errLifecycleSession
		}
	}
	reply, err = s.key.SignLifecycleChildServiceReply(challenge, &live)
	if err != nil {
		return p.LifecycleChildReply{}, err
	}
	if pending != nil && f.Purpose == p.LifecycleChildServiceResult {
		pending.proven = &state // Proof only: current trust/config/client remain unchanged.
	} else {
		if pending != nil {
			s.client, s.raw, s.privateBootConfig, s.bootTrust = client, pending.raw, cfg, trust
			confirmation := *f.Confirmation
			s.latestRebind, s.pendingRebind = &confirmation, nil
			s.workloadFailed = false
		}
		s.serviceState, s.rootBootSeen = &state, true
	}
	return reply, nil
}

// mu must be held. Check the entire current owner and live context after IO,
// including changes made by close/bindRetire while an exchange was in flight.
func (s *lifecycleSession) currentServiceMatches(client *c.LifecycleClient, cfg c.LifecycleClientConfig, grant a.LifecycleGrant, live a.LifecycleServiceResult) bool {
	if s.revoked || s.pendingRebind != nil || !s.rootBootSeen || s.client != client || s.privateBootConfig != cfg || s.owner.Grant != grant || s.retirement.Grant != (a.LifecycleGrant{}) {
		return false
	}
	state, err := p.LifecycleServiceStateFromResult(live, s.bootTrust.Fields())
	return err == nil && state.Grant == grant && (s.serviceState == nil || *s.serviceState == state)
}
