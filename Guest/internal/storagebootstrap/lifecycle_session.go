package storagebootstrap

// Lifecycle coordinator for the native inherited-parent channel. The bridge
// independently observes both processes' unique IDs/audit tokens, authenticates
// EVERY challenge as ROOT before proof, and delivers private boot credentials.
// Signed grants may traverse the private parent channel: bindGrant/bindRetire
// independently verify ROOT's signature, not the DTO sender. These private Go
// constructors and unit-test process values are NOT native authentication evidence.
// A grant binds intent, never successful application, resource drain or deletion.
// Nonexportability here is API confinement, not hardware key protection. There is
// no generic signer, injected TLS client, receipt input, lifecycle reconnect or receipt cache.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

var errLifecycleSession = errors.New("storagebootstrap: lifecycle session unavailable")

// Values must come from independent native observation, not daemon-supplied DTOs.
type lifecycleProcesses struct {
	daemonUniqueID, childUniqueID uint64
	daemonAudit, childAudit       [32]byte
}

type lifecycleSessionConfig struct {
	store         a.ID
	binding       a.Fingerprint
	expectedEpoch uint64
	incarnation   string
	root          p.BootstrapPublicKey
	processes     lifecycleProcesses
}

type lifecycleSession struct {
	// op orders exchanges with context-cancellable waiting; mu protects short
	// state changes and final signing. close never acquires op.
	op     chan struct{}
	closed chan struct{}
	mu     sync.Mutex

	key        p.Key
	root       p.BootstrapPublicKey
	greeting   p.LifecycleChildGreeting
	processes  lifecycleProcesses
	owner      a.SignedLifecycleGrant
	retirement a.SignedLifecycleGrant
	// At most one owner and one retirement candidate, never authority to apply.
	candidateOwner           a.LifecycleGrant
	candidateRetirement      a.LifecycleGrant
	highWater                uint64 // constant state, no nonce/UUID history or eviction
	bootAttempted            bool
	bootTrust                p.LifecycleBootTrust
	revoked                  bool
	raw                      net.Conn
	client                   *c.LifecycleClient
	privateBootConfig        c.LifecycleClientConfig
	rootBootSeen             bool
	attachmentRaw            net.Conn
	workloadRaw              net.Conn
	workload                 *c.Client
	workloadFailed           bool // Cleared only by ROOT's committed new-service rebind.
	serviceState             *p.LifecycleServiceState
	pendingRebind            *lifecyclePendingRebind
	latestRebind             *p.LifecycleServiceChangeConfirmation
	normalTakeoverAttempted  bool
	publicTakeoverReplayUsed bool
}

func newLifecycleSession(cfg lifecycleSessionConfig) (*lifecycleSession, error) {
	processes := cfg.processes
	if processes.daemonUniqueID == 0 || processes.childUniqueID == 0 || processes.daemonUniqueID == processes.childUniqueID ||
		processes.daemonAudit == ([32]byte{}) || processes.childAudit == ([32]byte{}) || processes.daemonAudit == processes.childAudit || len(cfg.root.PublicKey()) != ed25519.PublicKeySize {
		return nil, errLifecycleSession
	}
	key, err := p.NewControllerKey() // Never injected or exported.
	if err != nil {
		return nil, err
	}
	channel, err := p.NewUUID()
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return nil, err
	}
	greeting, err := p.NewLifecycleChildGreeting(p.LifecycleChildGreetingFields{
		Version: p.LifecycleChildVersion, ChannelID: channel, IncarnationID: cfg.incarnation,
		DaemonUniqueID: processes.daemonUniqueID, ControllerSPKI: base64.StdEncoding.EncodeToString(spki),
		RootPublicKey: base64.StdEncoding.EncodeToString(cfg.root.PublicKey()), Store: string(cfg.store),
		Binding: string(cfg.binding), ExpectedEpoch: cfg.expectedEpoch,
	})
	if err != nil {
		return nil, err
	}
	return &lifecycleSession{key: key, root: cfg.root, greeting: greeting, processes: processes,
		op: make(chan struct{}, 1), closed: make(chan struct{})}, nil
}

// Public-only greeting and CSR are available before there is a Guest service E.
func (s *lifecycleSession) controllerCSR() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return nil, errLifecycleSession
	}
	g := s.greeting.Fields()
	binding, err := p.NewControllerBinding(p.StoreID(g.Store), p.ControllerEpoch(g.ExpectedEpoch+1))
	if err != nil {
		return nil, err
	}
	return s.key.CSR(binding)
}

func (s *lifecycleSession) validGrant(signed a.SignedLifecycleGrant) bool {
	message, err := a.LifecycleGrantSigningBytes(signed.Grant)
	return err == nil && s.greeting.Matches(signed.Grant) && ed25519.Verify(s.root.PublicKey(), message, signed.Signature)
}

// The signature authenticates ROOT's exact intent even through a private parent
// relay. A matching candidate proof MUST precede binding ROOT's signed grant.
// This still is NOT an applied result.
func (s *lifecycleSession) bindGrant(signed a.SignedLifecycleGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	signed.Signature = bytes.Clone(signed.Signature)
	if s.revoked || s.owner.Grant != (a.LifecycleGrant{}) || signed.Grant.Operation == a.LifecycleRetire || !s.validGrant(signed) ||
		s.candidateOwner == (a.LifecycleGrant{}) || signed.Grant != s.candidateOwner {
		return errLifecycleSession
	}
	s.owner = signed
	return nil
}

// Later ROOT-signed retirement for this exact owner/generation/candidate only.
func (s *lifecycleSession) bindRetire(signed a.SignedLifecycleGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	signed.Signature = bytes.Clone(signed.Signature)
	g := signed.Grant
	if s.revoked || s.pendingRebind != nil || s.retirement.Grant != (a.LifecycleGrant{}) || !s.validGrant(signed) || !s.retirementMatchesOwner(g) ||
		s.candidateRetirement == (a.LifecycleGrant{}) || g != s.candidateRetirement {
		return errLifecycleSession
	}
	s.retirement = signed
	return nil
}

// These helpers require mu. Candidates bind only intent: ROOT needs their key
// proof BEFORE its checkpoint/sign/release step, so no signed grant is required.
func (s *lifecycleSession) retirementMatchesOwner(g a.LifecycleGrant) bool {
	owner := s.owner.Grant
	return owner != (a.LifecycleGrant{}) && g.Operation == a.LifecycleRetire && s.greeting.Matches(g) &&
		g.Identity == owner.Identity && g.NewKey == owner.NewKey && g.Serial > owner.Serial && g.ID != owner.ID
}

func (s *lifecycleSession) acceptCandidate(g a.LifecycleGrant) bool {
	if !s.greeting.Matches(g) {
		return false
	}
	bound, provisional := s.owner.Grant, &s.candidateOwner
	if g.Operation == a.LifecycleRetire {
		if !s.retirementMatchesOwner(g) {
			return false
		}
		bound, provisional = s.retirement.Grant, &s.candidateRetirement
	}
	if bound != (a.LifecycleGrant{}) {
		return g == bound
	}
	if *provisional == (a.LifecycleGrant{}) {
		*provisional = g
	}
	return g == *provisional
}

// Caller deadlines cap queue waiting as well as subsequent TLS IO. Revocation
// wakes queued operations even if the current transport has not yet unwound.
func (s *lifecycleSession) acquireOperation(ctx context.Context) error {
	if ctx == nil {
		return errLifecycleSession
	}
	select {
	case s.op <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closed:
		return errLifecycleSession
	}
	if err := ctx.Err(); err != nil {
		<-s.op
		return err
	}
	select {
	case <-s.closed:
		<-s.op
		return errLifecycleSession
	default:
		return nil
	}
}

// Frozen public PKI values received ONLY over the future trusted private boot
// channel. identity includes G; signed must be the entire already-bound grant.
type lifecycleBoot struct {
	identity     a.LifecycleIdentity
	signed       a.SignedLifecycleGrant
	serviceEpoch a.ID
	root         p.Root
	serverPin    p.Fingerprint
	certificate  p.Certificate
}

// Takes ownership of raw even on rejection. Exactly one initial boot attempt.
// The actual typed adapter is constructed here, never supplied by a caller.
func (s *lifecycleSession) connectTrustedBoot(ctx context.Context, raw net.Conn, boot lifecycleBoot) (err error) {
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
	if s.revoked || s.bootAttempted || ctx == nil || raw == nil {
		s.mu.Unlock()
		return errLifecycleSession
	}
	s.bootAttempted, s.raw = true, raw
	cfg, err := s.bootConfig(boot)
	var trust p.LifecycleBootTrust
	if err == nil {
		trust, err = s.deriveBootTrust(boot)
	}
	s.mu.Unlock()
	if err != nil {
		s.close()
		return err
	}
	client, err := c.NewLifecycleClient(ctx, raw, cfg)
	if err != nil {
		s.close()
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		client.Close()
		return errLifecycleSession
	}
	s.client = client
	s.bootTrust = trust
	s.privateBootConfig = cfg
	return nil
}

// Derive from actual immutable TLS inputs, never from a parent's asserted trust DTO.
func (s *lifecycleSession) deriveBootTrust(boot lifecycleBoot) (p.LifecycleBootTrust, error) {
	rootFingerprint, err := p.PublicKeyFingerprint(s.root.PublicKey())
	if err != nil {
		return p.LifecycleBootTrust{}, err
	}
	return p.NewLifecycleBootTrust(p.LifecycleBootTrustFields{
		Identity: boot.identity, ServiceEpoch: string(boot.serviceEpoch),
		TLSRootSHA256: p.Fingerprint(sha256.Sum256(boot.root.DER())).String(),
		ServerSPKI:    boot.serverPin.String(), BootstrapKey: rootFingerprint.String(),
	})
}

func (s *lifecycleSession) bootConfig(boot lifecycleBoot) (c.LifecycleClientConfig, error) {
	g := s.greeting.Fields()
	if s.owner.Grant == (a.LifecycleGrant{}) || boot.identity != s.owner.Grant.Identity || boot.signed.Grant != s.owner.Grant ||
		!bytes.Equal(boot.signed.Signature, s.owner.Signature) || !s.validGrant(boot.signed) || boot.serverPin == (p.Fingerprint{}) {
		return c.LifecycleClientConfig{}, errLifecycleSession
	}
	binding, err := p.NewControllerBinding(p.StoreID(g.Store), p.ControllerEpoch(g.ExpectedEpoch+1))
	if err != nil || boot.certificate.Binding() != binding {
		return c.LifecycleClientConfig{}, errLifecycleSession
	}
	identity, err := boot.certificate.WithKey(s.key)
	if err != nil {
		return c.LifecycleClientConfig{}, err
	}
	return c.LifecycleClientConfig{Identity: identity, ServerRoot: boot.root, ServerKey: boot.serverPin,
		Hello: c.LifecycleHello{Version: c.LifecycleControlVersion, Identity: boot.identity, ServiceEpoch: boot.serviceEpoch, ControllerEpoch: g.ExpectedEpoch + 1}}, nil
}

// Caller MUST authenticate this particular message as ROOT before calling proof.
// Challenges are DTOs, not evidence of their sender's audit identity.
func (s *lifecycleSession) proof(ctx context.Context, challenge p.LifecycleChildChallenge) (p.LifecycleChildReply, error) {
	if ctx == nil || challenge.Fields().ExpiresUnixMS > uint64(^uint64(0)>>1) {
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(int64(challenge.Fields().ExpiresUnixMS)))
	defer cancel()
	if err := s.acquireOperation(ctx); err != nil {
		return p.LifecycleChildReply{}, err
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	f := challenge.Fields()
	now := time.Now().UnixMilli()
	if s.revoked || ctx == nil || ctx.Err() != nil || now < 0 || !challenge.IsFresh(uint64(now)) ||
		f.Greeting != s.greeting.Fields() || f.ChildUniqueID != s.processes.childUniqueID ||
		f.ChildAudit != base64.StdEncoding.EncodeToString(s.processes.childAudit[:]) ||
		f.DaemonAudit != base64.StdEncoding.EncodeToString(s.processes.daemonAudit[:]) ||
		f.Counter <= s.highWater {
		s.mu.Unlock()
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	if f.Purpose == p.LifecycleChildCandidate {
		if !s.acceptCandidate(f.Grant) {
			s.mu.Unlock()
			return p.LifecycleChildReply{}, errLifecycleSession
		}
	} else if s.owner.Grant == (a.LifecycleGrant{}) || (f.Grant != s.owner.Grant && f.Grant != s.retirement.Grant) {
		// A provisional candidate can never authorize a result, boot or mutation.
		s.mu.Unlock()
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	// Consume BEFORE checking transport availability, IO, or signing. MaxUint64
	// can be the final counter; all later counters fail without wrapping/increment.
	s.highWater = f.Counter
	if f.Purpose == p.LifecycleChildCandidate {
		defer s.mu.Unlock()
		return s.key.SignLifecycleChildReply(challenge, nil)
	}
	if f.Purpose == p.LifecycleChildServiceResult || f.Purpose == p.LifecycleChildServiceCommit {
		s.mu.Unlock()
		return s.serviceProof(ctx, challenge)
	}
	if s.pendingRebind != nil {
		s.mu.Unlock()
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	client := s.client
	// This challenge came only from the ROOT-audited native channel. A valid
	// parent-selected TLS endpoint is not enough: compare before fresh Result IO.
	if client != nil && (f.Boot == nil || *f.Boot != s.bootTrust.Fields()) {
		s.mu.Unlock()
		s.close()
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	s.mu.Unlock()
	if client == nil {
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil {
		return p.LifecycleChildReply{}, err
	}
	// No Query, cached receipt, or supplied result can reach the signer.
	receipt, err := client.Result(ctx, f.Grant, nonce)
	if err != nil {
		return p.LifecycleChildReply{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || ctx.Err() != nil {
		return p.LifecycleChildReply{}, errLifecycleSession
	}
	reply, err := s.key.SignLifecycleChildReply(challenge, &receipt)
	if err == nil && f.Grant == s.owner.Grant {
		s.rootBootSeen = true
	}
	return reply, err
}

func (s *lifecycleSession) takeover(ctx context.Context) error { return s.apply(ctx, false) }
func (s *lifecycleSession) retire(ctx context.Context) error   { return s.apply(ctx, true) }

func (s *lifecycleSession) apply(ctx context.Context, retire bool) error {
	if err := s.acquireOperation(ctx); err != nil {
		return err
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	client, signed := s.client, s.owner
	if retire {
		signed = s.retirement
	}
	if s.revoked || s.pendingRebind != nil || ctx == nil || client == nil || (!retire && signed.Grant.Operation != a.LifecycleTakeover) || (retire && signed.Grant.Operation != a.LifecycleRetire) {
		s.mu.Unlock()
		return errLifecycleSession
	}
	if !retire {
		// Admission history only: normal retries remain unchanged.
		s.normalTakeoverAttempted = true
	}
	s.mu.Unlock()
	var err error
	if retire {
		err = client.Retire(ctx, signed)
	} else {
		_, err = client.Takeover(ctx, signed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return errLifecycleSession
	}
	return err // Success still cannot substitute for a fresh ROOT result proof.
}

func (s *lifecycleSession) close() {
	s.mu.Lock()
	if !s.revoked {
		s.revoked = true
		close(s.closed)
	}
	raw, client := s.raw, s.client
	workloadRaw, workload := s.workloadRaw, s.workload
	attachmentRaw := s.attachmentRaw
	pending := s.pendingRebind
	var pendingClient *c.LifecycleClient
	if pending != nil {
		pendingClient = pending.client
	}
	s.mu.Unlock()
	if pending != nil && pending.raw != nil {
		pending.raw.Close()
	}
	if pendingClient != nil {
		pendingClient.Close()
	}
	if attachmentRaw != nil {
		attachmentRaw.Close()
	}
	if workloadRaw != nil {
		workloadRaw.Close()
	}
	if workload != nil {
		workload.Close()
	}
	if client != nil {
		client.Close()
	} else if raw != nil {
		raw.Close()
	}
}
