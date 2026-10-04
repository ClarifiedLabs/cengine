package storageservice

// Lifecycle-only composition. No listener, unchecked principal, or exported
// base resource owner is provided by this package.
import (
	"context"
	"crypto/ed25519"
	"net"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

// LifecycleService must not be copied. owner retains the real resource barrier,
// PKI issuer and DATA server. All fields below are protected by owner.mu. Active
// lifecycle connections retain only their fixed endpoint; one shared counter
// bounds all generations. Installing policy never requires idle result sessions.
type LifecycleService struct {
	owner      *commonService
	endpoint   *c.LifecycleServer
	pending    a.LifecycleGrant
	retirement a.LifecycleGrant
}

func lifecycleController(g a.LifecycleGrant) a.Controller {
	epoch := g.ExpectedEpoch + 1
	if g.Operation == a.LifecycleRetire {
		epoch = g.ExpectedEpoch
	}
	return a.Controller{Epoch: epoch, Key: g.NewKey}
}
func verifyLifecycleGrant(cfg Config, signed a.SignedLifecycleGrant) error {
	message, err := a.LifecycleGrantSigningBytes(signed.Grant)
	if err != nil {
		return err
	}
	key := cfg.Bootstrap.PublicKey()
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, signed.Signature) {
		return a.ErrUnauthorized
	}
	return nil
}

// InitializeLifecycle accepts only ROOT's fresh initialize/expected-zero grant.
func InitializeLifecycle(cfg Config, signed a.SignedLifecycleGrant) (*LifecycleService, error) {
	if signed.Grant.Operation != a.LifecycleInitialize {
		return nil, ErrConfiguration
	}
	return constructLifecycle(cfg, signed.Grant.Identity, signed, true, nil)
}

// OpenLifecycle requires the full externally reconciled incarnation AND the
// signed exact latest initialize/takeover grant. Missing/v1/terminal state is
// never initialized, adopted or migrated. Exact latest-grant admission occurs
// under the authority journal flock before recovery, cleanup or advancing E.
func OpenLifecycle(cfg Config, identity a.LifecycleIdentity, current a.SignedLifecycleGrant) (*LifecycleService, error) {
	return constructLifecycle(cfg, identity, current, false, nil)
}

// ReopenLifecycle guards the exact reconciled predecessor S/E/C/key/open revision.
// Success consumes that predecessor; rejected intent never changes disk bytes/E.
func ReopenLifecycle(cfg Config, identity a.LifecycleIdentity, current a.SignedLifecycleGrant, expected a.ExpectedLifecycleStartup) (*LifecycleService, error) {
	return constructLifecycle(cfg, identity, current, false, &expected)
}

func constructLifecycle(cfg Config, identity a.LifecycleIdentity, current a.SignedLifecycleGrant, initialize bool, expected *a.ExpectedLifecycleStartup) (*LifecycleService, error) {
	if err := verifyLifecycleGrant(cfg, current); err != nil {
		return nil, err
	}
	if current.Grant.Identity != identity || identity.Store != cfg.Store || current.Grant.Operation == a.LifecycleRetire {
		return nil, a.ErrConflict
	}
	owner, err := constructAuthority(cfg, lifecycleController(current.Grant), func(ac a.Config) (*a.Authority, error) {
		if initialize {
			return a.InitializeLifecycle(ac, current)
		}
		if expected != nil {
			return a.OpenLifecycleExpected(ac, current, *expected)
		}
		return a.OpenLifecycleCurrent(ac, current)
	})
	if err != nil {
		return nil, err
	}
	return finishLifecycle(owner)
}

// ColdOpenAndTakeover consumes an exact ROOT-authorized cold predecessor. The
// authority commits the new service epoch and controller together; the ordinary
// resource owner and fresh TLS endpoints are then built from actual metadata.
func ColdOpenAndTakeover(cfg Config, signed a.SignedLifecycleColdOpen) (*LifecycleService, error) {
	if err := a.VerifyLifecycleColdOpen(cfg.Bootstrap.PublicKey(), signed); err != nil {
		return nil, err
	}
	request := signed.Request
	if request.Takeover.Grant.Identity.Store != cfg.Store ||
		!cfg.Now.Equal(time.Unix(int64(request.NowUnixSeconds), 0)) ||
		cfg.Lifetime != time.Duration(request.LifetimeSeconds)*time.Second {
		return nil, ErrConfiguration
	}
	owner, err := constructAuthority(cfg, lifecycleController(request.Takeover.Grant), func(ac a.Config) (*a.Authority, error) {
		return a.ColdOpenAndTakeover(ac, signed)
	})
	if err != nil {
		return nil, err
	}
	return finishLifecycle(owner)
}

// ResumeOpenAndTakeover consumes an exact ROOT-authorized fresh-init resume of
// a previously witnessed, unused initialization. UPSTREAM PRECONDITION (PID1,
// before this constructor and before any write): the read-only,
// no-replay probe ran a clean superblock check, the authority read-only census
// admitted the closed empty layout or the exact original genesis registry, and
// ONLY THEN was the lease promoted to the read-write mount cfg.Root names.
// This constructor performs the single publishing upgrade: the successor
// C2/E/key commit happens at most once (an exact applied retry is read-only,
// not a live recovery). No formatting, predecessor fabrication or dirty replay.
func ResumeOpenAndTakeover(cfg Config, signed a.SignedLifecycleResumeOpen) (*LifecycleService, error) {
	if err := a.VerifyLifecycleResumeOpen(cfg.Bootstrap.PublicKey(), signed); err != nil {
		return nil, err
	}
	request := signed.Request
	if request.Takeover.Grant.Identity.Store != cfg.Store ||
		!cfg.Now.Equal(time.Unix(int64(request.NowUnixSeconds), 0)) ||
		cfg.Lifetime != time.Duration(request.LifetimeSeconds)*time.Second {
		return nil, ErrConfiguration
	}
	owner, err := constructAuthority(cfg, lifecycleController(request.Takeover.Grant), func(ac a.Config) (*a.Authority, error) {
		return a.ResumeOpenAndTakeover(ac, signed)
	})
	if err != nil {
		return nil, err
	}
	return finishLifecycle(owner)
}

func finishLifecycle(owner *commonService) (*LifecycleService, error) {
	s := &LifecycleService{owner: owner}
	meta, err := owner.authority.LifecycleMetadata()
	if err == nil {
		owner.control, err = s.newWorkloadControl(meta)
	}
	if err == nil {
		s.endpoint, err = s.newEndpoint(meta, a.LifecycleGrant{}, a.LifecycleGrant{})
	}
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	return s, nil
}
func (s *LifecycleService) valid() bool { return s != nil && s.owner != nil }

// Scope is bounded public metadata, not a receipt or authorization capability.
func (s *LifecycleService) Scope() (a.LifecycleMetadata, error) {
	if !s.valid() {
		return a.LifecycleMetadata{}, ErrConfiguration
	}
	return s.owner.authority.LifecycleMetadata()
}
func (s *LifecycleService) Ready() (Ready, error) {
	if !s.valid() {
		return Ready{}, ErrConfiguration
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	meta, err := o.authority.LifecycleMetadata()
	if err != nil {
		return Ready{}, err
	}
	leaf := o.identity.Certificate()
	key, err := certificatePin(leaf)
	if err != nil {
		return Ready{}, err
	}
	return Ready{meta.Store, meta.Epoch, meta.Controller, meta.Revision, meta.Bootstrap, o.issuer.Root().DER(), leaf.DER(), key}, nil
}
func (s *LifecycleService) IssueController(csr []byte) (p.Certificate, error) {
	if !s.valid() {
		return p.Certificate{}, ErrConfiguration
	}
	return s.owner.IssueController(csr)
}

func (s *LifecycleService) newWorkloadControl(meta a.LifecycleMetadata) (*c.Server, error) {
	o := s.owner
	return c.NewPKILifecycleWorkloadServer(o.authority, c.PKILifecycleWorkloadServerConfig{
		Identity: o.identity, ClientRoot: o.issuer.Root(), LifecycleIdentity: meta.Identity,
		ServiceEpoch: meta.Epoch, CurrentController: meta.Controller, Limits: o.config.ControlLimits,
	})
}

func (s *LifecycleService) newEndpoint(meta a.LifecycleMetadata, pending, retirement a.LifecycleGrant) (*c.LifecycleServer, error) {
	o := s.owner
	key, err := pin(meta.Controller.Key)
	if err != nil {
		return nil, err
	}
	limits := o.config.ControlLimits
	// Lifecycle has its own small fixed wire, while sharing the configured
	// connection/time bounds. Ordinary workload response limits stay unchanged.
	if limits.RequestBytes > 16<<10 {
		limits.RequestBytes = 16 << 10
	}
	if limits.ResponseBytes > 16<<10 {
		limits.ResponseBytes = 16 << 10
	}
	cfg := c.LifecycleServerConfig{Identity: o.identity, ClientRoot: o.issuer.Root(), ServiceEpoch: meta.Epoch, CurrentGrant: meta.CurrentGrant, ControllerKey: key, SuccessorGrant: pending, RetireGrant: retirement, Limits: limits}
	if pending != (a.LifecycleGrant{}) {
		cfg.SuccessorKey, err = pin(pending.NewKey)
		if err != nil {
			return nil, err
		}
	}
	return c.NewLifecycleServer(o.authority, cfg)
}
func (s *LifecycleService) current() (a.LifecycleMetadata, error) {
	meta, err := s.owner.authority.LifecycleMetadata()
	if err != nil {
		return meta, err
	}
	if meta.RetirementGrant != (a.LifecycleGrant{}) {
		return meta, a.ErrBlocked
	}
	if meta.Controller != s.owner.generation {
		return meta, a.ErrConflict
	}
	return meta, nil
}

// AuthorizeSuccessor pins one exact ROOT-authorized next tuple and issues only
// its CSR. No assertion here advances the authority. Existing lifecycle sessions
// remain usable for fresh ROOT challenges until their own authority goes stale.
func (s *LifecycleService) AuthorizeSuccessor(signed a.SignedLifecycleGrant, csr []byte) (p.Certificate, error) {
	if !s.valid() {
		return p.Certificate{}, ErrConfiguration
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	meta, err := s.current()
	if err != nil {
		return p.Certificate{}, err
	}
	if err = verifyLifecycleGrant(o.config, signed); err != nil {
		return p.Certificate{}, err
	}
	g := signed.Grant
	if g.Operation != a.LifecycleTakeover || g.Identity != meta.Identity || g.ExpectedEpoch != meta.Controller.Epoch || g.Serial <= meta.CurrentGrant.Serial || g.ID == meta.CurrentGrant.ID || g.NewKey == meta.Controller.Key || g.NewKey == meta.Bootstrap {
		return p.Certificate{}, a.ErrUnauthorized
	}
	if s.retirement != (a.LifecycleGrant{}) || (s.pending != (a.LifecycleGrant{}) && s.pending != g) {
		return p.Certificate{}, a.ErrConflict
	}
	if err = csrPin(csr, g.NewKey); err != nil {
		return p.Certificate{}, err
	}
	binding, err := p.NewControllerBinding(p.StoreID(meta.Store.ID), p.ControllerEpoch(g.ExpectedEpoch+1))
	if err != nil {
		return p.Certificate{}, err
	}
	cert, err := o.issuer.IssueController(csr, binding, o.config.Now, o.config.Lifetime)
	if err != nil {
		return p.Certificate{}, err
	}
	if s.pending == g {
		return cert, nil
	}
	endpoint, err := s.newEndpoint(meta, g, a.LifecycleGrant{})
	if err != nil {
		return p.Certificate{}, err
	}
	s.endpoint, s.pending = endpoint, g
	return cert, nil
}

// AuthorizeRetirement allows one terminal grant for the exact current owner.
// ROOT is verified before monotonically arming the existing endpoint, including
// the persistent child's already-connected session. No identity/E/C/pin changes.
// Actual TLS RetireLifecycle must still verify ROOT and prove resource retirement.
func (s *LifecycleService) AuthorizeRetirement(signed a.SignedLifecycleGrant) error {
	if !s.valid() {
		return ErrConfiguration
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	meta, err := s.current()
	if err != nil {
		return err
	}
	if err = verifyLifecycleGrant(o.config, signed); err != nil {
		return err
	}
	g := signed.Grant
	if g.Operation != a.LifecycleRetire || g.Identity != meta.Identity || lifecycleController(g) != meta.Controller || g.Serial <= meta.CurrentGrant.Serial || g.ID == meta.CurrentGrant.ID {
		return a.ErrUnauthorized
	}
	if s.pending != (a.LifecycleGrant{}) || (s.retirement != (a.LifecycleGrant{}) && s.retirement != g) {
		return a.ErrConflict
	}
	if s.retirement == g {
		return nil
	}
	if err = s.endpoint.ArmRetirement(g); err != nil {
		return err
	}
	s.retirement = g
	return nil
}

// ReconcileController only installs workload CONTROL after real TLS takeover
// and after all old workload CONTROL/CSR workers are drained and joined. Idle
// lifecycle result connections need not close. DATA/resources are never replaced.
func (s *LifecycleService) ReconcileController(expected a.Controller) error {
	if !s.valid() {
		return ErrConfiguration
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	meta, err := o.authority.LifecycleMetadata()
	if err != nil {
		return err
	}
	if meta.RetirementGrant != (a.LifecycleGrant{}) {
		return a.ErrBlocked
	}
	if meta.Controller != expected {
		return a.ErrConflict
	}
	if s.pending == (a.LifecycleGrant{}) {
		if expected != o.generation {
			return a.ErrConflict
		}
		return nil
	}
	if meta.CurrentGrant != s.pending || expected != lifecycleController(s.pending) {
		return a.ErrConflict
	}
	if o.controlActive != 0 {
		return a.ErrBusy
	}
	control, err := s.newWorkloadControl(meta)
	if err != nil {
		return err
	}
	o.control, o.generation = control, expected
	// Preserve the successor endpoint: the persistent promoted child is still
	// connected to it and later retirement must arm that very endpoint. Its
	// frozen old-current + promoted-successor pair remains bounded; fresh
	// authority checks reject old owners. The next AuthorizeSuccessor installs
	// a new current + next pair (ROOT separately requires the old child dead).
	s.pending = a.LifecycleGrant{}
	return nil
}

// ServeLifecycle owns raw and charges one bounded shared slot across every fixed
// endpoint generation until its worker actually returns, including cancellation.
func (s *LifecycleService) ServeLifecycle(ctx context.Context, raw net.Conn) error {
	if !s.valid() || raw == nil {
		if raw != nil {
			raw.Close()
		}
		return ErrConfiguration
	}
	o := s.owner
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		raw.Close()
		return a.ErrClosed
	}
	if o.lifecycleActive >= o.config.ControlLimits.Connections {
		o.mu.Unlock()
		raw.Close()
		return c.ErrLimit
	}
	o.lifecycleActive++
	o.transportStarted = true
	endpoint := s.endpoint
	o.mu.Unlock()
	defer func() { o.mu.Lock(); o.lifecycleActive--; o.mu.Unlock() }()
	return endpoint.Serve(ctx, raw)
}
func (s *LifecycleService) ServeControl(ctx context.Context, raw net.Conn) error {
	if !s.valid() {
		if raw != nil {
			raw.Close()
		}
		return ErrConfiguration
	}
	return s.owner.ServeControl(ctx, raw)
}
func (s *LifecycleService) ServeData(ctx context.Context, raw net.Conn) error {
	if !s.valid() {
		if raw != nil {
			raw.Close()
		}
		return ErrConfiguration
	}
	return s.owner.ServeData(ctx, raw)
}
func (s *LifecycleService) ServeAttachmentCSR(ctx context.Context, raw net.Conn) error {
	if !s.valid() {
		if raw != nil {
			raw.Close()
		}
		return ErrConfiguration
	}
	return s.serveLifecycleAttachmentCSR(ctx, raw)
}
func (s *LifecycleService) Notifications() <-chan RetirementNotification {
	if !s.valid() {
		return nil
	}
	return s.owner.Notifications()
}
func (s *LifecycleService) Close() error {
	if !s.valid() {
		return ErrConfiguration
	}
	if err := s.owner.Close(); err != nil {
		return err
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	// Closed admission and joined workers make releasing the final endpoint's
	// TLS identity safe; do not retain private server material through the wrapper.
	s.endpoint = nil
	s.pending, s.retirement = a.LifecycleGrant{}, a.LifecycleGrant{}
	return nil
}
