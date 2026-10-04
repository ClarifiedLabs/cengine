// Package storageservice composes the real managed authority, resource owner,
// typed TLS PKI, and transports. It opens no listener and is not startup-wired.
package storageservice

import (
	"crypto/tls"
	"errors"
	"os"
	"sync"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

var ErrConfiguration = errors.New("storageservice: invalid configuration or credential request")

// Config is accepted only from the one-shot trusted private boot path. Root and
// DeviceUUID must already refer to the exact verified held disk; this package
// cannot verify a VZ device. No file/env/network trust override is supported.
// Root is borrowed during construction; Authority duplicates its descriptors.
// Now is authenticated host time. All leaf certificates expire with this boot CA.
type Config struct {
	Root            *os.File
	DeviceUUID      string
	Store           a.ID
	Bootstrap       p.BootstrapPublicKey
	Now             time.Time
	Lifetime        time.Duration
	AuthorityLimits a.Limits
	DataLimits      d.Limits
	ControlLimits   c.Limits
}

// Ready is public, detached metadata, never a readiness/activation certificate.
// Bootstrap and TLSRootDER are different trust domains. No private material is
// exposed; pins/DER must travel only over the paired private bootstrap channel.
type Ready struct {
	Store        a.Store
	ServiceEpoch a.ID
	Controller   a.Controller
	Revision     uint64
	Bootstrap    a.Fingerprint
	TLSRootDER   []byte
	ServerDER    []byte
	ServerKey    p.Fingerprint
}

type RetirementNotification struct{ Hello a.DataHello }

// commonService must not be copied. It retains the only service CA/server identities.
// All public operations are bounded and all authority mutations remain behind
// actual authenticated control TLS. There is no direct Retire or principal API.
type commonService struct {
	isolationMu               sync.Mutex
	isolationAddress          string
	isolationPending          *legacyListenerProbe
	consumer                  *d.ConsumerObservation
	compatibilityMu           sync.Mutex
	compatibilityWorker       string
	compatibilityInstalling   bool
	compatibility             *servicePrepareCompatibility
	compatibilityCheckpoint   bool // one-shot RTM098 guest checkpoint exit claim
	issuedPrepare             map[a.ID]issuedPrepareCertificate
	mu                        sync.Mutex
	authority                 *a.Authority
	resources                 *d.Resources
	data                      *d.Server
	control                   *c.Server
	issuer                    p.Issuer
	identity                  p.Identity
	credentialTLS             *tls.Config
	config                    Config
	generation                a.Controller
	controlActive, dataActive int
	lifecycleActive           int // shared bound across fixed lifecycle endpoints
	closed                    bool
	transportStarted          bool // under mu; remains true after the last disconnect
	notifications             chan RetirementNotification
}

// constructAuthority owns the shared resource barrier, PKI and DATA transport.
// finishLifecycle installs the control endpoints afterward. The opener is private.
func constructAuthority(cfg Config, expected a.Controller, open func(a.Config) (*a.Authority, error)) (_ *commonService, err error) {
	if cfg.Root == nil || cfg.DeviceUUID == "" || expected.Epoch == 0 {
		return nil, ErrConfiguration
	}
	if _, err = p.NewControllerBinding(p.StoreID(cfg.Store), p.ControllerEpoch(expected.Epoch)); err != nil {
		return nil, err
	}
	if _, err = pin(expected.Key); err != nil {
		return nil, err
	}
	cfg.DataLimits, err = d.ValidateLimits(cfg.DataLimits)
	if err != nil {
		return nil, err
	}
	cfg.ControlLimits, err = controlLimits(cfg.ControlLimits)
	if err != nil {
		return nil, err
	}
	issuer, err := p.NewIssuer(cfg.Now, cfg.Lifetime, cfg.Bootstrap)
	if err != nil {
		return nil, err
	}
	resources, err := d.NewResources()
	if err != nil {
		return nil, err
	}
	ac := a.Config{Root: cfg.Root, DeviceID: cfg.DeviceUUID, BootstrapKey: cfg.Bootstrap.PublicKey(), Barrier: resources.Barrier, Limits: cfg.AuthorityLimits, CopyRecoveryPreflight: resources.PreflightCopyRecovery, PrepareRetirementProof: resources.PrepareRetirementProof}
	authority, err := open(ac)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = authority.Close()
		}
	}()
	meta, err := authority.StartupMetadata()
	if err != nil {
		return nil, err
	}
	if meta.Store.ID != cfg.Store || meta.Controller != expected {
		return nil, a.ErrConflict
	}
	key, err := p.NewServerKey()
	if err != nil {
		return nil, err
	}
	binding, err := p.NewServerBinding(p.StoreID(meta.Store.ID), p.ServiceEpoch(meta.Epoch))
	if err != nil {
		return nil, err
	}
	csr, err := key.CSR(binding)
	if err != nil {
		return nil, err
	}
	cert, err := issuer.IssueServer(csr, binding, cfg.Now, cfg.Lifetime)
	if err != nil {
		return nil, err
	}
	identity, err := cert.WithKey(key)
	if err != nil {
		return nil, err
	}
	s := &commonService{consumer: d.NewConsumerObservation(), authority: authority, resources: resources, issuer: issuer, identity: identity, config: cfg, generation: meta.Controller, notifications: make(chan RetirementNotification, 32)}
	s.config.Root = nil // retain no caller descriptor
	s.credentialTLS, err = p.ServerTLSConfig(identity, issuer.Root())
	if err != nil {
		return nil, err
	}
	// Claim the resource owner only after all other construction has succeeded.
	s.data, err = d.NewPKIWithResources(resources, authority, d.PKIConfig{Identity: identity, ClientRoot: issuer.Root(), Store: meta.Store.ID, ServiceEpoch: meta.Epoch, Limits: cfg.DataLimits, RequestRetirement: func(h a.DataHello, _ error) { s.notifications <- RetirementNotification{Hello: h} }})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *commonService) Ready() (Ready, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Ready{}, a.ErrClosed
	}
	meta, err := s.authority.StartupMetadata()
	if err != nil {
		return Ready{}, err
	}
	leaf := s.identity.Certificate()
	serverPin, err := certificatePin(leaf)
	if err != nil {
		return Ready{}, err
	}
	return Ready{meta.Store, meta.Epoch, meta.Controller, meta.Revision, meta.Bootstrap, s.issuer.Root().DER(), leaf.DER(), serverPin}, nil
}

// Notifications is a bounded, lossless handoff to the trusted host. A full queue
// holds DATA connection capacity. Receiving a notification does not retire A,
// release guards, or prove drain. The controller must send its durable Retire RPC.
func (s *commonService) Notifications() <-chan RetirementNotification { return s.notifications }

// Close refuses active transport/work and retained managed resources. It never
// manufactures retirement on transport loss. Caller must cancel/join connections
// and obtain real Retire receipts first. No descriptor is force-closed as a drain.
func (s *commonService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.controlActive != 0 || s.lifecycleActive != 0 || s.dataActive != 0 || !s.resources.Idle() {
		return a.ErrBusy
	}
	if err := s.authority.Close(); err != nil {
		return err
	}
	s.closed = true
	s.consumer.Close()
	close(s.notifications)
	s.issuer, s.identity, s.credentialTLS = p.Issuer{}, p.Identity{}, nil
	s.control, s.data = nil, nil
	return nil
}
