package storagecontrol

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"net"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// LifecycleWorkloadVersion identifies the workload CONTROL protocol.
// Only Query uses registry schema 4; workload operations use schema 3 receipts.
// Successor admission and Takeover are not available on this endpoint.
const LifecycleWorkloadVersion = 3

// workloadPolicy is fixed by construction, not selected by an incoming Hello or
// response schema. Its zero value refuses every handshake and snapshot.
// Values are detached copies; no caller-controlled identity pointer is retained.
type workloadPolicy struct {
	identity   a.LifecycleIdentity
	epoch      a.ID
	controller a.Controller
}

func (p workloadPolicy) lifecycle() bool { return p.identity != (a.LifecycleIdentity{}) }
func (p workloadPolicy) version() int    { return LifecycleWorkloadVersion }
func (p workloadPolicy) identityCopy() *a.LifecycleIdentity {
	if !p.lifecycle() {
		return nil
	}
	i := p.identity
	return &i
}
func (p workloadPolicy) matchesIdentity(i *a.LifecycleIdentity) bool {
	if !p.lifecycle() {
		return false
	}
	return i != nil && *i == p.identity
}
func (p workloadPolicy) validHello(h Hello) bool {
	if !p.lifecycle() {
		return false
	}
	return h.Version == LifecycleWorkloadVersion && h.Role == Controller &&
		h.ControllerEpoch == p.controller.Epoch && h.Store == p.identity.Store &&
		h.ServiceEpoch == p.epoch && p.matchesIdentity(h.LifecycleIdentity)
}
func (p workloadPolicy) validSnapshot(s *a.Snapshot) bool {
	if s == nil || s.Revision == 0 {
		return false
	}
	if !p.lifecycle() {
		return false
	}
	return s.Schema == a.LifecycleSchemaVersion && s.Store.ID == p.identity.Store &&
		s.Epoch == p.epoch && s.Controller == p.controller
}

// PKILifecycleWorkloadClientConfig requires independently reconciled full
// incarnation, live server E/pin, and current controller epoch/key. It exposes
// neither a caller TLS config nor a version/role negotiation or fallback.
type PKILifecycleWorkloadClientConfig struct {
	Identity          p.Identity
	ServerRoot        p.Root
	ServerKey         p.Fingerprint
	LifecycleIdentity a.LifecycleIdentity
	ServiceEpoch      a.ID
	CurrentController a.Controller
	Limits            Limits
}

// PKILifecycleWorkloadServerConfig has no successor/grant admission fields.
// The authority must be a real live InitializeLifecycle/OpenLifecycle owner.
type PKILifecycleWorkloadServerConfig struct {
	Identity          p.Identity
	ClientRoot        p.Root
	LifecycleIdentity a.LifecycleIdentity
	ServiceEpoch      a.ID
	CurrentController a.Controller
	Limits            Limits
}

func lifecycleWorkloadPolicy(identity a.LifecycleIdentity, epoch a.ID, controller a.Controller) (workloadPolicy, error) {
	if identity.Validate() != nil || !validID(epoch) || controller.Epoch == 0 {
		return workloadPolicy{}, ErrConfiguration
	}
	if _, err := lifecycleWorkloadKey(controller.Key); err != nil {
		return workloadPolicy{}, ErrConfiguration
	}
	return workloadPolicy{identity: identity, epoch: epoch, controller: controller}, nil
}

func lifecycleWorkloadKey(value a.Fingerprint) (p.Fingerprint, error) {
	var key p.Fingerprint
	b, err := hex.DecodeString(string(value))
	if err != nil || len(b) != len(key) || hex.EncodeToString(b) != string(value) {
		return key, ErrConfiguration
	}
	copy(key[:], b)
	return key, nil
}

// NewPKILifecycleWorkloadClient owns raw on success or failure and admits only
// workload protocol v3 with the configured lifecycle identity.
func NewPKILifecycleWorkloadClient(ctx context.Context, raw net.Conn, c PKILifecycleWorkloadClientConfig) (_ *Client, err error) {
	defer func() {
		if err != nil && raw != nil {
			raw.Close()
		}
	}()
	policy, err := lifecycleWorkloadPolicy(c.LifecycleIdentity, c.ServiceEpoch, c.CurrentController)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(c.Identity.Certificate().DER())
	if err != nil {
		return nil, ErrConfiguration
	}
	certKey, err := a.PublicKeyFingerprint(leaf.PublicKey)
	if err != nil || certKey != c.CurrentController.Key {
		return nil, ErrConfiguration
	}
	server, err := p.NewServerBinding(p.StoreID(c.LifecycleIdentity.Store), p.ServiceEpoch(c.ServiceEpoch))
	if err != nil {
		return nil, ErrConfiguration
	}
	controller, err := p.NewControllerBinding(p.StoreID(c.LifecycleIdentity.Store), p.ControllerEpoch(c.CurrentController.Epoch))
	if err != nil {
		return nil, ErrConfiguration
	}
	return newPKIClient(ctx, raw, workloadPKIClientConfig{
		Identity: c.Identity, ServerRoot: c.ServerRoot, Server: server, ServerKey: c.ServerKey,
		Controller: controller, ControllerEpoch: c.CurrentController.Epoch, Limits: c.Limits,
		Hello: Hello{Version: LifecycleWorkloadVersion, Role: Controller, ControllerEpoch: c.CurrentController.Epoch,
			Store: c.LifecycleIdentity.Store, ServiceEpoch: c.ServiceEpoch, LifecycleIdentity: policy.identityCopy()},
	}, policy)
}

func NewPKILifecycleWorkloadServer(authority *a.Authority, c PKILifecycleWorkloadServerConfig) (*Server, error) {
	policy, err := lifecycleWorkloadPolicy(c.LifecycleIdentity, c.ServiceEpoch, c.CurrentController)
	if err != nil || authority == nil {
		return nil, ErrConfiguration
	}
	meta, err := authority.LifecycleMetadata()
	if err != nil || meta.Identity != c.LifecycleIdentity || meta.Store.ID != c.LifecycleIdentity.Store ||
		meta.Epoch != c.ServiceEpoch || meta.Controller != c.CurrentController || meta.Sealed || meta.RetirementGrant != (a.LifecycleGrant{}) {
		return nil, ErrConfiguration
	}
	server, err := p.NewServerBinding(p.StoreID(c.LifecycleIdentity.Store), p.ServiceEpoch(c.ServiceEpoch))
	if err != nil {
		return nil, ErrConfiguration
	}
	controller, err := p.NewControllerBinding(p.StoreID(c.LifecycleIdentity.Store), p.ControllerEpoch(c.CurrentController.Epoch))
	if err != nil {
		return nil, ErrConfiguration
	}
	key, err := lifecycleWorkloadKey(c.CurrentController.Key)
	if err != nil {
		return nil, ErrConfiguration
	}
	return newPKIServer(authority, workloadPKIServerConfig{
		Identity: c.Identity, ClientRoot: c.ClientRoot, Store: c.LifecycleIdentity.Store, ServiceEpoch: c.ServiceEpoch,
		Server: server, Controller: controller, ControllerEpoch: c.CurrentController.Epoch, ControllerKey: key, Limits: c.Limits,
	}, policy)
}
