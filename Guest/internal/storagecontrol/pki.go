package storagecontrol

import (
	"context"
	"crypto/tls"
	"net"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// workloadPKIClientConfig freezes the lifecycle controller and server scope.
type workloadPKIClientConfig struct {
	Identity        p.Identity
	ServerRoot      p.Root
	Server          p.Binding
	ServerKey       p.Fingerprint
	Controller      p.Binding
	ControllerEpoch uint64
	Hello           Hello
	Limits          Limits
}

func newPKIClient(ctx context.Context, raw net.Conn, c workloadPKIClientConfig, policy workloadPolicy) (_ *Client, err error) {
	defer func() {
		if err != nil && raw != nil {
			raw.Close()
		}
	}()
	if ctx == nil || raw == nil || !policy.validHello(c.Hello) {
		return nil, ErrConfiguration
	}
	server, e := p.NewServerBinding(p.StoreID(c.Hello.Store), p.ServiceEpoch(c.Hello.ServiceEpoch))
	if e != nil || server != c.Server {
		return nil, ErrConfiguration
	}
	controller, e := p.NewControllerBinding(p.StoreID(c.Hello.Store), p.ControllerEpoch(c.ControllerEpoch))
	if e != nil || controller != c.Controller || c.Identity.Certificate().Binding() != controller || (c.Hello.Role == Controller && c.ControllerEpoch != c.Hello.ControllerEpoch) {
		return nil, ErrConfiguration
	}
	conn, e := p.NewControllerTLSClient(raw, c.Identity, c.ServerRoot, server, c.ServerKey)
	if e != nil {
		return nil, ErrConfiguration
	}
	return newClientOwned(ctx, raw, workloadClientConfig{ServerKey: a.Fingerprint(c.ServerKey.String()), Hello: c.Hello, Limits: c.Limits}, conn, policy)
}

// workloadPKIServerConfig pins one lifecycle controller generation. Reconstruct
// it after takeover using independently reconciled registry metadata.
type workloadPKIServerConfig struct {
	Identity        p.Identity
	ClientRoot      p.Root
	Store           a.ID
	ServiceEpoch    a.ID
	Server          p.Binding
	Controller      p.Binding
	ControllerEpoch uint64
	ControllerKey   p.Fingerprint
	Limits          Limits
}

func newPKIServer(authority *a.Authority, c workloadPKIServerConfig, policy workloadPolicy) (*Server, error) {
	if !policy.lifecycle() || authority == nil || !validID(c.Store) || c.ServiceEpoch != authority.Epoch() {
		return nil, ErrConfiguration
	}
	server, err := p.NewServerBinding(p.StoreID(c.Store), p.ServiceEpoch(c.ServiceEpoch))
	if err != nil || c.Server != server || c.Identity.Certificate().Binding() != server {
		return nil, ErrConfiguration
	}
	controller, err := p.NewControllerBinding(p.StoreID(c.Store), p.ControllerEpoch(c.ControllerEpoch))
	if err != nil || c.Controller != controller || c.ControllerKey == (p.Fingerprint{}) {
		return nil, ErrConfiguration
	}
	l, err := limits(c.Limits)
	if err != nil {
		return nil, err
	}
	cfg, err := p.ServerTLSConfig(c.Identity, c.ClientRoot)
	if err != nil {
		return nil, ErrConfiguration
	}
	return &Server{authority: authority, config: workloadServerConfig{TLS: cfg, Store: c.Store, Limits: l}, pki: &c, policy: policy, slots: make(chan struct{}, l.Connections), queries: make(chan struct{}, 1), createVolume: authority.CreateVolume}, nil
}

func (c workloadPKIServerConfig) verifyPeer(state tls.ConnectionState, h Hello) error {
	if h.Store != c.Store || h.ServiceEpoch != c.ServiceEpoch {
		return a.ErrUnauthorized
	}
	binding, pin := c.Controller, c.ControllerKey
	if h.Role != Controller || h.ControllerEpoch != c.ControllerEpoch {
		return a.ErrUnauthorized
	}
	if p.VerifyController(state, c.ClientRoot, binding, pin) != nil {
		return a.ErrUnauthorized
	}
	return nil
}
