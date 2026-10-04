package storageauthority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
)

// Principals have no exported authority fields, setters, or unchecked constructors.
// Passing a zero value or a principal from another Open always fails.
type DataPrincipal struct {
	owner   *Authority
	epoch   ID
	binding Binding
}

// Binding returns a value copy of the authenticated identity, including role and
// mode. It is routing/policy metadata, not proof of current admission: callers
// must still call Authority.Admit for EVERY request. The snapshot remains valid
// metadata after retirement or service closure, but cannot reactivate authority.
// A nil or zero principal has no authenticated binding.
func (p *DataPrincipal) Binding() (Binding, error) {
	if p == nil || p.owner == nil {
		return Binding{}, ErrUnauthorized
	}
	return p.binding, nil
}

type ControllerPrincipal struct {
	owner *Authority
	epoch uint64
	key   Fingerprint
}
type SuccessorPrincipal struct {
	owner *Authority
	key   Fingerprint
}

func verifiedPeer(ctx context.Context, conn *tls.Conn) (Fingerprint, error) {
	if conn == nil {
		return "", ErrUnauthorized
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	s := conn.ConnectionState()
	if !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.DidResume || len(s.PeerCertificates) == 0 || len(s.VerifiedChains) == 0 {
		return "", ErrUnauthorized
	}
	leaf := s.PeerCertificates[0]
	matched := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0].Equal(leaf) {
			matched = true
		}
	}
	if !matched {
		return "", ErrUnauthorized
	}
	client := false
	for _, use := range leaf.ExtKeyUsage {
		if use == x509.ExtKeyUsageClientAuth {
			client = true
		}
	}
	if !client {
		return "", ErrUnauthorized
	}
	return PublicKeyFingerprint(leaf.PublicKey)
}
func (a *Authority) AuthenticateData(ctx context.Context, conn *tls.Conn, h DataHello) (*DataPrincipal, error) {
	key, err := verifiedPeer(ctx, conn)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.available(); err != nil {
		return nil, err
	}
	rec, ok := a.s.Attachments[h.Binding.Attachment]
	if !ok || h.Epoch != a.s.Epoch || h.Binding != rec.Binding || key != rec.Binding.Key {
		return nil, ErrUnauthorized
	}
	if rec.Phase != Active {
		return nil, ErrBlocked
	}
	rt := a.runtime[h.Binding.Attachment]
	// One authenticated data connection per A,E. No reconnect/replay.
	if rt.connected {
		return nil, ErrConflict
	}
	rt.connected = true
	return &DataPrincipal{a, a.s.Epoch, rec.Binding}, nil
}
func (a *Authority) AuthenticateController(ctx context.Context, conn *tls.Conn, epoch uint64) (*ControllerPrincipal, error) {
	key, err := verifiedPeer(ctx, conn)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.available(); err != nil {
		return nil, err
	}
	if a.s.Controller.Key != key || a.s.Controller.Epoch != epoch {
		return nil, ErrUnauthorized
	}
	return &ControllerPrincipal{a, epoch, key}, nil
}

// AuthenticateSuccessor verifies TLS key possession only. It grants no control
// authority; TakeoverLifecycle atomically validates the separately signed grant.
func (a *Authority) AuthenticateSuccessor(ctx context.Context, conn *tls.Conn) (*SuccessorPrincipal, error) {
	key, err := verifiedPeer(ctx, conn)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.available(); err != nil {
		return nil, err
	}
	return &SuccessorPrincipal{a, key}, nil
}
