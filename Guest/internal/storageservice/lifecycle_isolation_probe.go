package storageservice

import (
	"bytes"
	"context"
	"net"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
)

// ProbeIsolation observes the actual lifecycle owner, never the v1 Ready path.
// PID1 owns the separate-process exclusivity challenger and adds the authenticated
// request/worker binding; this service accepts only fixed, read-only observations.
func (s *LifecycleService) ProbeIsolation(kind string) (*IsolationProof, error) {
	if !s.valid() {
		return nil, ErrConfiguration
	}
	if pc.CurrentProfile() != pc.FullProfile || (kind != "isolation-state" && kind != "legacy-connection") {
		return nil, a.ErrUnauthorized
	}
	before, err := s.Ready()
	if err != nil {
		return nil, err
	}
	digest, err := s.owner.authority.CompatibilityStateDigest()
	if err != nil {
		return nil, err
	}
	result := "registry-state"
	if kind == "legacy-connection" {
		if err = s.owner.rejectLegacyConnection(); err != nil {
			return nil, err
		}
		result = "legacy-tls-header-rejected"
	}
	after, err := s.Ready()
	if err != nil {
		return nil, err
	}
	final, err := s.owner.authority.CompatibilityStateDigest()
	if err != nil {
		return nil, err
	}
	if digest != final || before.Store != after.Store || before.ServiceEpoch != after.ServiceEpoch || before.Controller != after.Controller || before.Revision != after.Revision || before.Bootstrap != after.Bootstrap || before.ServerKey != after.ServerKey || !bytes.Equal(before.TLSRootDER, after.TLSRootDER) || !bytes.Equal(before.ServerDER, after.ServerDER) {
		return nil, a.ErrConflict
	}
	return &IsolationProof{CaseName: kind, Store: string(before.Store.ID), ServiceEpoch: string(before.ServiceEpoch), Revision: before.Revision, RegistrySHA256: digest, Result: result}, nil
}

// BindCompatibilityDataListener receives the actual bound DATA listener, not a
// probe-selected destination. The owner retains no address in ordinary profiles.
func (s *LifecycleService) BindCompatibilityDataListener(address net.Addr) error {
	if !s.valid() {
		return ErrConfiguration
	}
	return s.owner.BindCompatibilityDataListener(address)
}

// ServeDataConnection uses the owner's real DATA TLS handler and publishes probe
// completion only after that handler has joined and the accepted stream closed.
func (s *LifecycleService) ServeDataConnection(ctx context.Context, raw net.Conn) error {
	if !s.valid() || raw == nil {
		if raw != nil {
			raw.Close()
		}
		return ErrConfiguration
	}
	return s.owner.ServeDataConnection(ctx, raw)
}
