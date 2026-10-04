package storageserver

import (
	"crypto/tls"
	"encoding/hex"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// PKIConfig accepts typed values only: no external pools, hooks, or TLS configs.
// Authority still verifies the full binding and pinned key against its registry.
type PKIConfig struct {
	Identity          p.Identity
	ClientRoot        p.Root
	Store             a.ID
	ServiceEpoch      a.ID
	Limits            Limits
	RequestRetirement func(a.DataHello, error)
}

func NewPKIWithResources(r *Resources, authority *a.Authority, c PKIConfig) (*Server, error) {
	if authority == nil {
		return nil, ErrConfiguration
	}
	meta, err := authority.StartupMetadata()
	if err != nil || meta.Store.ID != c.Store || meta.Epoch != c.ServiceEpoch {
		return nil, ErrConfiguration
	}
	binding, err := p.NewServerBinding(p.StoreID(c.Store), p.ServiceEpoch(c.ServiceEpoch))
	if err != nil || c.Identity.Certificate().Binding() != binding {
		return nil, ErrConfiguration
	}
	// This config is born private from immutable typed credentials. Do not strip
	// callbacks/pools from a caller config to sneak it through snapshotTLS.
	tlsConfig, err := p.ServerTLSConfig(c.Identity, c.ClientRoot)
	if err != nil {
		return nil, ErrConfiguration
	}
	s, err := newOwned(r, Config{Limits: c.Limits, RequestRetirement: c.RequestRetirement}, tlsConfig)
	if err != nil {
		return nil, err
	}
	s.authority, s.pki = authority, &c
	return s, nil
}

// AttachmentBinding maps the complete public authority tuple to its exact URI.
// It grants no authority and deliberately omits no role/mode/incarnation fields.
func AttachmentBinding(h a.DataHello) (p.Binding, error) {
	b := h.Binding
	return p.NewAttachmentBinding(p.StoreID(b.Store), p.ServiceEpoch(h.Epoch), p.AttachmentTuple{Attachment: p.AttachmentID(b.Attachment), Volume: p.VolumeID(b.Volume), Role: p.Role(b.Role), Mode: p.Mode(b.Mode), Container: p.ContainerID(b.Container), Launch: p.LaunchID(b.Launch), Prepare: p.PrepareID(b.Prepare)})
}

func (c PKIConfig) verifyPeer(state tls.ConnectionState, h a.DataHello) error {
	if h.Binding.Store != c.Store || h.Epoch != c.ServiceEpoch {
		return a.ErrUnauthorized
	}
	binding, err := AttachmentBinding(h)
	if err != nil {
		return a.ErrUnauthorized
	}
	bytes, err := hex.DecodeString(string(h.Binding.Key))
	if err != nil || len(bytes) != 32 || hex.EncodeToString(bytes) != string(h.Binding.Key) {
		return a.ErrUnauthorized
	}
	var pin p.Fingerprint
	copy(pin[:], bytes)
	if p.VerifyAttachment(state, c.ClientRoot, binding, pin) != nil {
		return a.ErrUnauthorized
	}
	return nil
}
