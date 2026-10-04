package storageservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"net"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

// Mirrors storagecontrol's closed bounds until that package exports preflight.
// Keep policy parity: neither partial defaults nor oversized values are accepted.
func controlLimits(l c.Limits) (c.Limits, error) {
	if l == (c.Limits{}) {
		l = c.DefaultLimits()
	}
	if l.Connections < 1 || l.Connections > 32 || l.RequestBytes < 1024 || l.RequestBytes > 2<<20 || l.ResponseBytes < 1024 || l.ResponseBytes > 64<<20 || l.HandshakeTimeout <= 0 || l.ReadTimeout <= 0 || l.WriteTimeout <= 0 || l.OperationTimeout <= 0 {
		return l, c.ErrConfiguration
	}
	return l, nil
}

func pin(value a.Fingerprint) (p.Fingerprint, error) {
	var result p.Fingerprint
	b, err := hex.DecodeString(string(value))
	if err != nil || len(b) != len(result) || hex.EncodeToString(b) != string(value) {
		return result, ErrConfiguration
	}
	copy(result[:], b)
	return result, nil
}
func certificatePin(cert p.Certificate) (p.Fingerprint, error) {
	leaf, err := x509.ParseCertificate(cert.DER())
	if err != nil {
		return p.Fingerprint{}, err
	}
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return p.Fingerprint{}, ErrConfiguration
	}
	return p.PublicKeyFingerprint(key)
}

// CSR possession alone never chooses its own authorized key. Enforce the key
// before issuance; Issuer then verifies canonical CSR signature/URI/attributes.
func csrPin(csr []byte, expected a.Fingerprint) error {
	if len(csr) == 0 || len(csr) > p.MaxDERSize {
		return ErrConfiguration
	}
	req, err := x509.ParseCertificateRequest(bytes.Clone(csr))
	if err != nil || req.CheckSignature() != nil {
		return ErrConfiguration
	}
	key, ok := req.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ErrConfiguration
	}
	actual, err := p.PublicKeyFingerprint(key)
	if err != nil || a.Fingerprint(actual.String()) != expected {
		return a.ErrUnauthorized
	}
	return nil
}

// IssueController issues only for the exact CURRENT persisted S/C/key. It is
// public CSR delivery, not control authorization, and does not advance C.
func (s *commonService) IssueController(csr []byte) (p.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return p.Certificate{}, a.ErrClosed
	}
	meta, err := s.authority.StartupMetadata()
	if err != nil {
		return p.Certificate{}, err
	}
	if err = csrPin(csr, meta.Controller.Key); err != nil {
		return p.Certificate{}, err
	}
	binding, err := p.NewControllerBinding(p.StoreID(meta.Store.ID), p.ControllerEpoch(meta.Controller.Epoch))
	if err != nil {
		return p.Certificate{}, err
	}
	return s.issuer.IssueController(csr, binding, s.config.Now, s.config.Lifetime)
}

// begin bounds all control generations AND credential connections together.
func (s *commonService) begin(raw net.Conn, control bool) (func(), error) {
	if raw == nil {
		return nil, ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		raw.Close()
		return nil, a.ErrClosed
	}
	limit := s.config.ControlLimits.Connections
	if control {
		if s.controlActive >= limit {
			raw.Close()
			return nil, c.ErrLimit
		}
		s.controlActive++
	} else {
		if s.dataActive >= s.config.DataLimits.Connections {
			raw.Close()
			return nil, d.ErrOverload
		}
		s.dataActive++
	}
	s.transportStarted = true
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if control {
			s.controlActive--
		} else {
			s.dataActive--
		}
	}, nil
}
func (s *commonService) ServeControl(ctx context.Context, raw net.Conn) error {
	done, err := s.begin(raw, true)
	if err != nil {
		return err
	}
	defer done()
	// Generation cannot be replaced while this worker owns its active count.
	return s.control.Serve(ctx, raw)
}
func (s *commonService) ServeData(ctx context.Context, raw net.Conn) (err error) {
	ctx = s.consumer.Context(ctx)
	defer func() { s.consumer.Finish(ctx, err) }()
	done, err := s.begin(raw, false)
	if err != nil {
		return err
	}
	defer done()
	return s.data.Serve(ctx, s.authority, raw)
}
