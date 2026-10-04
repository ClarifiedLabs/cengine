package storagepki

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

func (r Root) pool() (*x509.CertPool, error) {
	if _, err := ParseRootDER(r.DER()); err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(r.DER())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return pool, nil
}
func (i Identity) tlsCertificate() (tls.Certificate, error) {
	if _, err := i.cert.WithKey(i.key); err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(i.cert.DER())
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{i.cert.DER()}, PrivateKey: i.key.private(), Leaf: leaf}, nil
}

// ServerTLSConfig returns a fresh static TLS config compatible with storageserver's
// callback-free snapshot policy. The caller MUST VerifyController/VerifyAttachment
// after handshake and before authority authentication/admission. TLS alone cannot
// distinguish controller and attachment certificates (both use clientAuth).
func ServerTLSConfig(identity Identity, clientRoot Root) (*tls.Config, error) {
	if identity.cert.binding.role != ServerRole {
		return nil, ErrInvalid
	}
	cert, err := identity.tlsCertificate()
	if err != nil {
		return nil, err
	}
	pool, err := clientRoot.pool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, SessionTicketsDisabled: true}, nil
}

// ClientTLSConfig returns an attachment config using normal chain/hostname/EKU/time
// verification AND a fixed expected server binding/SPKI pin. Controller identities
// are rejected: their credentials must remain inside NewControllerTLSClient.
// No callback, clock, or signer is accepted from the caller.
func ClientTLSConfig(identity Identity, serverRoot Root, server Binding, pin Fingerprint) (*tls.Config, error) {
	if identity.cert.binding.role != PrepareRole && identity.cert.binding.role != RuntimeRole {
		return nil, ErrInvalid
	}
	return clientTLSConfig(identity, serverRoot, server, pin)
}

// NewControllerTLSClient wraps a raw transport without exposing the controller's
// TLS config, private key, or signer. The caller performs the handshake and owns
// connection teardown; raw remains the caller's responsibility on error. Normal
// TLS verification and the immutable server binding/SPKI pin are mandatory.
func NewControllerTLSClient(raw net.Conn, identity Identity, serverRoot Root, server Binding, pin Fingerprint) (*tls.Conn, error) {
	if raw == nil || identity.cert.binding.role != ControllerRole {
		return nil, ErrInvalid
	}
	if _, ok := raw.(*tls.Conn); ok {
		return nil, ErrInvalid
	}
	cfg, err := clientTLSConfig(identity, serverRoot, server, pin)
	if err != nil {
		return nil, err
	}
	return tls.Client(raw, cfg), nil
}

// The credential-bearing config never leaves this package for controller roles.
func clientTLSConfig(identity Identity, serverRoot Root, server Binding, pin Fingerprint) (*tls.Config, error) {
	if identity.cert.binding.role == ServerRole || server.role != ServerRole || pin == (Fingerprint{}) {
		return nil, ErrInvalid
	}
	cert, err := identity.tlsCertificate()
	if err != nil {
		return nil, err
	}
	pool, err := serverRoot.pool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: ServerName, SessionTicketsDisabled: true, VerifyConnection: func(s tls.ConnectionState) error { return verify(s, serverRoot, server, pin, false) }}, nil
}

// Verify* require a completed, non-resumed TLS 1.3 handshake and normal verified
// chains. They recheck chain, real current time, exact EKU/SAN and SPKI against the
// independently expected immutable binding. They do NOT create an authority
// principal. Call only with ConnectionState from the actual authenticated conn.
func VerifyServer(s tls.ConnectionState, root Root, expected Binding, pin Fingerprint) error {
	if expected.role != ServerRole {
		return ErrInvalid
	}
	return verify(s, root, expected, pin, true)
}
func VerifyController(s tls.ConnectionState, root Root, expected Binding, pin Fingerprint) error {
	if expected.role != ControllerRole {
		return ErrInvalid
	}
	return verify(s, root, expected, pin, true)
}
func VerifyAttachment(s tls.ConnectionState, root Root, expected Binding, pin Fingerprint) error {
	if expected.role != PrepareRole && expected.role != RuntimeRole {
		return ErrInvalid
	}
	return verify(s, root, expected, pin, true)
}

// crypto/tls invokes VerifyConnection before setting HandshakeComplete. Only the
// package-owned client callback may skip that one check; public utilities cannot.
func verify(s tls.ConnectionState, root Root, b Binding, pin Fingerprint, completed bool) error {
	if (completed && !s.HandshakeComplete) || s.Version != tls.VersionTLS13 || s.DidResume || len(s.PeerCertificates) != 1 || s.PeerCertificates[0] == nil || len(s.VerifiedChains) == 0 || pin == (Fingerprint{}) {
		return ErrInvalid
	}
	// Reparse raw DER rather than trust mutable parsed certificate fields.
	leaf, err := x509.ParseCertificate(append([]byte(nil), s.PeerCertificates[0].Raw...))
	if err != nil || leafProfile(leaf, b) != nil {
		return ErrInvalid
	}
	matched := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(leaf) {
			matched = true
		}
	}
	if !matched {
		return ErrInvalid
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(sum[:], pin[:]) != 1 {
		return ErrInvalid
	}
	pool, err := root.pool()
	if err != nil {
		return err
	}
	eku := x509.ExtKeyUsageClientAuth
	dns := ""
	if b.role == ServerRole {
		eku = x509.ExtKeyUsageServerAuth
		dns = ServerName
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now(), DNSName: dns, KeyUsages: []x509.ExtKeyUsage{eku}})
	return err
}
