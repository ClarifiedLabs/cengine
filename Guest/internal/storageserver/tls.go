package storageserver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
)

// Build from an allowlisted static configuration rather than retaining arbitrary
// callbacks or hidden state from tls.Config.Clone. No external signer is retained.
// DER is the sole trust input: CertPool.Equal ignores AddCertWithConstraint hooks,
// and neither Equal nor Clone can establish independently owned static trust.
func snapshotTLS(c *tls.Config, roots [][]byte) (*tls.Config, error) {
	if c == nil || c.MinVersion != tls.VersionTLS13 || c.MaxVersion != tls.VersionTLS13 || c.ClientAuth != tls.RequireAndVerifyClientCert || c.ClientCAs != nil || c.RootCAs != nil || len(roots) == 0 || !c.SessionTicketsDisabled || c.ClientSessionCache != nil || c.GetConfigForClient != nil || c.GetCertificate != nil || c.GetClientCertificate != nil || c.VerifyPeerCertificate != nil || c.VerifyConnection != nil || c.UnwrapSession != nil || c.WrapSession != nil || c.InsecureSkipVerify || c.Rand != nil || c.Time != nil || c.KeyLogWriter != nil || c.NameToCertificate != nil || c.Renegotiation != tls.RenegotiateNever || len(c.Certificates) == 0 || len(c.EncryptedClientHelloConfigList) != 0 || c.EncryptedClientHelloRejectionVerify != nil || c.GetEncryptedClientHelloKeys != nil || len(c.EncryptedClientHelloKeys) != 0 {
		return nil, ErrConfiguration
	}
	pool := x509.NewCertPool()
	for _, der := range roots {
		root, err := x509.ParseCertificate(bytes.Clone(der))
		if err != nil {
			return nil, fmt.Errorf("%w: client root: %v", ErrConfiguration, err)
		}
		pool.AddCert(root)
	}
	owned := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, SessionTicketsDisabled: true, NextProtos: slices.Clone(c.NextProtos), CurvePreferences: slices.Clone(c.CurvePreferences), DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled}
	for _, cert := range c.Certificates {
		clone, err := snapshotCertificate(cert)
		if err != nil {
			return nil, err
		}
		owned.Certificates = append(owned.Certificates, clone)
	}
	return owned, nil
}

func snapshotCertificate(cert tls.Certificate) (tls.Certificate, error) {
	var out tls.Certificate
	if len(cert.Certificate) == 0 {
		return out, ErrConfiguration
	}
	// Do not call arbitrary crypto.Signer implementations, even during cloning.
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.D == nil || len(key.Primes) < 2 {
			return out, ErrConfiguration
		}
		for _, prime := range key.Primes {
			if prime == nil {
				return out, ErrConfiguration
			}
		}
		if err := key.Validate(); err != nil {
			return out, fmt.Errorf("%w: RSA key: %v", ErrConfiguration, err)
		}
	case *ecdsa.PrivateKey:
		if key == nil || key.D == nil || key.X == nil || key.Y == nil {
			return out, ErrConfiguration
		}
		// An arbitrary elliptic.Curve is external executable state too.
		switch key.Curve {
		case elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return out, ErrConfiguration
		}
		if key.D.Sign() <= 0 || key.D.Cmp(key.Params().N) >= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
			return out, ErrConfiguration
		}
		x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
		if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
			return out, ErrConfiguration
		}
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return out, ErrConfiguration
		}
	default:
		return out, fmt.Errorf("%w: unsupported private key", ErrConfiguration)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return out, fmt.Errorf("%w: private key: %v", ErrConfiguration, err)
	}
	out.PrivateKey, err = x509.ParsePKCS8PrivateKey(encoded)
	clear(encoded)
	if err != nil {
		return out, fmt.Errorf("%w: private key: %v", ErrConfiguration, err)
	}
	out.Certificate = cloneBytes(cert.Certificate)
	for i, der := range out.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return out, fmt.Errorf("%w: certificate: %v", ErrConfiguration, err)
		}
		if i == 0 {
			out.Leaf = parsed
		}
	}
	public, err := x509.MarshalPKIXPublicKey(out.PrivateKey.(crypto.Signer).Public())
	if err != nil || !bytes.Equal(public, out.Leaf.RawSubjectPublicKeyInfo) {
		return out, fmt.Errorf("%w: certificate key mismatch", ErrConfiguration)
	}
	out.SupportedSignatureAlgorithms = slices.Clone(cert.SupportedSignatureAlgorithms)
	out.OCSPStaple = bytes.Clone(cert.OCSPStaple)
	out.SignedCertificateTimestamps = cloneBytes(cert.SignedCertificateTimestamps)
	return out, nil
}
func cloneBytes(values [][]byte) [][]byte {
	out := make([][]byte, len(values))
	for i := range values {
		out[i] = bytes.Clone(values[i])
	}
	return out
}
