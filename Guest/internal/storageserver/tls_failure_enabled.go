//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	a "dev.cengine/guest/internal/storageauthority"
	"errors"
	"hash"
	"net"
	"sync/atomic"
)

const tlsFailurePrefixLimit = 128 << 10

type tlsFailureObservationKey struct{}

// WithTLSFailureObservation requests local, bounded handshake observation for
// Serve calls using this context. It does not install a collector or callback,
// alter TLS/authentication, or arm a consumer probe. Only full-compat builds act
// on the request; ordinary builds return ctx unchanged. Owners must retain the
// returned Serve error themselves. No background or process-wide recording runs.
func WithTLSFailureObservation(ctx context.Context) context.Context {
	return context.WithValue(ctx, tlsFailureObservationKey{}, true)
}

type tlsFailureReadObserver struct {
	net.Conn
	digest          hash.Hash
	count           uint64
	snapshot        TLSFailureSnapshot
	transportFailed atomic.Bool
}

func (s *Server) observeTLSFailure(ctx context.Context, raw net.Conn) (net.Conn, *tlsFailureReadObserver) {
	if enabled, _ := ctx.Value(tlsFailureObservationKey{}).(bool); !enabled || s.pki == nil {
		return raw, nil
	}
	o := &tlsFailureReadObserver{Conn: raw, digest: sha256.New(), snapshot: TLSFailureSnapshot{Store: s.pki.Store, ServiceEpoch: s.pki.ServiceEpoch}}
	_, _ = o.digest.Write([]byte(TLSFailurePrefixDomain))
	return o, o
}

// TLS owns reads serially. Close and deadlines remain the underlying Conn's
// methods and never touch observation state. Read receives the original slice,
// returns the exact original n/error, and hashes even bytes accompanied by error.
func (o *tlsFailureReadObserver) Read(b []byte) (int, error) {
	n, err := o.Conn.Read(b)
	if err != nil {
		o.transportFailed.Store(true)
	}
	if o.digest != nil {
		if n < 0 || n > len(b) || uint64(n) > tlsFailurePrefixLimit-o.count {
			o.stop() // overflow/ambiguity discards evidence, not the TLS failure
		} else {
			_, _ = o.digest.Write(b[:n])
			o.count += uint64(n)
		}
	}
	return n, err
}

// A transport can return caller-constructed TLS-shaped errors. Such an error
// must never become proof that crypto/tls actually rejected a certificate.
func (o *tlsFailureReadObserver) Write(b []byte) (int, error) {
	n, err := o.Conn.Write(b)
	if err != nil {
		o.transportFailed.Store(true)
	}
	return n, err
}

func (o *tlsFailureReadObserver) stop() {
	if o != nil {
		o.digest = nil
	}
}

func (o *tlsFailureReadObserver) failure(err error) error {
	if o == nil || o.digest == nil {
		return err
	}
	defer o.stop()
	if o.transportFailed.Load() {
		return err
	}
	verification, ok := err.(*tls.CertificateVerificationError)
	var unknown x509.UnknownAuthorityError
	if !ok || !errors.As(verification.Err, &unknown) || len(verification.UnverifiedCertificates) != 1 || verification.UnverifiedCertificates[0] == nil || unknown.Cert == nil || o.count == 0 {
		return err
	}
	leaf := verification.UnverifiedCertificates[0]
	// The production PKI is a direct-root single-leaf profile. Refuse ambiguous
	// chain errors, rather than attributing an intermediate failure to a leaf.
	if len(leaf.Raw) == 0 || !bytes.Equal(leaf.Raw, unknown.Cert.Raw) {
		return err
	}
	snapshot := o.snapshot
	snapshot.RejectedCertificateSHA256 = sha256.Sum256(leaf.Raw)
	snapshot.ByteCount = o.count
	copy(snapshot.PrefixSHA256[:], o.digest.Sum(nil))
	return &tlsFailureError{cause: err, snapshot: snapshot}
}

// Called only after crypto/tls verified the actual client CertificateVerify and
// PKIConfig.verifyPeer rejected the decoded Hello, before AuthenticateData.
func (o *tlsFailureReadObserver) peerFailure(state tls.ConnectionState, h a.DataHello, err error) error {
	if o == nil || o.digest == nil || o.transportFailed.Load() || o.count == 0 || err != a.ErrUnauthorized || !state.HandshakeComplete || state.DidResume || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) != 1 {
		return err
	}
	defer o.stop()
	snapshot := o.snapshot
	snapshot.RejectedCertificateSHA256 = sha256.Sum256(state.PeerCertificates[0].Raw)
	snapshot.ByteCount = o.count
	copy(snapshot.PrefixSHA256[:], o.digest.Sum(nil))
	return &helloFailureError{cause: err, snapshot: snapshot, hello: h}
}
