//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"
)

type forgedTLSFailureTransport struct {
	net.Conn
	failure     error
	readFailure bool
}

func (c *forgedTLSFailureTransport) Read(b []byte) (int, error) {
	if c.readFailure {
		if len(b) != 0 {
			b[0] = 22
			return 1, c.failure
		}
		return 0, c.failure
	}
	return c.Conn.Read(b)
}
func (c *forgedTLSFailureTransport) Write(b []byte) (int, error) {
	if c.readFailure {
		return len(b), nil
	}
	return 0, c.failure
}

// Exercise Server.Serve, not just the accessor. crypto/tls can propagate errors
// from net.Conn verbatim; their Go type must not mint certificate-verification
// evidence when no actual certificate verification produced the error.
func TestTLSFailureTransportCannotMintEvidence(t *testing.T) {
	for _, fromRead := range []bool{true, false} {
		name := "write"
		if fromRead {
			name = "read"
		}
		t.Run(name, func(t *testing.T) {
			server, authority, config, der := tlsFailureFixture(t, false)
			leaf, err := x509.ParseCertificate(der)
			must(t, err)
			forged := &tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{leaf}, Err: x509.UnknownAuthorityError{Cert: leaf}}
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()
			raw := &forgedTLSFailureTransport{Conn: serverRaw, failure: forged, readFailure: fromRead}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			if !fromRead {
				go func() { defer clientRaw.Close(); done <- tls.Client(clientRaw, config).HandshakeContext(ctx) }()
			}
			err = server.Serve(WithTLSFailureObservation(ctx), authority, raw)
			if !errors.Is(err, forged) {
				t.Fatalf("transport failure was not preserved: %v", err)
			}
			if _, ok := TLSFailureEvidence(err); ok {
				t.Fatal("caller-supplied transport error minted evidence")
			}
			if !fromRead {
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("client handshake did not join")
				}
			}
		})
	}
}
