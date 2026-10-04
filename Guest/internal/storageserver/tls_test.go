package storageserver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

func TestTLSRejectsCallerCAPoolsBeforeMutation(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	var constraints atomic.Int32
	constrained := x509.NewCertPool()
	constrained.AddCertWithConstraint(f.ca, func([]*x509.Certificate) error {
		constraints.Add(1)
		return errors.New("reject this client chain")
	})
	if !constrained.Equal(f.pool) {
		t.Fatal("regression requires equal certificates despite different constraints")
	}
	// Prove that real TLS enforces the constraint that CertPool.Equal ignores.
	rawConfig := f.inputTLS.Clone()
	rawConfig.ClientCAs = constrained
	if err := testTLSHandshake(t, f, rawConfig); err == nil || constraints.Load() == 0 {
		t.Fatalf("constrained TLS accepted client: err=%v calls=%d", err, constraints.Load())
	}
	for name, pool := range map[string]*x509.CertPool{"empty": x509.NewCertPool(), "static": f.pool, "constrained": constrained} {
		for _, field := range []string{"ClientCAs", "RootCAs"} {
			t.Run(field+"/"+name, func(t *testing.T) {
				c := f.inputTLS.Clone()
				if field == "ClientCAs" {
					c.ClientCAs = pool
				} else {
					c.RootCAs = pool
				}
				clientPool, serverPool := c.ClientCAs, c.RootCAs
				roots := [][]byte{bytes.Clone(f.ca.Raw)}
				certBefore := bytes.Clone(c.Certificates[0].Certificate[0])
				keyBefore, err := x509.MarshalPKCS8PrivateKey(c.Certificates[0].PrivateKey)
				must(t, err)
				callsBefore := constraints.Load()
				var retirements atomic.Int32
				server, err := New(Config{TLSConfig: c, ClientRoots: roots, RequestRetirement: func(a.DataHello, error) { retirements.Add(1) }})
				if server != nil || !errors.Is(err, ErrConfiguration) {
					t.Fatalf("caller pool accepted: server=%v err=%v", server, err)
				}
				keyAfter, err := x509.MarshalPKCS8PrivateKey(c.Certificates[0].PrivateKey)
				must(t, err)
				if c.ClientCAs != clientPool || c.RootCAs != serverPool || !bytes.Equal(roots[0], f.ca.Raw) || !bytes.Equal(certBefore, c.Certificates[0].Certificate[0]) || !bytes.Equal(keyBefore, keyAfter) {
					t.Fatal("rejected configuration mutated caller trust or identity")
				}
				if constraints.Load() != callsBefore || retirements.Load() != 0 {
					t.Fatal("constructor invoked caller callbacks")
				}
			})
		}
	}
}

func TestTLSSafeDEROnlyRootsAreOwned(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	roots := [][]byte{bytes.Clone(f.ca.Raw)}
	server, err := New(Config{TLSConfig: f.inputTLS, ClientRoots: roots, RequestRetirement: func(a.DataHello, error) {}})
	must(t, err)
	if f.inputTLS.RootCAs != nil || f.inputTLS.ClientCAs != nil || server.config.ClientRoots != nil || server.config.TLSConfig.ClientCAs == f.pool {
		t.Fatal("constructor mutated config or retained caller root storage")
	}
	clear(roots[0])
	roots[0] = []byte("replacement caller root")
	// The source DER is gone, but both peers must still verify full TLS chains.
	must(t, testTLSHandshake(t, f, server.config.TLSConfig))
}

// Exercise crypto/tls on both ends, including server-side client chain checking.
// A TLS 1.3 client can finish its handshake before the server rejects its cert.
func testTLSHandshake(t *testing.T, f *fixture, config *tls.Config) error {
	t.Helper()
	raw, client := f.pair(key(t))
	return testTLSHandshakePeers(t, raw, client, config)
}

func testTLSHandshakePeers(t *testing.T, raw net.Conn, client *tls.Conn, config *tls.Config) error {
	t.Helper()
	defer client.NetConn().Close()
	server := tls.Server(raw, config)
	must(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	done := make(chan error, 1)
	go func() {
		err := server.Handshake()
		raw.Close()
		done <- err
	}()
	clientErr := client.Handshake()
	var peerErr error
	var received int
	if clientErr == nil {
		// Handshake completion is not server acceptance in TLS 1.3. Keep the
		// peer reading so the server can finish its synchronous rejection alert.
		// On success the server's owned raw close supplies EOF instead.
		var payload [1]byte
		received, peerErr = client.Read(payload[:])
	}
	// Close raw transport, not tls.Close (which could write another alert).
	// Also unblock the server if the client itself failed during the handshake.
	client.NetConn().Close()
	serverErr := wait(t, done) // join only after the peer read/close has completed
	if received != 0 {
		t.Fatal("unexpected application data in handshake-only fixture")
	}
	if serverErr == nil {
		must(t, clientErr)
		if peerErr != io.EOF {
			t.Fatalf("successful server did not close its peer: %v", peerErr)
		}
		for _, conn := range []*tls.Conn{server, client} {
			state := conn.ConnectionState()
			if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || state.DidResume {
				t.Fatal("TLS peer did not verify a fresh TLS 1.3 chain")
			}
		}
	} else if clientErr == nil {
		var remote *net.OpError
		if !errors.As(peerErr, &remote) || remote.Op != "remote error" {
			t.Fatalf("server rejection did not reach the TLS peer: %T: %v", peerErr, peerErr)
		}
	}
	return serverErr
}

// Observe the real encrypted alert's write result, without replacing TLS,
// buffering the pipe, changing deadlines, or timing how fast a test completes.
type tlsRejectionWriter struct {
	net.Conn
	rejected atomic.Bool
	count    atomic.Int32
	writes   chan error
}

func (c *tlsRejectionWriter) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if c.rejected.Load() {
		c.count.Add(1)
		select {
		case c.writes <- err:
		default: // An unexpected second write must fail, never block the worker.
		}
	}
	return n, err
}

func TestTLSHandshakeRejectionDeliversAlertBeforeJoin(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	raw, client := f.pair(key(t))
	observed := &tlsRejectionWriter{Conn: raw, writes: make(chan error, 1)}
	constrained := x509.NewCertPool()
	constrained.AddCertWithConstraint(f.ca, func([]*x509.Certificate) error {
		observed.rejected.Store(true)
		return errors.New("reject this client chain")
	})
	config := f.inputTLS.Clone()
	config.ClientCAs = constrained
	err := testTLSHandshakePeers(t, observed, client, config)
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &verification) || !errors.As(err, &unknown) {
		t.Fatalf("expected actual client-chain verification failure, got %T: %v", err, err)
	}
	if observed.count.Load() != 1 {
		t.Fatal("expected exactly one terminal rejection alert", observed.count.Load())
	}
	select {
	case writeErr := <-observed.writes:
		if writeErr != nil {
			t.Fatalf("rejection alert was not delivered before server join: %v", writeErr)
		}
	default:
		t.Fatal("server did not write the rejection alert")
	}
}

func TestCertificateSnapshotOwnsRSAECDSAAndChainMetadata(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	for _, kind := range []string{"rsa", "ecdsa"} {
		t.Run(kind, func(t *testing.T) {
			var signer crypto.Signer
			if kind == "rsa" {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				must(t, err)
				signer = key
			} else {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				must(t, err)
				signer = key
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"storage.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, f.ca, signer.Public(), f.caKey)
			must(t, err)
			source := tls.Certificate{Certificate: [][]byte{der, bytes.Clone(f.ca.Raw)}, PrivateKey: signer, Leaf: f.ca, OCSPStaple: []byte{1, 2}, SignedCertificateTimestamps: [][]byte{{3, 4}}, SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PSSWithSHA256}}
			expectedPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
			must(t, err)
			owned, err := snapshotCertificate(source)
			must(t, err)
			clear(source.Certificate[0])
			clear(source.Certificate[1])
			clear(source.OCSPStaple)
			clear(source.SignedCertificateTimestamps[0])
			clear(source.SupportedSignatureAlgorithms)
			switch key := signer.(type) {
			case *rsa.PrivateKey:
				key.N.SetInt64(1)
				key.D.SetInt64(1)
				key.Primes[0].SetInt64(1)
			case *ecdsa.PrivateKey:
				key.D.SetInt64(1)
				key.X.SetInt64(0)
				key.Y.SetInt64(0)
			}
			if !bytes.Equal(owned.Leaf.RawSubjectPublicKeyInfo, expectedPublic) {
				t.Fatal("leaf aliases source or trusts supplied Leaf")
			}
			if !bytes.Equal(owned.Certificate[1], f.ca.Raw) || !bytes.Equal(owned.OCSPStaple, []byte{1, 2}) || !bytes.Equal(owned.SignedCertificateTimestamps[0], []byte{3, 4}) || owned.SupportedSignatureAlgorithms[0] != tls.PSSWithSHA256 {
				t.Fatal("chain or metadata aliases source")
			}
			digest := sha256.Sum256([]byte("private signing state"))
			signature, err := owned.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
			must(t, err)
			if kind == "rsa" {
				must(t, rsa.VerifyPKCS1v15(owned.Leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
			} else if !ecdsa.VerifyASN1(owned.Leaf.PublicKey.(*ecdsa.PublicKey), digest[:], signature) {
				t.Fatal("ECDSA snapshot signature invalid")
			}
		})
	}
}

func TestCertificateSnapshotRejectsMalformedStandardKeysAndChains(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	for _, private := range []any{(*rsa.PrivateKey)(nil), &rsa.PrivateKey{}, (*ecdsa.PrivateKey)(nil), &ecdsa.PrivateKey{}, []byte("not a supported key")} {
		cert := f.cert(key(t))
		cert.PrivateKey = private
		if _, err := snapshotCertificate(cert); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("%T: %v", private, err)
		}
	}
	cert := f.cert(key(t))
	cert.Certificate = append(cert.Certificate, []byte("not a certificate"))
	if _, err := snapshotCertificate(cert); !errors.Is(err, ErrConfiguration) {
		t.Fatal(err)
	}
}
