package storageserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	p "dev.cengine/guest/internal/storagepki"
	w "dev.cengine/guest/internal/storagewire"
)

// This fixture uses real PKI constructors, real authority initialization, and
// Server.Serve; it does not install principals, auth callbacks, or executors.
func tlsFailureFixture(t *testing.T, stale bool) (*Server, *a.Authority, *tls.Config, []byte) {
	t.Helper()
	r, err := NewResources()
	must(t, err)
	path := t.TempDir()
	must(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	must(t, err)
	t.Cleanup(func() { root.Close() })
	bootstrapPrivate := key(t)
	bootstrapKey := bootstrapPrivate.Public().(ed25519.PublicKey)
	authority, err := at.New(t, bootstrapPrivate, id(t), fingerprint(t, key(t))).Initialize(a.Config{Root: root, DeviceID: "tls-failure-test", BootstrapKey: bootstrapKey, Barrier: r.Barrier})
	must(t, err)
	t.Cleanup(func() { must(t, authority.Close()) })
	meta, err := authority.StartupMetadata()
	must(t, err)
	bootstrap, err := p.NewBootstrapPublicKey(bootstrapKey)
	must(t, err)
	now := time.Now().Add(-time.Minute)
	issuer, err := p.NewIssuer(now, time.Hour, bootstrap)
	must(t, err)
	serverBinding, err := p.NewServerBinding(p.StoreID(meta.Store.ID), p.ServiceEpoch(meta.Epoch))
	must(t, err)
	serverKey, err := p.NewServerKey()
	must(t, err)
	csr, err := serverKey.CSR(serverBinding)
	must(t, err)
	serverCert, err := issuer.IssueServer(csr, serverBinding, now, time.Hour)
	must(t, err)
	serverIdentity, err := serverCert.WithKey(serverKey)
	must(t, err)
	server, err := NewPKIWithResources(r, authority, PKIConfig{Identity: serverIdentity, ClientRoot: issuer.Root(), Store: meta.Store.ID, ServiceEpoch: meta.Epoch, RequestRetirement: func(a.DataHello, error) { t.Error("unauthenticated retirement") }})
	must(t, err)
	clientIssuer := issuer
	clientEpoch := meta.Epoch
	if stale {
		clientIssuer, err = p.NewIssuer(now, time.Hour, bootstrap)
		must(t, err)
		clientEpoch = id(t)
	}
	binding, err := p.NewAttachmentBinding(p.StoreID(meta.Store.ID), p.ServiceEpoch(clientEpoch), p.AttachmentTuple{Attachment: p.AttachmentID(id(t)), Volume: p.VolumeID(id(t)), Role: p.RuntimeRole, Mode: p.ReadWrite, Container: p.ContainerID(strings.Repeat("a", 64)), Launch: p.LaunchID(id(t))})
	must(t, err)
	clientKey, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	csr, err = clientKey.CSR(binding)
	must(t, err)
	clientCert, err := clientIssuer.IssueAttachment(csr, binding, now, time.Hour)
	must(t, err)
	clientIdentity, err := clientCert.WithKey(clientKey)
	must(t, err)
	pin, err := serverKey.Fingerprint()
	must(t, err)
	cfg, err := p.ClientTLSConfig(clientIdentity, issuer.Root(), serverBinding, pin)
	must(t, err)
	return server, authority, cfg, clientCert.DER()
}

type failureReadPeer struct {
	net.Conn
	limit  int
	prefix bytes.Buffer
}

func (c *failureReadPeer) Read(b []byte) (int, error) {
	if len(b) > c.limit {
		b = b[:c.limit]
	}
	n, err := c.Conn.Read(b)
	c.prefix.Write(b[:n])
	return n, err
}

type failureWritePeer struct {
	net.Conn
	written bytes.Buffer
}

func (c *failureWritePeer) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written.Write(b[:n])
	return n, err
}
func failureTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	must(t, err)
	server, err := listener.Accept()
	must(t, err)
	t.Cleanup(func() { client.Close(); server.Close() })
	must(t, client.SetDeadline(time.Now().Add(4*time.Second)))
	return server, client
}

func TestTLSFailureProductionServe(t *testing.T) {
	for _, limit := range []int{1, 17, 4096} {
		for _, optedIn := range []bool{false, true} {
			t.Run(fmt.Sprintf("read-%d/observed-%t", limit, optedIn), func(t *testing.T) {
				s, authority, cfg, leaf := tlsFailureFixture(t, true)
				raw, other := failureTCPPair(t)
				reader := &failureReadPeer{Conn: raw, limit: limit}
				writer := &failureWritePeer{Conn: other}
				client := tls.Client(writer, cfg)
				ctx := context.Background()
				if optedIn {
					ctx = WithTLSFailureObservation(ctx)
				}
				done := make(chan error, 1)
				go func() { done <- s.Serve(ctx, authority, reader) }()
				// TLS 1.3 client completion alone is not server acceptance.
				must(t, client.Handshake())
				var b [1]byte
				if n, err := client.Read(b[:]); n != 0 || err == nil {
					t.Fatalf("missing rejection: %d %v", n, err)
				}
				err := wait(t, done)
				var verification *tls.CertificateVerificationError
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &verification) || !errors.As(err, &unknown) || !bytes.Equal(unknown.Cert.Raw, leaf) {
					t.Fatalf("not actual old-leaf rejection: %T %v", err, err)
				}
				snapshot, ok := TLSFailureEvidence(err)
				if ok != (tlsFailureTestEnabled && optedIn) {
					t.Fatalf("unexpected evidence: %t", ok)
				}
				if !ok {
					return
				}
				prefix := reader.prefix.Bytes()
				written := writer.written.Bytes()
				if len(prefix) > len(written) || !bytes.Equal(prefix, written[:len(prefix)]) {
					t.Fatal("not actual client write prefix")
				}
				digest := sha256.Sum256(append([]byte(TLSFailurePrefixDomain), prefix...))
				if snapshot.Store != s.pki.Store || snapshot.ServiceEpoch != authority.Epoch() || snapshot.RejectedCertificateSHA256 != sha256.Sum256(leaf) || snapshot.ByteCount != uint64(len(prefix)) || snapshot.PrefixSHA256 != digest {
					t.Fatalf("incorrect snapshot: %+v", snapshot)
				}
				if limit == 1 && (len(prefix) >= len(written) || snapshot.PrefixSHA256 == sha256.Sum256(append([]byte(TLSFailurePrefixDomain), written...))) {
					t.Fatal("fragmented certificate rejection incorrectly claims full ClientFinished flight")
				}
				if !errors.Is(err, verification) {
					t.Fatal("lost original error identity")
				}
				if fmt.Sprintf("%#v", err) != err.Error() {
					t.Fatal("non-redacted error formatting")
				}
				snapshot.ByteCount = 0
				again, _ := TLSFailureEvidence(err)
				if again.ByteCount == 0 {
					t.Fatal("snapshot aliases internal evidence")
				}
				t.Logf("read limit=%d server prefix=%d client write=%d", limit, len(prefix), len(written))
			})
		}
	}
}

func TestTLSFailureSuccessfulHandshakeNoEvidence(t *testing.T) {
	s, authority, cfg, _ := tlsFailureFixture(t, false)
	raw, other := failureTCPPair(t)
	client := tls.Client(other, cfg)
	done := make(chan error, 1)
	go func() { done <- s.Serve(WithTLSFailureObservation(context.Background()), authority, raw) }()
	var hello w.ServerHello
	must(t, w.ReadFrame(client, &hello)) // real successful TLS, before authority Hello
	if hello.Epoch != authority.Epoch() {
		t.Fatal("wrong server epoch")
	}
	other.Close()
	if err := wait(t, done); err == nil {
		t.Fatal("expected closed transport")
	} else if _, ok := TLSFailureEvidence(err); ok {
		t.Fatal("successful TLS acquired failure evidence")
	}
}

func TestTLSFailureCallerErrorIsNotEvidence(t *testing.T) {
	for _, err := range []error{nil, errors.New("unknown authority"), &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}} {
		if _, ok := TLSFailureEvidence(err); ok {
			t.Fatal("caller minted evidence")
		}
	}
}
