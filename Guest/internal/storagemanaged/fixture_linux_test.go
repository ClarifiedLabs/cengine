//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	"dev.cengine/guest/internal/storageidentity"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

type fixture struct {
	t                 *testing.T
	authority         *a.Authority
	lifecycle         *at.Fixture
	control           *a.ControllerPrincipal
	registry          *Registry
	gate              *sync.Mutex
	worker            *storageidentity.Worker
	root, volume      *os.File
	path              string
	storeID, volumeID a.ID
	ca                *x509.Certificate
	caKey             ed25519.PrivateKey
	pool              *x509.CertPool
	server            tls.Certificate
	sequence          map[*Session]uint64
	expectFaults      bool              // deliberate terminal-volume tests only
	bootstrap         ed25519.PublicKey // public restart-test configuration
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func newID(t *testing.T) a.ID { t.Helper(); id, err := a.NewID(); must(t, err); return id }
func key(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	return k
}
func fingerprint(t *testing.T, k ed25519.PrivateKey) a.Fingerprint {
	f, err := a.PublicKeyFingerprint(k.Public())
	must(t, err)
	return f
}
func newFixture(t *testing.T) *fixture { return newFixtureAt(t, t.TempDir()) }
func newFixtureAt(t *testing.T, path string, physicalDevice ...string) *fixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root with storageidentity setup capabilities")
	}
	f := &fixture{t: t, gate: new(sync.Mutex), worker: new(storageidentity.Worker), sequence: make(map[*Session]uint64)}
	f.path = path
	must(t, os.Chmod(f.path, 0755))
	var fs unix.Statfs_t
	must(t, unix.Statfs(f.path, &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatalf("TMPDIR must be on ext4, got %#x", fs.Type)
	}
	must(t, os.Mkdir(filepath.Join(f.path, "volumes"), 0755))
	must(t, os.Mkdir(filepath.Join(f.path, "volumes", "data"), 0777))
	must(t, os.Chmod(filepath.Join(f.path, "volumes", "data"), 0777))
	var err error
	f.root, err = os.Open(f.path)
	must(t, err)
	f.volume, err = os.Open(filepath.Join(f.path, "volumes", "data"))
	must(t, err)
	t.Cleanup(func() { f.volume.Close(); f.root.Close() })
	f.registry, err = NewRegistry(f.gate)
	must(t, err)
	f.caKey = key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, f.caKey.Public(), f.caKey)
	must(t, err)
	f.ca, err = x509.ParseCertificate(der)
	must(t, err)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.ca)
	f.server = f.cert(key(t))
	controller := key(t)
	bootstrap := key(t)
	f.bootstrap = bootstrap.Public().(ed25519.PublicKey)
	f.storeID = newID(t)
	device := "isolated-ext4-test"
	if len(physicalDevice) == 1 {
		device = physicalDevice[0]
	}
	f.lifecycle = at.New(t, bootstrap, f.storeID, fingerprint(t, controller))
	f.authority, err = f.lifecycle.Initialize(a.Config{Root: f.root, DeviceID: device, BootstrapKey: bootstrap.Public().(ed25519.PublicKey), Barrier: f.registry.Barrier})
	must(t, err)
	t.Cleanup(func() {
		err := f.authority.Close()
		if !f.expectFaults {
			must(t, err)
		}
	})
	f.control, err = f.authority.AuthenticateController(context.Background(), f.conn(controller), 1)
	must(t, err)
	st, err := stat(int(f.volume.Fd()))
	must(t, err)
	f.volumeID = newID(t)
	must(t, f.authority.AddVolume(f.control, a.VolumeRequest{Operation: newID(t), Volume: a.Volume{ID: f.volumeID, Name: "data", Root: a.RootIdentity{Device: st.Dev, Inode: st.Ino}}}))
	return f
}
func (f *fixture) cert(k ed25519.PrivateKey) tls.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	must(f.t, err)
	c := &x509.Certificate{SerialNumber: serial, DNSNames: []string{"storage.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, f.ca, k.Public(), f.caKey)
	must(f.t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
func (f *fixture) conn(k ed25519.PrivateKey) *tls.Conn {
	l, r := net.Pipe()
	f.t.Cleanup(func() { l.Close(); r.Close() })
	server := tls.Server(l, &tls.Config{Certificates: []tls.Certificate{f.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.pool, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	client := tls.Client(r, &tls.Config{Certificates: []tls.Certificate{f.cert(k)}, RootCAs: f.pool, ServerName: "storage.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.HandshakeContext(ctx) }()
	must(f.t, server.HandshakeContext(ctx))
	must(f.t, <-done)
	return server
}
func (f *fixture) principal(mode a.Mode) (a.Binding, *a.DataPrincipal) {
	k := key(f.t)
	b := a.Binding{Store: f.storeID, Volume: f.volumeID, Attachment: newID(f.t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: newID(f.t), Key: fingerprint(f.t, k), Role: a.RuntimeRole, Mode: mode}
	must(f.t, f.authority.RegisterAttachment(f.control, a.RegisterRequest{Operation: newID(f.t), Binding: b}))
	p, err := f.authority.AuthenticateData(context.Background(), f.conn(k), a.DataHello{Epoch: f.authority.Epoch(), Binding: b})
	must(f.t, err)
	return b, p
}
func (f *fixture) session(mode a.Mode) (*Session, w.Entry) {
	b, p := f.principal(mode)
	g, err := f.authority.Admit(p, b.Volume, false)
	must(f.t, err)
	defer g.Release()
	s, entry, err := New(g, p, b, f.gate, f.worker, f.registry)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		if !s.closed {
			if f.expectFaults {
				// Tests have already joined every guard. Authority quarantine can
				// reject another retirement; still release test-owned resources.
				_ = f.registry.Barrier(s.binding, f.volume)
				return
			}
			_, err := f.authority.Retire(context.Background(), f.control, a.RetireRequest{Operation: newID(f.t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
			must(f.t, err)
		}
	})
	return s, entry
}
func caller(uid, gid uint32, groups ...uint32) w.Auth {
	if groups == nil {
		groups = []uint32{}
	}
	return w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{FSUID: uid, FSGID: gid, Groups: groups}}
}
func (f *fixture) dispatch(s *Session, auth w.Auth, body w.RequestBody) Result {
	f.t.Helper()
	f.sequence[s]++
	r := w.Request{Sequence: f.sequence[s], Auth: auth, Body: body}
	g, err := f.authority.Admit(s.principal, s.binding.Volume, r.Mutates())
	must(f.t, err)
	defer g.Release()
	result, err := s.Dispatch(g, r)
	must(f.t, err)
	must(f.t, w.ValidateReplyFor(r, result.Reply))
	return result
}
func (f *fixture) call(s *Session, auth w.Auth, body w.RequestBody) w.ReplyBody {
	f.t.Helper()
	r := f.dispatch(s, auth, body)
	if r.Reply.Errno != 0 {
		f.t.Fatalf("%s errno=%d", body.Operation(), r.Reply.Errno)
	}
	return r.Reply.Body
}
func (f *fixture) wantError(s *Session, auth w.Auth, body w.RequestBody, want unix.Errno) {
	f.t.Helper()
	r := f.dispatch(s, auth, body)
	if r.Reply.Errno != uint32(want) {
		f.t.Fatalf("%s errno=%d want %d", body.Operation(), r.Reply.Errno, want)
	}
}
