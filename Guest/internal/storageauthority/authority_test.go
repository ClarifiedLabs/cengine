package storageauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func mustID(t *testing.T) ID {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustContainerID(t *testing.T) ContainerID {
	t.Helper()
	var bytes [32]byte
	_, err := rand.Read(bytes[:])
	must(t, err)
	return ContainerID(hex.EncodeToString(bytes[:]))
}
func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func fp(t *testing.T, k ed25519.PrivateKey) Fingerprint {
	t.Helper()
	p, err := PublicKeyFingerprint(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v; want %v", err, want)
	}
}

type fixture struct {
	a                               *Authority
	c                               Config
	control                         *ControllerPrincipal
	controllerKey, bootstrap, caKey ed25519.PrivateKey
	ca                              *x509.Certificate
	server                          tls.Certificate
	pool                            *x509.CertPool
	path                            string
	t                               *testing.T
}

func newFixture(t *testing.T, barrier Barrier) *fixture {
	t.Helper()
	return newFixtureAt(t, barrier, t.TempDir())
}
func newFixtureAt(t *testing.T, barrier Barrier, path string) *fixture {
	t.Helper()
	f := newFixtureBase(t, barrier, path)
	var err error
	g := LifecycleGrant{LifecycleInitialize, mustID(t), LifecycleIdentity{mustID(t), 7, fp(t, newKey(t))}, 11, 0, fp(t, f.controllerKey)}
	f.a, err = InitializeLifecycle(f.c, signLifecycle(t, f.bootstrap, g))
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	return f
}
func newFixtureBase(t *testing.T, barrier Barrier, path string) *fixture {
	t.Helper()
	f := &fixture{t: t, path: path}
	must(t, os.Mkdir(filepath.Join(f.path, "volumes"), 0700))
	root, err := os.Open(f.path)
	must(t, err)
	t.Cleanup(func() { root.Close() })
	f.bootstrap = newKey(t)
	f.controllerKey = newKey(t)
	f.caKey = newKey(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, f.caKey.Public(), f.caKey)
	must(t, err)
	f.ca, err = x509.ParseCertificate(der)
	must(t, err)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.ca)
	f.server = f.cert(newKey(t))
	if barrier == nil {
		barrier = func(Binding, *os.File) error { return nil }
	}
	f.c = Config{Root: root, DeviceID: "test-device-uuid", BootstrapKey: f.bootstrap.Public().(ed25519.PublicKey), Barrier: barrier}
	t.Cleanup(func() {
		if f.a == nil {
			return
		}
		if err := f.a.Close(); err != nil {
			t.Errorf("close authority: %v", err)
		}
	})
	return f
}
func (f *fixture) cert(key ed25519.PrivateKey) tls.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	must(f.t, err)
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test peer"}, DNSNames: []string{"storage.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, f.ca, key.Public(), f.caKey)
	must(f.t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func (f *fixture) conn(key ed25519.PrivateKey, version uint16, verified bool) *tls.Conn {
	left, right := net.Pipe()
	f.t.Cleanup(func() { left.Close(); right.Close() })
	serverConfig := &tls.Config{Certificates: []tls.Certificate{f.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.pool, MinVersion: version, MaxVersion: version, SessionTicketsDisabled: true}
	if !verified {
		serverConfig.ClientAuth = tls.RequireAnyClientCert
	}
	server := tls.Server(left, serverConfig)
	client := tls.Client(right, &tls.Config{Certificates: []tls.Certificate{f.cert(key)}, RootCAs: f.pool, ServerName: "storage.test", MinVersion: version, MaxVersion: version, SessionTicketsDisabled: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.HandshakeContext(ctx) }()
	must(f.t, server.HandshakeContext(ctx))
	must(f.t, <-done)
	return server
}
func (f *fixture) authControl(key ed25519.PrivateKey, epoch uint64) *ControllerPrincipal {
	p, err := f.a.AuthenticateController(context.Background(), f.conn(key, tls.VersionTLS13, true), epoch)
	must(f.t, err)
	return p
}
func (f *fixture) volume(name string) Volume {
	f.t.Helper()
	path := filepath.Join(f.path, "volumes", name)
	must(f.t, os.Mkdir(path, 0700))
	fd, err := os.Open(path)
	must(f.t, err)
	root, err := identity(fd)
	fd.Close()
	must(f.t, err)
	v := Volume{mustID(f.t), name, root}
	must(f.t, f.a.AddVolume(f.control, VolumeRequest{mustID(f.t), v}))
	return v
}
func (f *fixture) binding(v Volume, role Role, mode Mode, p ID) (Binding, ed25519.PrivateKey) {
	k := newKey(f.t)
	return Binding{f.a.s.Store.ID, v.ID, mustID(f.t), p, mustContainerID(f.t), mustID(f.t), fp(f.t, k), role, mode}, k
}
func (f *fixture) runtime(v Volume, mode Mode) (Binding, *DataPrincipal) {
	b, k := f.binding(v, RuntimeRole, mode, "")
	must(f.t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(f.t), b}))
	p, err := f.a.AuthenticateData(context.Background(), f.conn(k, tls.VersionTLS13, true), DataHello{f.a.Epoch(), b})
	must(f.t, err)
	return b, p
}
func (f *fixture) retire(b Binding) Receipt {
	r, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(f.t), b.Store, b.Volume, b.Attachment, b.Launch})
	must(f.t, err)
	return r
}
func await(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("synchronization timed out")
	}
}

func TestAdmissionRetirementQueuedResourcesAndCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := newLifecycleWorkloadFixture(t, func(b Binding, root *os.File) error {
		if root == nil {
			return ErrInvalid
		}
		calls.Add(1)
		close(entered)
		<-release
		return nil
	})
	v := f.volume("data")
	b, p := f.runtime(v, ReadWrite)
	guard, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	// This guard models work already admitted but queued for identity/namespace.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	_, err = f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	_, err = f.a.Admit(p, v.ID, true)
	wantErr(t, err, ErrBlocked)
	wantErr(t, f.a.Close(), ErrBusy)
	select {
	case <-entered:
		t.Fatal("barrier ran while queued work owned resources")
	default:
	}
	copyGuard := *guard
	guard.Release()
	copyGuard.Release()
	guard.Release()
	await(t, entered)
	// Retirement barrier never owns the admission/control mutex.
	v2 := f.volume("unrelated")
	b2, _ := f.runtime(v2, ReadWrite)
	_, err = f.a.Retire(ctx, f.control, RetireRequest{mustID(t), b2.Store, b2.Volume, b2.Attachment, b2.Launch})
	wantErr(t, err, context.Canceled)
	// The unrelated transaction cannot erase the durable barrier uncertainty.
	if _, err := os.Stat(filepath.Join(f.path, registryName, barrierName)); err != nil {
		t.Fatal(err)
	}
	// Use an idempotent second barrier for the unrelated attachment.
	f.a.mu.Lock()
	f.a.barrier = func(Binding, *os.File) error { return nil }
	f.a.mu.Unlock()
	close(release)
	receipt, err := f.a.Retire(context.Background(), f.control, req)
	must(t, err)
	again, err := f.a.Retire(context.Background(), f.control, req)
	must(t, err)
	if receipt != again || calls.Load() != 1 {
		t.Fatalf("unstable receipt/barrier: %+v %+v %d", receipt, again, calls.Load())
	}
	f.retire(b2)
	changed := req
	changed.Volume = v2.ID
	_, err = f.a.Retire(context.Background(), f.control, changed)
	wantErr(t, err, ErrConflict)
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	s, err := f.a.Query(f.control)
	must(t, err)
	if *s.Attachments[b.Attachment].Receipt != receipt {
		t.Fatal("receipt changed across open")
	}
}

func TestRetireRequiresExactBindingLaunch(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("launch-fence")
	b, _ := f.runtime(v, ReadWrite)
	operation := mustID(t)

	malformed := RetireRequest{operation, b.Store, b.Volume, b.Attachment, ID("not-a-launch")}
	if _, err := f.a.Retire(context.Background(), f.control, malformed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed launch accepted: %v", err)
	}
	if f.a.s.Attachments[b.Attachment].Phase != Active || f.a.s.Attachments[b.Attachment].Retirement != "" {
		t.Fatal("malformed launch changed attachment state")
	}

	wrong := RetireRequest{operation, b.Store, b.Volume, b.Attachment, mustID(t)}
	if _, err := f.a.Retire(context.Background(), f.control, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong launch accepted: %v", err)
	}
	if f.a.s.Attachments[b.Attachment].Phase != Active || f.a.s.Attachments[b.Attachment].Retirement != "" {
		t.Fatal("wrong launch changed attachment state")
	}

	exact := RetireRequest{operation, b.Store, b.Volume, b.Attachment, b.Launch}
	receipt, err := f.a.Retire(context.Background(), f.control, exact)
	must(t, err)
	if receipt.Launch != b.Launch || receipt.Attachment != b.Attachment {
		t.Fatalf("receipt lost generation fence: %+v", receipt)
	}
	changed := exact
	changed.Launch = mustID(t)
	if _, err := f.a.Retire(context.Background(), f.control, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed launch replay accepted: %v", err)
	}
	again, err := f.a.Retire(context.Background(), f.control, exact)
	must(t, err)
	if again != receipt {
		t.Fatalf("valid exact replay changed receipt: %+v %+v", receipt, again)
	}
}

func TestTLSBindingReadOnlyAndNoReconnect(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("ro")
	b, k := f.binding(v, RuntimeRole, ReadOnly, "")
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}))
	conn := f.conn(k, tls.VersionTLS13, true)
	bad := b
	bad.Role = PrepareRole
	_, err := f.a.AuthenticateData(context.Background(), conn, DataHello{f.a.Epoch(), bad})
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.AuthenticateData(context.Background(), f.conn(newKey(t), tls.VersionTLS13, true), DataHello{f.a.Epoch(), b})
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.AuthenticateData(context.Background(), f.conn(k, tls.VersionTLS12, true), DataHello{f.a.Epoch(), b})
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.AuthenticateData(context.Background(), f.conn(k, tls.VersionTLS13, false), DataHello{f.a.Epoch(), b})
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.AuthenticateData(context.Background(), conn, DataHello{mustID(t), b})
	wantErr(t, err, ErrUnauthorized)
	p, err := f.a.AuthenticateData(context.Background(), conn, DataHello{f.a.Epoch(), b})
	must(t, err)
	_, err = f.a.AuthenticateData(context.Background(), conn, DataHello{f.a.Epoch(), b})
	wantErr(t, err, ErrConflict)
	_, err = f.a.Admit(p, v.ID, true)
	wantErr(t, err, ErrReadOnly)
	_, err = f.a.Admit(p, mustID(t), false)
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.Admit(&DataPrincipal{}, v.ID, false)
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.Query(&ControllerPrincipal{})
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.AuthenticateController(context.Background(), conn, 1)
	wantErr(t, err, ErrUnauthorized)
	guard, err := f.a.Admit(p, v.ID, false)
	must(t, err)
	guard.Release()
	snap, err := f.a.Query(f.control)
	must(t, err)
	delete(snap.Attachments, b.Attachment)
	if len(f.a.s.Attachments) != 1 {
		t.Fatal("mutable snapshot leaked")
	}
}

func TestAtomicReservationCompletionReplacementAndKeyTombstones(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v1, v2, v3 := f.volume("one"), f.volume("two"), f.volume("three")
	_, peer := f.runtime(v1, ReadWrite)
	p := mustID(t)
	b1, _ := f.binding(v1, PrepareRole, ReadWrite, p)
	b2, _ := f.binding(v2, PrepareRole, ReadWrite, p)
	req := ReserveRequest{mustID(t), p, []Binding{b2, b1}}
	must(t, f.a.ReservePrepare(f.control, req))
	must(t, f.a.ReservePrepare(f.control, req))
	guard, err := f.a.Admit(peer, v1.ID, true)
	must(t, err)
	guard.Release()
	runtime, _ := f.binding(v1, RuntimeRole, ReadWrite, "")
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), runtime}), ErrBlocked)
	otherP := mustID(t)
	clash, _ := f.binding(v2, PrepareRole, ReadWrite, otherP)
	disjoint, _ := f.binding(v3, PrepareRole, ReadWrite, otherP)
	failed := ReserveRequest{mustID(t), otherP, []Binding{disjoint, clash}}
	wantErr(t, f.a.ReservePrepare(f.control, failed), ErrBlocked)
	if _, ok := f.a.s.Attachments[disjoint.Attachment]; ok {
		t.Fatal("partial all-volume reservation")
	}
	changed := req
	changed.Attachments = []Binding{b1}
	wantErr(t, f.a.ReservePrepare(f.control, changed), ErrConflict)
	plannedKey := runtime
	plannedKey.Key = b1.Key
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), plannedKey}), ErrConflict)
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b1}))
	r1 := f.retire(b1) // b2 remains RESERVED and must also drain.
	complete := CompleteRequest{mustID(t), p, []Receipt{r1}, Attestation{p, true, true}}
	wantErr(t, f.a.CompletePrepare(f.control, complete), ErrBlocked)
	r2 := f.retire(b2)
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b2}), ErrBlocked)
	complete.Receipts = []Receipt{r2, r1}
	complete.Attestation.CleanCopyUp = false
	wantErr(t, f.a.CompletePrepare(f.control, complete), ErrInvalid)
	nextP := mustID(t)
	n1, _ := f.binding(v1, PrepareRole, ReadWrite, nextP)
	n2, _ := f.binding(v2, PrepareRole, ReadWrite, nextP)
	replace := ReplaceRequest{mustID(t), p, []Receipt{r2, r1}, ReserveRequest{mustID(t), nextP, []Binding{n1, n2}}}
	must(t, f.a.ReplacePrepare(f.control, replace))
	must(t, f.a.ReplacePrepare(f.control, replace))
	complete.Attestation.CleanCopyUp = true
	wantErr(t, f.a.CompletePrepare(f.control, complete), ErrConflict)
	finish := CompleteRequest{mustID(t), nextP, []Receipt{f.retire(n1), f.retire(n2)}, Attestation{nextP, true, true}}
	must(t, f.a.CompletePrepare(f.control, finish))
	must(t, f.a.CompletePrepare(f.control, finish))
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), runtime}))
	replay, _ := f.binding(v3, RuntimeRole, ReadWrite, "")
	replay.Key = b1.Key
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), replay}), ErrConflict)
	must(t, f.a.validate())
}

func TestRestartFencesEpochReservedAndActive(t *testing.T) {
	var calls atomic.Int32
	f := newLifecycleWorkloadFixture(t, func(Binding, *os.File) error { calls.Add(1); return nil })
	v := f.volume("restart")
	b, old := f.runtime(v, ReadWrite)
	prep := mustID(t)
	reserved, _ := f.binding(v, PrepareRole, ReadWrite, prep)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), prep, []Binding{reserved}}))
	epoch := f.a.Epoch()
	oldControl := f.control
	must(t, f.a.Close())
	var err error
	f.a, err = f.openCurrent()
	must(t, err)
	if f.a.Epoch() == epoch {
		t.Fatal("epoch reused")
	}
	_, err = f.a.Admit(old, v.ID, true)
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.Query(oldControl)
	wantErr(t, err, ErrUnauthorized)
	f.control = f.authControl(f.controllerKey, 1)
	for _, id := range []ID{b.Attachment, reserved.Attachment} {
		if f.a.s.Attachments[id].Phase != Retiring {
			t.Fatal("recovered admission")
		}
	}
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}), ErrBlocked)
	f.retire(b)
	f.retire(reserved)
	if calls.Load() != 2 {
		t.Fatal("recovery skipped barrier")
	}
}

func TestControllerTakeoverPinnedKeyEpochAndDurableConsume(t *testing.T) {
	f := newFixture(t, nil)
	next := newKey(t)
	successor, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(next, tls.VersionTLS13, true))
	must(t, err)
	g := f.takeoverGrant(1, fp(t, next))
	msg, err := LifecycleGrantSigningBytes(g)
	must(t, err)
	req := SignedLifecycleGrant{g, ed25519.Sign(f.controllerKey, msg)}
	_, err = f.a.TakeoverLifecycle(successor, req)
	wantErr(t, err, ErrUnauthorized)
	req.Signature = ed25519.Sign(f.bootstrap, msg)
	got, err := f.a.TakeoverLifecycle(successor, req)
	must(t, err)
	if got.Epoch != 2 {
		t.Fatal(got)
	}
	again, err := f.a.TakeoverLifecycle(successor, req)
	must(t, err)
	if got != again {
		t.Fatal("takeover reply not stable")
	}
	_, err = f.a.Query(f.control)
	wantErr(t, err, ErrUnauthorized)
	_, err = f.a.AuthenticateController(context.Background(), f.conn(f.controllerKey, tls.VersionTLS13, true), 2)
	wantErr(t, err, ErrUnauthorized)
	f.control = f.authControl(next, 2)
	newer := newKey(t)
	sp, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(newer, tls.VersionTLS13, true))
	must(t, err)
	stale := f.takeoverGrant(1, fp(t, newer))
	msg, err = LifecycleGrantSigningBytes(stale)
	must(t, err)
	_, err = f.a.TakeoverLifecycle(sp, SignedLifecycleGrant{stale, ed25519.Sign(f.bootstrap, msg)})
	wantErr(t, err, ErrUnauthorized)
	stale.ID = g.ID
	_, err = f.a.TakeoverLifecycle(sp, SignedLifecycleGrant{stale, ed25519.Sign(f.bootstrap, msg)})
	wantErr(t, err, ErrUnauthorized)
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	sp, err = f.a.AuthenticateSuccessor(context.Background(), f.conn(next, tls.VersionTLS13, true))
	must(t, err)
	got, err = f.a.TakeoverLifecycle(sp, req)
	must(t, err)
	if got.Epoch != 2 {
		t.Fatal("grant replay advanced epoch")
	}
	f.control = f.authControl(next, 2)
	must(t, f.a.validate())
}
