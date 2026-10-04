package storagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func id(t *testing.T) a.ID { t.Helper(); v, e := a.NewID(); must(t, e); return v }
func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	return k
}
func fp(t *testing.T, k ed25519.PrivateKey) a.Fingerprint {
	t.Helper()
	v, e := a.PublicKeyFingerprint(k.Public())
	must(t, e)
	return v
}

// Workload fixtures use the actual lifecycle authority and production v3 transport.
// The separate static CA below is only for exercising authority DATA guards.
type fixture struct {
	*lifecycleFixture
	server       *Server
	ca           *x509.Certificate
	caKey        ed25519.PrivateKey
	serverConfig *tls.Config
	pool         *x509.CertPool
	store        a.ID
	l            Limits
}

func fixtureFor(t *testing.T, l Limits, barrier a.Barrier) *fixture {
	t.Helper()
	if l == (Limits{}) {
		l = DefaultLimits()
		l.ResponseBytes = 1 << 20
	}
	if barrier == nil {
		barrier = func(a.Binding, *os.File) error { return nil }
	}
	f := &fixture{lifecycleFixture: newLifecycleTLSFixtureWithBarrier(t, barrier), caKey: key(t), l: l}
	f.store = f.initial.Grant.Identity.Store
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, f.caKey.Public(), f.caKey)
	must(t, e)
	f.ca, e = x509.ParseCertificate(der)
	must(t, e)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.ca)
	f.serverConfig = &tls.Config{Certificates: []tls.Certificate{f.cert(key(t), x509.ExtKeyUsageServerAuth)}, ClientCAs: f.pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	f.server, e = NewPKILifecycleWorkloadServer(f.authority, f.serverPolicy(l))
	must(t, e)
	return f
}
func (f *fixture) serverPolicy(l Limits) PKILifecycleWorkloadServerConfig {
	sc, _ := workloadConfigs(f.lifecycleFixture)
	sc.Limits = l
	return sc
}
func (f *fixture) config() PKILifecycleWorkloadClientConfig {
	_, cc := workloadConfigs(f.lifecycleFixture)
	cc.Limits = f.l
	return cc
}
func (f *fixture) hello() Hello {
	cc := f.config()
	return Hello{Version: LifecycleWorkloadVersion, Role: Controller, ControllerEpoch: cc.CurrentController.Epoch, Store: cc.LifecycleIdentity.Store, ServiceEpoch: cc.ServiceEpoch, LifecycleIdentity: &cc.LifecycleIdentity}
}
func (f *fixture) rawController(raw net.Conn) *tls.Conn {
	cc := f.config()
	server, err := p.NewServerBinding(p.StoreID(f.store), p.ServiceEpoch(cc.ServiceEpoch))
	must(f.t, err)
	conn, err := p.NewControllerTLSClient(raw, cc.Identity, cc.ServerRoot, server, cc.ServerKey)
	must(f.t, err)
	return conn
}
func (f *fixture) cert(k ed25519.PrivateKey, usage x509.ExtKeyUsage) tls.Certificate {
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	must(f.t, e)
	tmpl := &x509.Certificate{SerialNumber: serial, DNSNames: []string{"control.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, f.ca, k.Public(), f.caKey)
	must(f.t, e)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	must(t, e)
	defer l.Close()
	right, e := net.Dial("tcp", l.Addr().String())
	must(t, e)
	left, e := l.Accept()
	must(t, e)
	return left, right
}

type testWorker struct {
	done chan struct{}
	err  error // Published by closing done, after Serve releases its slot.
}

func (w *testWorker) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-w.done:
		return w.err
	case <-time.After(3 * time.Second):
		t.Fatal("server worker did not join")
		return nil
	}
}

func (f *fixture) connectWorker(server *Server, c PKILifecycleWorkloadClientConfig) (*Client, *testWorker, error) {
	left, right := tcpPair(f.t)
	worker := &testWorker{done: make(chan struct{})}
	go func() {
		defer close(worker.done)
		worker.err = server.Serve(context.Background(), left)
	}()
	f.t.Cleanup(func() { right.Close(); worker.wait(f.t) })
	client, e := NewPKILifecycleWorkloadClient(context.Background(), right, c)
	if e == nil {
		f.t.Cleanup(func() { client.Close() })
	}
	return client, worker, e
}

func (f *fixture) connect(c PKILifecycleWorkloadClientConfig) (*Client, error) {
	client, _, e := f.connectWorker(f.server, c)
	return client, e
}
func (f *fixture) client() *Client {
	c, e := f.connect(f.config())
	must(f.t, e)
	return c
}
func call(t *testing.T, c interface {
	Call(context.Context, Request) (Response, error)
}, q Request) Response {
	t.Helper()
	r, e := c.Call(context.Background(), q)
	must(t, e)
	return r
}
func remote(t *testing.T, e error, want Code) {
	t.Helper()
	var r *RemoteError
	if !errors.As(e, &r) || r.Code != want {
		t.Fatalf("got %v want code %s", e, want)
	}
}
func (f *fixture) binding(v a.ID, prepare a.ID) (a.Binding, ed25519.PrivateKey) {
	k := key(f.t)
	role := a.RuntimeRole
	if prepare != "" {
		role = a.PrepareRole
	}
	return a.Binding{Store: f.store, Volume: v, Attachment: id(f.t), Prepare: prepare, Container: a.ContainerID(strings.Repeat("1", 64)), Launch: id(f.t), Key: fp(f.t, k), Role: role, Mode: a.ReadWrite}, k
}
func (f *fixture) data(k ed25519.PrivateKey, b a.Binding) *a.DataPrincipal {
	left, right := tcpPair(f.t)
	server := tls.Server(left, f.serverConfig)
	cfg := &tls.Config{Certificates: []tls.Certificate{f.cert(k, x509.ExtKeyUsageClientAuth)}, ServerName: "control.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	cfg.RootCAs = f.pool
	client := tls.Client(right, cfg)
	f.t.Cleanup(func() { left.Close(); right.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.HandshakeContext(ctx) }()
	must(f.t, server.HandshakeContext(ctx))
	must(f.t, <-done)
	p, e := f.authority.AuthenticateData(ctx, server, a.DataHello{Epoch: f.authority.Epoch(), Binding: b})
	must(f.t, e)
	return p
}
func TestActualAuthorityLifecycleAndDuplicateRetries(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	c := f.client()
	create := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: "managed"}
	first := call(t, c, Request{CreateVolume: &create})
	if first.VolumeReceipt.Schema != a.SchemaVersion || first.VolumeReceipt.Phase != a.VolumeReady {
		t.Fatal("invalid real creation receipt")
	}
	// Explicit retry on another connection returns the original immutable result.
	c.Close()
	c = f.client()
	again := call(t, c, Request{CreateVolume: &create})
	if *first.VolumeReceipt != *again.VolumeReceipt {
		t.Fatal("create retry changed receipt")
	}
	p := id(t)
	b, k := f.binding(create.Volume, p)
	reserve := a.ReserveRequest{Operation: id(t), Prepare: p, Attachments: []a.Binding{b}}
	call(t, c, Request{ReservePrepare: &reserve})
	call(t, c, Request{ReservePrepare: &reserve})
	register := a.RegisterRequest{Operation: id(t), Binding: b}
	call(t, c, Request{RegisterAttachment: &register})
	data := f.data(k, b)
	g, e := f.authority.Admit(data, b.Volume, true)
	must(t, e)
	retire := a.RetireRequest{Operation: id(t), Store: f.store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}
	done := make(chan Response, 1)
	errs := make(chan error, 1)
	go func() {
		r, e := c.Call(context.Background(), Request{Retire: &retire})
		if e != nil {
			errs <- e
		} else {
			done <- r
		}
	}()
	observer := f.client()
	deadline := time.Now().Add(time.Second)
	for {
		snap := call(t, observer, Request{Query: &Empty{}}).Snapshot
		if snap.Attachments[b.Attachment].Phase == a.Retiring {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retirement never fenced")
		}
		time.Sleep(time.Millisecond)
	}
	if _, e = f.authority.Admit(data, b.Volume, true); !errors.Is(e, a.ErrBlocked) {
		t.Fatalf("not fenced: %v", e)
	}
	select {
	case <-done:
		t.Fatal("manufactured early receipt")
	case e := <-errs:
		t.Fatal(e)
	default:
	}
	g.Release()
	var receipt a.Receipt
	select {
	case r := <-done:
		receipt = *r.Receipt
	case e := <-errs:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("retire blocked")
	}
	same := call(t, observer, Request{Retire: &retire})
	if receipt != *same.Receipt {
		t.Fatal("retire retry changed receipt")
	}
	complete := a.CompleteRequest{Operation: id(t), Prepare: p, Receipts: []a.Receipt{receipt}, Attestation: a.Attestation{Prepare: p, Succeeded: true, CleanCopyUp: true}}
	call(t, observer, Request{CompletePrepare: &complete})
	del := a.DeleteVolumeRequest{Operation: id(t), Store: f.store, Volume: b.Volume}
	deleted := call(t, observer, Request{DeleteVolume: &del})
	if deleted.VolumeReceipt.Phase != a.VolumeDeleted {
		t.Fatal("not deleted")
	}
	retry := call(t, observer, Request{DeleteVolume: &del})
	if *deleted.VolumeReceipt != *retry.VolumeReceipt {
		t.Fatal("delete retry changed receipt")
	}
}
func TestLostReplyRetirementTimeoutCoreKeepsBarrier(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	releaseBarrier := sync.OnceFunc(func() { close(release) })
	var barriers atomic.Int32
	f := fixtureFor(t, Limits{}, func(a.Binding, *os.File) error { barriers.Add(1); close(entered); <-release; return nil })
	c := f.client()
	create := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: "timeout"}
	call(t, c, Request{CreateVolume: &create})
	b, _ := f.binding(create.Volume, "")
	call(t, c, Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: b}})

	// Only the faulting Retire uses a short server deadline. Durable setup and
	// receipt publication can legitimately exceed 80ms on a real Linux disk.
	// Keep the client deadline normal so its timer cannot mask the server fault.
	l := f.l
	l.OperationTimeout = 80 * time.Millisecond
	faultServer, e := NewPKILifecycleWorkloadServer(f.authority, f.serverPolicy(l))
	must(t, e)
	faultClient, worker, e := f.connectWorker(faultServer, f.config())
	must(t, e)
	retire := a.RetireRequest{Operation: id(t), Store: f.store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}
	retirementJoined := false
	defer func() {
		releaseBarrier()
		if !retirementJoined {
			// A transport-worker join does not join the core's detached drain.
			// Reuse the healthy setup client to finish it before authority cleanup.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := c.Call(ctx, Request{Retire: &retire}); err != nil {
				t.Errorf("join retirement during cleanup: %v", err)
			}
		}
	}()
	_, e = faultClient.Call(context.Background(), Request{Retire: &retire})
	if e == nil {
		t.Fatal("timeout returned success")
	}
	if e = worker.wait(t); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("retirement worker did not hit its operation deadline: %v", e)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("retirement barrier never started")
	}
	observer := f.client()
	snapshot := call(t, observer, Request{Query: &Empty{}}).Snapshot
	if snapshot.Attachments[b.Attachment].Phase != a.Retiring || snapshot.Attachments[b.Attachment].Receipt != nil {
		t.Fatal("timeout drained attachment")
	}
	releaseBarrier()
	result := call(t, observer, Request{Retire: &retire})
	retirementJoined = true
	if result.Receipt == nil || barriers.Load() != 1 {
		t.Fatal("retry did not join original barrier")
	}
}
func TestStrictJSONBeforeMutationAndSequences(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	valid := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: "must-not-create"}
	base, _ := json.Marshal(Request{ID: 1, CreateVolume: &valid})
	cases := []string{
		`{"id":1,"query":{},"query":{}}`, `{"id":1,"Query":{}}`, `{"id":1,"query":null}`, `{"id":1,"query":{},"extra":0}`,
		`{"id":1,"query":{},"retire":{}}`, `{"id":0,"query":{}}`, `{"id":2,"query":{}}`, `{"id":1,"add_volume":{}}`,
		strings.Replace(string(base), `"name":"must-not-create"`, `"name":"must-not-create","name":"duplicate"`, 1),
		strings.Replace(string(base), `"name":"must-not-create"`, `"name":"must-not-create","extra":1`, 1),
	}
	for _, body := range cases {
		c := f.client()
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(body)))
		must(t, writeFull(c.conn, append(header[:], []byte(body)...)))
		var response Response
		if e := readFrame(c.conn, &response, f.l.ResponseBytes, &budget{}); e == nil {
			t.Fatalf("accepted malformed request: %s", body)
		}
		c.Close()
	}
	c := f.client()
	snap := call(t, c, Request{Query: &Empty{}}).Snapshot
	if len(snap.Volumes) != 0 {
		t.Fatal("malformed request mutated authority")
	}
	must(t, writeFrame(c.conn, Request{ID: 1, Query: &Empty{}}, f.l.RequestBytes, &budget{}))
	var response Response
	if e := readFrame(c.conn, &response, f.l.ResponseBytes, &budget{}); e == nil {
		t.Fatal("duplicate sequence accepted")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
func TestFrameBoundsPartialIOAndBudget(t *testing.T) {
	var out shortWriter
	q := Request{ID: 1, Query: &Empty{}}
	must(t, writeFrame(&out, q, 1024, &budget{}))
	var decoded Request
	must(t, readFrame(&out, &decoded, 1024, &budget{}))
	if !decoded.valid() {
		t.Fatal("short writes lost request")
	}
	if !errors.Is(writeFrame(zeroWriter{}, q, 1024, &budget{}), io.ErrShortWrite) {
		t.Fatal("zero write not rejected")
	}
	for _, n := range []uint32{0, 1025, ^uint32(0)} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		if !errors.Is(readFrame(bytes.NewReader(b[:]), &decoded, 1024, &budget{}), ErrLimit) {
			t.Fatal("size accepted")
		}
	}
	if e := readFrame(bytes.NewReader([]byte{0, 0, 0, 10, '{'}), &decoded, 1024, &budget{}); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal(e)
	}
	b := &budget{}
	if !b.take(MaxAggregate) || b.take(1) {
		t.Fatal("aggregate bound")
	}
	if !errors.Is(writeFrame(&out, q, 1024, b), ErrLimit) {
		t.Fatal("unreserved response")
	}
	b.release(MaxAggregate)
	if b.used != 0 {
		t.Fatal("leak")
	}
	for _, body := range []string{`{"id":1,"query":{}} {}`, `{"id":1,"query":{},"ID":1}`, `{"id":1.2,"query":{}}`, `{"id":1,"query":{"x":null}}`} {
		if strictDecode([]byte(body), &decoded) == nil {
			t.Fatal(body)
		}
	}
}
func TestDedicatedConnectionLimitAndQueryOverflow(t *testing.T) {
	l := DefaultLimits()
	l.Connections = 2
	l.ResponseBytes = 1024
	f := fixtureFor(t, l, nil)
	first, firstWorker, e := f.connectWorker(f.server, f.config())
	must(t, e)
	second, secondWorker, e := f.connectWorker(f.server, f.config())
	must(t, e)
	if _, e := f.connect(f.config()); e == nil {
		t.Fatal("exceeded connection capacity")
	}
	first.Close()
	second.Close()
	firstWorker.wait(t)
	secondWorker.wait(t)
	c := f.client()
	for i := 0; i < 8; i++ {
		q := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: string(rune('a' + i))}
		call(t, c, Request{CreateVolume: &q})
	}
	r, e := c.Call(context.Background(), Request{Query: &Empty{}})
	remote(t, e, Limit)
	if r.Snapshot != nil {
		t.Fatal("truncated query presented as success")
	}
}
