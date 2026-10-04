package storagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

type lifecycleFixture struct {
	*pkiFixture
	rootPath                  string
	initial, takeover, retire a.SignedLifecycleGrant
	sc                        LifecycleServerConfig
	cc                        LifecycleClientConfig
}

func lifecycleSign(t *testing.T, k ed25519.PrivateKey, g a.LifecycleGrant) a.SignedLifecycleGrant {
	t.Helper()
	b, e := a.LifecycleGrantSigningBytes(g)
	must(t, e)
	return a.SignedLifecycleGrant{Grant: g, Signature: ed25519.Sign(k, b)}
}
func newLifecycleTLSFixture(t *testing.T) *lifecycleFixture {
	return newLifecycleTLSFixtureWithBarrier(t, func(a.Binding, *os.File) error {
		t.Error("unexpected resource barrier in empty-store lifecycle test")
		return a.ErrBlocked
	})
}

func newLifecycleTLSFixtureWithBarrier(t *testing.T, barrier a.Barrier) *lifecycleFixture {
	t.Helper()
	// Reuse PKI issuance helpers and provision a fresh signed authority below.
	f := &lifecycleFixture{pkiFixture: &pkiFixture{t: t, now: time.Now().Add(-time.Minute).UTC().Truncate(time.Second)}}
	f.bootstrap = key(t)
	pub, e := p.NewBootstrapPublicKey(f.bootstrap.Public().(ed25519.PublicKey))
	must(t, e)
	f.issuer, e = p.NewIssuer(f.now, 2*time.Hour, pub)
	must(t, e)
	f.controllerKey, e = p.NewControllerKey()
	must(t, e)
	f.successorKey, e = p.NewControllerKey()
	must(t, e)
	f.serverKey, e = p.NewServerKey()
	must(t, e)
	ident := a.LifecycleIdentity{Store: id(t), Generation: 9007199254740993, Binding: a.Fingerprint(strings.Repeat("b", 64))}
	f.initial = lifecycleSign(t, f.bootstrap, a.LifecycleGrant{Operation: a.LifecycleInitialize, ID: id(t), Identity: ident, Serial: 9007199254740993, NewKey: a.Fingerprint(pkiPin(t, f.controllerKey).String())})
	f.takeover = lifecycleSign(t, f.bootstrap, a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: ident, Serial: f.initial.Grant.Serial + 1, ExpectedEpoch: 1, NewKey: a.Fingerprint(pkiPin(t, f.successorKey).String())})
	f.retire = lifecycleSign(t, f.bootstrap, a.LifecycleGrant{Operation: a.LifecycleRetire, ID: id(t), Identity: ident, Serial: f.initial.Grant.Serial + 2, ExpectedEpoch: 2, NewKey: f.takeover.Grant.NewKey})
	dir := t.TempDir()
	f.rootPath = dir
	must(t, os.Mkdir(filepath.Join(dir, "volumes"), 0700))
	root, e := os.Open(dir)
	must(t, e)
	defer root.Close()
	f.authority, e = a.InitializeLifecycle(a.Config{Root: root, DeviceID: "lifecycle-control-host-test", BootstrapKey: f.bootstrap.Public().(ed25519.PublicKey), Barrier: barrier}, f.initial)
	must(t, e)
	t.Cleanup(func() { must(t, f.authority.Close()) })
	server, e := p.NewServerBinding(p.StoreID(ident.Store), p.ServiceEpoch(f.authority.Epoch()))
	must(t, e)
	controller, e := p.NewControllerBinding(p.StoreID(ident.Store), 1)
	must(t, e)
	f.sc = LifecycleServerConfig{Identity: f.issue(f.serverKey, server), ClientRoot: f.issuer.Root(), ServiceEpoch: f.authority.Epoch(), CurrentGrant: f.initial.Grant, ControllerKey: pkiPin(t, f.controllerKey), SuccessorGrant: f.takeover.Grant, SuccessorKey: pkiPin(t, f.successorKey), RetireGrant: f.retire.Grant}
	f.cc = LifecycleClientConfig{Identity: f.issue(f.controllerKey, controller), ServerRoot: f.issuer.Root(), ServerKey: pkiPin(t, f.serverKey), Hello: LifecycleHello{Version: LifecycleControlVersion, Identity: ident, ServiceEpoch: f.authority.Epoch(), ControllerEpoch: 1}}
	return f
}
func lifecycleServe(t *testing.T, s *LifecycleServer) (net.Conn, *testWorker) {
	t.Helper()
	left, right := tcpPair(t)
	worker := &testWorker{done: make(chan struct{})}
	go func() { defer close(worker.done); worker.err = s.Serve(context.Background(), left) }()
	t.Cleanup(func() { right.Close(); worker.wait(t) })
	return right, worker
}
func lifecycleConnect(t *testing.T, s *LifecycleServer, c LifecycleClientConfig) *LifecycleClient {
	t.Helper()
	raw, _ := lifecycleServe(t, s)
	client, e := NewLifecycleClient(context.Background(), raw, c)
	must(t, e)
	t.Cleanup(func() { client.Close() })
	return client
}
func (f *lifecycleFixture) successor() LifecycleClientConfig {
	c := f.cc
	c.Hello.ControllerEpoch = 2
	b, e := p.NewControllerBinding(p.StoreID(c.Hello.Identity.Store), 2)
	must(f.t, e)
	c.Identity = f.issue(f.successorKey, b)
	return c
}
func TestLifecycleTLSInitializeTakeoverRetireResult(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	s, e := NewLifecycleServer(f.authority, f.sc)
	must(t, e)
	oldRaw, oldWorker := lifecycleServe(t, s)
	old, e := NewLifecycleClient(context.Background(), oldRaw, f.cc)
	must(t, e)
	t.Cleanup(func() { old.Close() })
	r, e := old.Result(context.Background(), f.initial.Grant, bytes.Repeat([]byte{1}, 32))
	must(t, e)
	if r.Grant != f.initial.Grant || r.ServiceEpoch != f.authority.Epoch() {
		t.Fatal("wrong initial result")
	}
	next := lifecycleConnect(t, s, f.successor())
	_, e = next.Result(context.Background(), f.takeover.Grant, make([]byte, 32))
	remote(t, e, Unauthorized)
	bad := f.takeover
	bad.Signature = bytes.Repeat([]byte{0}, 64)
	_, e = next.Takeover(context.Background(), bad)
	remote(t, e, Unauthorized)
	controller, e := next.Takeover(context.Background(), f.takeover)
	must(t, e)
	if controller.Epoch != 2 || controller.Key != f.takeover.Grant.NewKey {
		t.Fatal("takeover")
	}
	_, e = old.Result(context.Background(), f.initial.Grant, make([]byte, 32))
	remote(t, e, Unauthorized)
	old.Close()
	oldWorker.wait(t)
	// Explicit reconnect is refused at Hello, before any stale session can idle.
	raw, rejected := lifecycleServe(t, s)
	if stale, err := NewLifecycleClient(context.Background(), raw, f.cc); err == nil {
		stale.Close()
		t.Fatal("stale controller Hello accepted")
	}
	if err := rejected.wait(t); !errors.Is(err, a.ErrUnauthorized) {
		t.Fatal(err)
	}
	r, e = next.Result(context.Background(), f.takeover.Grant, bytes.Repeat([]byte{2}, 32))
	must(t, e)
	if r.Revision <= 1 {
		t.Fatal("not actual takeover receipt")
	}
	must(t, next.Retire(context.Background(), f.retire))
	seal, e := next.Result(context.Background(), f.retire.Grant, bytes.Repeat([]byte{3}, 32))
	must(t, e)
	again, e := next.Result(context.Background(), f.retire.Grant, bytes.Repeat([]byte{4}, 32))
	must(t, e)
	if seal.Grant != f.retire.Grant || seal.Revision != again.Revision || bytes.Equal(seal.Nonce, again.Nonce) {
		t.Fatal("terminal result not fresh and stable")
	}
	_, e = next.Result(context.Background(), f.takeover.Grant, make([]byte, 32))
	remote(t, e, Unauthorized)
	if e = next.Retire(context.Background(), f.retire); e == nil {
		t.Fatal("sealed mutation accepted")
	}
	next.Close()
	next = lifecycleConnect(t, s, f.successor())
	_, e = next.Result(context.Background(), f.retire.Grant, bytes.Repeat([]byte{5}, 32))
	must(t, e)
}
func TestLifecycleTLSFullGrantAndNonceBinding(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	s, e := NewLifecycleServer(f.authority, f.sc)
	must(t, e)
	c := lifecycleConnect(t, s, f.cc)
	for _, change := range []func(*a.LifecycleGrant){
		func(g *a.LifecycleGrant) { g.ID = id(t) }, func(g *a.LifecycleGrant) { g.Identity.Store = id(t) },
		func(g *a.LifecycleGrant) { g.Identity.Generation++ }, func(g *a.LifecycleGrant) { g.Identity.Binding = g.NewKey },
		func(g *a.LifecycleGrant) { g.Serial++ }, func(g *a.LifecycleGrant) { g.ExpectedEpoch++ },
		func(g *a.LifecycleGrant) { g.NewKey = f.takeover.Grant.NewKey }, func(g *a.LifecycleGrant) { g.Operation = a.LifecycleRetire },
	} {
		g := f.initial.Grant
		change(&g)
		// Bypass typed client prechecks to exercise the real server policy.
		_, e = c.call(context.Background(), lifecycleRequest{Result: &lifecycleResultRequest{g, make([]byte, 32)}})
		remote(t, e, Unauthorized)
	}
	_, e = c.call(context.Background(), lifecycleRequest{Result: &lifecycleResultRequest{f.initial.Grant, make([]byte, 31)}})
	remote(t, e, Unauthorized)
	_, e = c.Result(context.Background(), f.initial.Grant, make([]byte, 32))
	must(t, e)
}
func TestLifecycleTLSPolicyRefusals(t *testing.T) {
	for _, kind := range []string{"identity", "pin", "root", "server-epoch", "controller-key", "controller-uri", "role", "expired"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			s, e := NewLifecycleServer(f.authority, f.sc)
			must(t, e)
			c := f.cc
			switch kind {
			case "identity":
				c.Hello.Identity.Generation++
			case "pin":
				c.ServerKey = pkiPin(t, f.controllerKey)
			case "root":
				issuer, e := p.NewIssuer(f.now, 2*time.Hour, mustBootstrap(t))
				must(t, e)
				c.ServerRoot = issuer.Root()
			case "server-epoch":
				c.Hello.ServiceEpoch = id(t)
			case "controller-key":
				c.Identity = f.issue(f.successorKey, c.Identity.Certificate().Binding())
			case "controller-uri":
				b, e := p.NewControllerBinding(p.StoreID(id(t)), 1)
				must(t, e)
				c.Identity = f.issue(f.controllerKey, b)
			case "role":
				c.Identity = f.sc.Identity
			case "expired":
				binding := c.Identity.Certificate().Binding()
				csr, e := f.controllerKey.CSR(binding)
				must(t, e)
				cert, e := f.issuer.IssueController(csr, binding, f.now, time.Second)
				must(t, e)
				c.Identity, e = cert.WithKey(f.controllerKey)
				must(t, e)
			}
			raw, _ := lifecycleServe(t, s)
			if client, e := NewLifecycleClient(context.Background(), raw, c); e == nil {
				client.Close()
				t.Fatal("bad PKI scope accepted")
			}
		})
	}
}
func mustBootstrap(t *testing.T) p.BootstrapPublicKey {
	t.Helper()
	k, e := p.NewBootstrapPublicKey(key(t).Public().(ed25519.PublicKey))
	must(t, e)
	return k
}
func TestLifecycleTLSProtocolReplayAndV1(t *testing.T) {
	for _, kind := range []string{"replay", "v1", "duplicate", "nested-unknown", "truncated", "mixed-service-result"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			s, e := NewLifecycleServer(f.authority, f.sc)
			must(t, e)
			raw, worker := lifecycleServe(t, s)
			server, e := p.NewServerBinding(p.StoreID(f.cc.Hello.Identity.Store), p.ServiceEpoch(f.cc.Hello.ServiceEpoch))
			must(t, e)
			conn, e := p.NewControllerTLSClient(raw, f.cc.Identity, f.cc.ServerRoot, server, f.cc.ServerKey)
			must(t, e)
			must(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
			must(t, conn.HandshakeContext(context.Background()))
			if kind == "v1" {
				must(t, writeFrame(conn, Hello{Version: 2, Role: Controller, ControllerEpoch: 1, Store: f.cc.Hello.Identity.Store, ServiceEpoch: f.cc.Hello.ServiceEpoch}, 4096, &budget{}))
				var reply LifecycleHello
				if e = readFrame(conn, &reply, 4096, &budget{}); e == nil {
					t.Fatal("v1 admitted")
				}
				return
			}
			must(t, writeFrame(conn, f.cc.Hello, 4096, &budget{}))
			var h LifecycleHello
			must(t, readFrame(conn, &h, 4096, &budget{}))
			q := lifecycleRequest{ID: 1, Result: &lifecycleResultRequest{f.initial.Grant, make([]byte, 32)}}
			if kind == "mixed-service-result" {
				q.ServiceResult = q.Result
			}
			if kind == "replay" {
				must(t, writeFrame(conn, q, lifecycleFrameBytes, &budget{}))
				var r lifecycleResponse
				must(t, readFrame(conn, &r, lifecycleFrameBytes, &budget{}))
				must(t, writeFrame(conn, q, lifecycleFrameBytes, &budget{}))
			} else {
				b, e := json.Marshal(q)
				must(t, e)
				switch kind {
				case "duplicate":
					b = bytes.Replace(b, []byte(`"serial":`), []byte(`"serial":1,"serial":`), 1)
				case "nested-unknown":
					b = bytes.Replace(b, []byte(`"generation":`), []byte(`"extra":1,"generation":`), 1)
				}
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], uint32(len(b)))
				must(t, writeFull(conn, header[:]))
				if kind == "truncated" {
					raw.Close()
				} else {
					must(t, writeFull(conn, b))
				}
			}
			worker.wait(t)
			if worker.err == nil {
				t.Fatal("malformed/replay accepted")
			}
		})
	}
}
func TestLifecycleTLSConnectionLossAndCancellation(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	s, e := NewLifecycleServer(f.authority, f.sc)
	must(t, e)
	raw, worker := lifecycleServe(t, s)
	c, e := NewLifecycleClient(context.Background(), raw, f.cc)
	must(t, e)
	t.Cleanup(func() { c.Close() })
	c.raw.Close()
	if _, e = c.Result(context.Background(), f.initial.Grant, make([]byte, 32)); e == nil {
		t.Fatal("lost connection returned receipt")
	}
	if _, e = c.Result(context.Background(), f.initial.Grant, make([]byte, 32)); !errors.Is(e, ErrClosed) {
		t.Fatal("hidden replay", e)
	}
	worker.wait(t)
	c = lifecycleConnect(t, s, f.cc)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Result(ctx, f.initial.Grant, make([]byte, 32)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestLifecycleSchemaClosedAndNumberPreserving(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	b, e := json.Marshal(lifecycleRequest{ID: 1, Result: &lifecycleResultRequest{f.initial.Grant, make([]byte, 32)}})
	must(t, e)
	var q lifecycleRequest
	must(t, strictDecode(b, &q))
	if q.Result.Grant != f.initial.Grant {
		t.Fatal("uint64 rounded")
	}
	for _, b := range []string{`{"id":1,"result":null}`, `{"id":1,"ID":1}`, `{"id":1,"result":{"grant":{}}}`, strings.Replace(string(b), `"nonce":`, `"nonce":null,"nonce":`, 1)} {
		if strictDecode([]byte(b), &q) == nil {
			t.Fatal("open schema", b)
		}
	}
}

// A real TLS server with deliberately corrupt result data isolates client-side
// exact receipt validation. It has no authority seam in production constructors.
func TestLifecycleTLSClientRejectsCorruptReceipt(t *testing.T) {
	for _, kind := range []string{"nonce", "grant", "identity", "epoch", "revision", "counter"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			left, right := tcpPair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer left.Close()
				cfg, e := p.ServerTLSConfig(f.sc.Identity, f.sc.ClientRoot)
				if e != nil {
					return
				}
				conn := tls.Server(left, cfg)
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if conn.HandshakeContext(context.Background()) != nil {
					return
				}
				var h LifecycleHello
				if readFrame(conn, &h, 4096, &budget{}) != nil {
					return
				}
				if writeFrame(conn, h, 4096, &budget{}) != nil {
					return
				}
				var q lifecycleRequest
				if readFrame(conn, &q, lifecycleFrameBytes, &budget{}) != nil {
					return
				}
				r := a.LifecycleReceipt{Grant: q.Result.Grant, Nonce: bytes.Clone(q.Result.Nonce), ServiceEpoch: h.ServiceEpoch, Revision: 1}
				response := lifecycleResponse{ID: q.ID, Receipt: &r}
				switch kind {
				case "nonce":
					r.Nonce[0] ^= 1
				case "grant":
					r.Grant.Serial++
				case "identity":
					r.Grant.Identity.Generation++
				case "epoch":
					r.ServiceEpoch = f.initial.Grant.ID
				case "revision":
					r.Revision = 0
				case "counter":
					response.ID++
				}
				writeFrame(conn, response, lifecycleFrameBytes, &budget{})
			}()
			client, e := NewLifecycleClient(context.Background(), right, f.cc)
			must(t, e)
			_, e = client.Result(context.Background(), f.initial.Grant, make([]byte, 32))
			if !errors.Is(e, ErrProtocol) {
				t.Fatal(e)
			}
			client.Close()
			<-done
		})
	}
}
