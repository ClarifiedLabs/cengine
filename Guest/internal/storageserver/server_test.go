package storageserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
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
func fingerprint(t *testing.T, k ed25519.PrivateKey) a.Fingerprint {
	t.Helper()
	f, e := a.PublicKeyFingerprint(k.Public())
	must(t, e)
	return f
}

type fixture struct {
	t        *testing.T
	s        *Server
	a        *a.Authority
	control  *a.ControllerPrincipal
	ca       *x509.Certificate
	caKey    ed25519.PrivateKey
	pool     *x509.CertPool
	volume   a.ID
	retired  chan a.DataHello
	inputTLS *tls.Config
	path     string
}

func newFixture(t *testing.T, limits Limits, real bool, configure ...func(*a.Config)) *fixture {
	t.Helper()
	f := &fixture{t: t, caKey: key(t), retired: make(chan a.DataHello, 32)}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, f.caKey.Public(), f.caKey)
	must(t, e)
	f.ca, e = x509.ParseCertificate(der)
	must(t, e)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.ca)
	config := &tls.Config{Certificates: []tls.Certificate{f.cert(key(t))}, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	f.inputTLS = config
	f.s, e = New(Config{TLSConfig: config, ClientRoots: [][]byte{f.ca.Raw}, Limits: limits, RequestRetirement: func(h a.DataHello, _ error) { f.retired <- h }})
	must(t, e)
	path := t.TempDir()
	f.path = path
	must(t, os.Mkdir(filepath.Join(path, "volumes"), 0755))
	must(t, os.Mkdir(filepath.Join(path, "volumes", "data"), 0777))
	root, e := os.Open(path)
	must(t, e)
	t.Cleanup(func() { root.Close() })
	controller := key(t)
	barrier := f.s.Barrier
	if !real {
		barrier = func(a.Binding, *os.File) error { return nil }
	}
	bootstrap := key(t)
	authorityConfig := a.Config{Root: root, DeviceID: "transport-test", BootstrapKey: bootstrap.Public().(ed25519.PublicKey), Barrier: barrier}
	for _, setup := range configure {
		setup(&authorityConfig)
	}
	f.a, e = at.New(t, bootstrap, id(t), fingerprint(t, controller)).Initialize(authorityConfig)
	must(t, e)
	t.Cleanup(func() { must(t, f.a.Close()) })
	raw, client := f.pair(controller)
	server := tls.Server(raw, f.s.config.TLSConfig)
	done := make(chan error, 1)
	go func() { done <- client.Handshake() }()
	f.control, e = f.a.AuthenticateController(context.Background(), server, 1)
	must(t, e)
	must(t, <-done)
	server.NetConn().Close()
	client.NetConn().Close()
	var st unix.Stat_t
	must(t, unix.Stat(filepath.Join(path, "volumes", "data"), &st))
	f.volume = id(t)
	must(t, f.a.AddVolume(f.control, a.VolumeRequest{Operation: id(t), Volume: a.Volume{ID: f.volume, Name: "data", Root: a.RootIdentity{Device: uint64(st.Dev), Inode: st.Ino}}}))
	if !real {
		f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
			if e := g.ValidateFor(p); e != nil {
				return nil, w.Entry{}, e
			}
			return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
				if e := g.ValidateFor(p); e != nil {
					return m.Result{}, e
				}
				return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: r.Body.Operation(), Body: w.GetAttrReply{Attr: rootEntry().Attr}}}, nil
			}), rootEntry(), nil
		}
	}
	return f
}
func rootEntry() w.Entry {
	return w.Entry{Node: 1, Generation: 1, Object: w.ObjectID{1}, Attr: w.Attr{Ino: 1, Mode: 0040755, Nlink: 1, BlockSize: 4096}}
}
func (f *fixture) cert(k ed25519.PrivateKey) tls.Certificate {
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	must(f.t, e)
	c := &x509.Certificate{SerialNumber: serial, DNSNames: []string{"storage.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, c, f.ca, k.Public(), f.caKey)
	must(f.t, e)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
func (f *fixture) pair(k ed25519.PrivateKey) (net.Conn, *tls.Conn) {
	l, r := net.Pipe()
	f.t.Cleanup(func() { l.Close(); r.Close() })
	client := tls.Client(r, &tls.Config{Certificates: []tls.Certificate{f.cert(k)}, RootCAs: f.pool, ServerName: "storage.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	must(f.t, client.SetDeadline(time.Now().Add(5*time.Second)))
	return l, client
}
func (f *fixture) binding() (a.Binding, ed25519.PrivateKey) {
	k := key(f.t)
	snapshot, e := f.a.Query(f.control)
	must(f.t, e)
	b := a.Binding{Store: snapshot.Store.ID, Volume: f.volume, Attachment: id(f.t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(f.t), Key: fingerprint(f.t, k), Role: a.RuntimeRole, Mode: a.ReadWrite}
	must(f.t, f.a.RegisterAttachment(f.control, a.RegisterRequest{Operation: id(f.t), Binding: b}))
	return b, k
}
func (f *fixture) start(b a.Binding, k ed25519.PrivateKey) (*tls.Conn, chan error) {
	server, client := f.pair(k)
	done := make(chan error, 1)
	go func() { done <- f.s.Serve(context.Background(), f.a, server) }()
	var hello w.ServerHello
	must(f.t, w.ReadFrame(client, &hello))
	must(f.t, w.WriteFrame(client, &w.ClientHello{Authority: a.DataHello{Epoch: hello.Epoch, Binding: b}, Profile: w.RequiredProfile()}))
	return client, done
}
func (f *fixture) connected() (*tls.Conn, chan error, a.Binding) {
	b, k := f.binding()
	client, done := f.start(b, k)
	var root w.RootReply
	must(f.t, w.ReadFrame(client, &root))
	return client, done, b
}
func wait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("server did not join")
		return nil
	}
}
func retired(t *testing.T, ch <-chan a.DataHello) a.DataHello {
	t.Helper()
	select {
	case h := <-ch:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("missing retirement")
		return a.DataHello{}
	}
}

type execFunc func(*a.Guard, w.Request) (m.Result, error)

func (e execFunc) Dispatch(g *a.Guard, r w.Request) (m.Result, error) { return e(g, r) }
func request(n uint64) w.Request {
	return w.Request{Sequence: n, Auth: w.Auth{Kind: w.NodeMetadataAuth}, Body: w.GetAttrRequest{Node: 1}}
}
func readMessage(t *testing.T, c *tls.Conn) w.ServerMessage {
	t.Helper()
	v, e := w.ReadServerFrame(c)
	must(t, e)
	return v
}

func TestTLSAndSequenceTerminalNoReconnect(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	b, k := f.binding()
	c, done := f.start(b, k)
	var root w.RootReply
	must(t, w.ReadFrame(c, &root))
	r := request(2)
	must(t, w.WriteFrame(c, &r))
	if v := readMessage(t, c).(*w.Reply); v.Sequence != 2 {
		t.Fatal(v)
	}
	must(t, w.WriteFrame(c, &r))
	if e := wait(t, done); !errors.Is(e, w.ErrInvalid) {
		t.Fatalf("sequence error: %v", e)
	}
	if h := retired(t, f.retired); h.Binding != b || h.Epoch != f.a.Epoch() {
		t.Fatal(h)
	}
	c, done = f.start(b, k)
	if e := w.ReadFrame(c, &root); e == nil {
		t.Fatal("reconnected")
	}
	if e := wait(t, done); !errors.Is(e, a.ErrConflict) {
		t.Fatal(e)
	}
	select {
	case h := <-f.retired:
		t.Fatalf("unauthenticated retirement: %v", h)
	default:
	}
}
func TestGuardSurvivesEOFAndRetirement(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	entered := make(chan *a.Guard, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
			calls.Add(1)
			entered <- g
			<-release
			must(t, g.ValidateFor(p))
			return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: rootEntry().Attr}}}, nil
		}), rootEntry(), nil
	}
	c, done, b := f.connected()
	r := request(1)
	must(t, w.WriteFrame(c, &r))
	g := <-entered
	c.NetConn().Close()
	if h := retired(t, f.retired); h.Binding != b {
		t.Fatal(h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	retire := a.RetireRequest{Operation: id(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}
	_, e := f.a.Retire(ctx, f.control, retire)
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if duplicate, e := g.DupVolumeRoot(); e != nil {
		t.Fatal(e)
	} else {
		must(t, duplicate.Close())
	}
	if e := f.a.Close(); !errors.Is(e, a.ErrBusy) {
		t.Fatalf("guard released early: %v", e)
	}
	close(release)
	wait(t, done)
	_, e = f.a.Retire(context.Background(), f.control, retire)
	must(t, e)
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}
func TestEventsReplyBeforeOriginAndCrossSessionPartialError(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
			must(t, g.ValidateFor(p))
			return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpGetAttr, Errno: 5}, Events: []w.Event{{EventSequence: r.Sequence, Volume: b.Volume, Object: w.ObjectID{9}, Kind: w.InvalidateAttr, Name: []byte{}}}}, nil
		}), rootEntry(), nil
	}
	c1, d1, b1 := f.connected()
	c2, d2, _ := f.connected()
	r := request(1)
	must(t, w.WriteFrame(c1, &r))
	if got := readMessage(t, c1).(*w.Reply); got.Errno != 5 {
		t.Fatal(got)
	}
	for _, c := range []*tls.Conn{c1, c2} {
		e := readMessage(t, c).(*w.Event)
		if e.Object != (w.ObjectID{9}) || e.Volume != b1.Volume {
			t.Fatal(e)
		}
	}
	c1.NetConn().Close()
	c2.NetConn().Close()
	wait(t, d1)
	wait(t, d2)
}
func TestWriterTimeoutDoesNotHoldGuard(t *testing.T) {
	limits := DefaultLimits()
	limits.WriteTimeout = 50 * time.Millisecond
	f := newFixture(t, limits, false)
	completed := make(chan *a.Guard, 1)
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
			completed <- g
			return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: rootEntry().Attr}}}, nil
		}), rootEntry(), nil
	}
	c, done, b := f.connected()
	r := request(1)
	must(t, w.WriteFrame(c, &r))
	g := <-completed
	wait(t, done)
	if h := retired(t, f.retired); h.Binding != b {
		t.Fatal(h)
	}
	if _, e := g.DupVolumeRoot(); !errors.Is(e, a.ErrClosed) {
		t.Fatalf("guard still owned: %v", e)
	}
}
func TestMalformedAndHandshakeTimeout(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		f := newFixture(t, Limits{}, false)
		c, done, b := f.connected()
		_, e := c.Write([]byte{0, 0, 0, 2, '{', '}'})
		must(t, e)
		if e := wait(t, done); !errors.Is(e, w.ErrInvalid) {
			t.Fatal(e)
		}
		if retired(t, f.retired).Binding != b {
			t.Fatal("wrong attachment")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		l := DefaultLimits()
		l.HandshakeTimeout = 30 * time.Millisecond
		f := newFixture(t, l, false)
		server, client := f.pair(key(t))
		defer client.NetConn().Close()
		done := make(chan error, 1)
		go func() { done <- f.s.Serve(context.Background(), f.a, server) }()
		if wait(t, done) == nil {
			t.Fatal("handshake succeeded")
		}
		select {
		case <-f.retired:
			t.Fatal("unauthenticated retirement")
		default:
		}
	})
}
func TestTLSConfigurationRejectsRelaxation(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	mutations := []func(*tls.Config){func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 }, func(c *tls.Config) { c.MaxVersion = 0 }, func(c *tls.Config) { c.SessionTicketsDisabled = false }, func(c *tls.Config) { c.ClientAuth = tls.RequireAnyClientCert }, func(c *tls.Config) {
		c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return c, nil }
	}, func(c *tls.Config) { c.ClientCAs = f.pool }, func(c *tls.Config) { c.RootCAs = f.pool }}
	for _, mutate := range mutations {
		c := f.inputTLS.Clone()
		mutate(c)
		if _, e := New(Config{TLSConfig: c, ClientRoots: [][]byte{f.ca.Raw}, RequestRetirement: func(a.DataHello, error) {}}); !errors.Is(e, ErrConfiguration) {
			t.Fatal(e)
		}
	}
}
