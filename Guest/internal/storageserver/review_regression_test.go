package storageserver

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
)

func TestAdmittedThirdMutationSurvivesFullFIFOAndSocketClose(t *testing.T) {
	var mutations atomic.Int32
	barrier := make(chan a.Binding, 1)
	f := newFixture(t, Limits{}, false, func(c *a.Config) {
		c.Limits = a.DefaultLimits()
		c.Limits.InFlight = 3
		c.Barrier = func(b a.Binding, _ *os.File) error {
			if mutations.Load() != 3 {
				return fmt.Errorf("barrier preceded admitted mutations: %d", mutations.Load())
			}
			barrier <- b
			return nil
		}
	})
	first := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	principals := make(chan *a.DataPrincipal, 1)
	executed := make(chan uint64, 3)
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		principals <- p
		return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
			if r.Sequence == 1 {
				close(first)
				<-release
			}
			if err := g.ValidateFor(p); err != nil {
				return m.Result{}, err
			}
			mutations.Add(1)
			executed <- r.Sequence
			return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpSetAttr, Body: w.SetAttrReply{Attr: rootEntry().Attr}}}, nil
		}), rootEntry(), nil
	}
	operation := id(t)
	callbackDone := make(chan error, 1)
	f.s.config.RequestRetirement = func(h a.DataHello, _ error) {
		f.retired <- h
		_, err := f.a.Retire(context.Background(), f.control, a.RetireRequest{Operation: operation, Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch})
		callbackDone <- err
	}
	c, done, b := f.connected()
	defer c.NetConn().Close()
	p := <-principals
	for seq := uint64(1); seq <= 3; seq++ {
		r := w.Request{Sequence: seq, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.SetAttrRequest{Node: 1, Valid: w.SetMode, Mode: 0600, Semantics: w.MetadataValid | w.MetadataCTime}}
		must(t, w.WriteFrame(c, &r))
		if seq == 1 {
			select {
			case <-first:
			case <-time.After(5 * time.Second):
				t.Fatal("first RPC did not execute")
			}
		}
	}
	// Prove the third request is admitted, not merely buffered in TLS or decoded.
	// All three authority slots remain occupied until dispatch completion.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		g, err := f.a.Admit(p, b.Volume, false)
		if errors.Is(err, a.ErrLimit) {
			break
		}
		must(t, err)
		g.Release()
		select {
		case <-deadline.C:
			t.Fatal("third request never admitted")
		case <-time.After(time.Millisecond):
		}
	}
	c.NetConn().Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.a.Retire(ctx, f.control, a.RetireRequest{Operation: operation, Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-barrier:
		t.Fatal("drain ran while FIFO owned mutations")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	wait(t, done)
	must(t, wait(t, callbackDone))
	for expected := uint64(1); expected <= 3; expected++ {
		if got := <-executed; got != expected {
			t.Fatalf("execution order: got %d want %d", got, expected)
		}
	}
	if got := <-barrier; got != b {
		t.Fatal(got)
	}
	if got := retired(t, f.retired); got.Binding != b {
		t.Fatal(got)
	}
	if len(f.s.receive) != 0 {
		t.Fatal("accepted receive ownership leaked")
	}
}

func TestAllDefaultConnectionsCanIdleWithoutPayloadSlots(t *testing.T) {
	limits := DefaultLimits()
	limits.ReadTimeout = 50 * time.Millisecond
	f := newFixture(t, limits, false)
	var clients []*tls.Conn
	var completions []chan error
	t.Cleanup(func() {
		for _, c := range clients {
			c.NetConn().Close()
		}
		for _, done := range completions {
			wait(t, done)
		}
	})
	for i := 0; i < DefaultLimits().Connections; i++ {
		c, done, _ := f.connected()
		clients = append(clients, c)
		completions = append(completions, done)
	}
	// More idle attachments than receive slots, for several frame deadlines.
	time.Sleep(3 * limits.ReadTimeout)
	if len(f.s.receive) != 0 {
		t.Fatalf("idle payload reservations=%d", len(f.s.receive))
	}
	select {
	case h := <-f.retired:
		t.Fatalf("idle attachment retired: %+v", h)
	default:
	}
	for _, c := range clients {
		r := request(1)
		must(t, w.WriteFrame(c, &r))
		reply := readMessage(t, c).(*w.Reply)
		must(t, w.ValidateReplyFor(r, *reply))
	}
	select {
	case h := <-f.retired:
		t.Fatalf("active attachment retired after idle: %+v", h)
	default:
	}
}

func TestFrameHeaderSizeAndPartialReadDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		want  error
	}{
		{"partial_header", []byte{0}, nil},
		{"partial_payload", []byte{0, 0, 0, 8, '{'}, nil},
		{"empty", []byte{0, 0, 0, 0}, w.ErrInvalid},
		{"oversized", []byte{0, 16, 0, 1}, w.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.ReadTimeout = 50 * time.Millisecond
			f := newFixture(t, limits, false)
			c, done, b := f.connected()
			defer c.NetConn().Close()
			_, err := c.Write(tc.input)
			must(t, err)
			err = wait(t, done)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatal(err)
			}
			if retired(t, f.retired).Binding != b {
				t.Fatal("wrong retirement")
			}
			if len(f.s.receive) != 0 {
				t.Fatal("receive capacity leak")
			}
		})
	}
}

func TestTimedOutFactoryOwnershipJoinsExactRetirement(t *testing.T) {
	// Native executor seam models only registry ownership. Authority, TLS, root
	// duplication, fencing, and the joined retirement callback are all real.
	var mu sync.Mutex
	resources := make(map[a.Binding]*os.File)
	barrier := make(chan a.Binding, 1)
	limits := DefaultLimits()
	limits.HandshakeTimeout = 100 * time.Millisecond
	f := newFixture(t, limits, false, func(c *a.Config) {
		c.Barrier = func(b a.Binding, _ *os.File) error {
			mu.Lock()
			defer mu.Unlock()
			resource := resources[b]
			if resource == nil {
				return errors.New("exact registered session missing")
			}
			delete(resources, b)
			err := resource.Close()
			barrier <- b
			return err
		}
	})
	other, _ := f.binding()
	unaffected, err := os.Open(f.path)
	must(t, err)
	defer unaffected.Close()
	resources[other] = unaffected
	registered := make(chan *os.File, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		root, err := g.DupVolumeRoot()
		if err != nil {
			return nil, w.Entry{}, err
		}
		mu.Lock()
		resources[b] = root
		mu.Unlock()
		registered <- root
		<-release
		return execFunc(func(*a.Guard, w.Request) (m.Result, error) { return m.Result{}, errors.New("unexpected dispatch") }), rootEntry(), nil
	}
	operation := id(t)
	callbackDone := make(chan error, 1)
	f.s.config.RequestRetirement = func(h a.DataHello, _ error) {
		f.retired <- h
		_, err := f.a.Retire(context.Background(), f.control, a.RetireRequest{Operation: operation, Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch})
		callbackDone <- err
	}
	b, k := f.binding()
	c, done := f.start(b, k)
	defer c.NetConn().Close()
	var owned *os.File
	select {
	case owned = <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("factory did not register")
	}
	if h := retired(t, f.retired); h.Binding != b {
		t.Fatal(h)
	}
	if _, err := owned.Stat(); err != nil {
		t.Fatalf("transport closed registry ownership: %v", err)
	}
	select {
	case <-barrier:
		t.Fatal("barrier ran before setup guard joined")
	case <-done:
		t.Fatal("Serve abandoned registered setup")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	if err := wait(t, done); err == nil {
		t.Fatal("timed out setup succeeded")
	}
	must(t, wait(t, callbackDone))
	if got := <-barrier; got != b {
		t.Fatal(got)
	}
	mu.Lock()
	_, remains := resources[b]
	_, otherRemains := resources[other]
	mu.Unlock()
	if remains || !otherRemains {
		t.Fatalf("wrong session removed: target=%v unrelated=%v", remains, otherRemains)
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("registry root not closed by drain: %v", err)
	}
	if _, err := unaffected.Stat(); err != nil {
		t.Fatalf("unrelated ownership closed: %v", err)
	}
}

// An arbitrary signer must be rejected without invoking either method.
type externalSigner struct{}

func (externalSigner) Public() crypto.PublicKey { panic("external signer invoked") }
func (externalSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("external signer invoked")
}

func TestTLSRejectsExternalSigningAndDynamicCertificateState(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	cases := []struct {
		name   string
		change func(*tls.Config)
	}{
		{"signer", func(c *tls.Config) { c.Certificates[0].PrivateKey = externalSigner{} }},
		{"get_certificate", func(c *tls.Config) {
			c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { panic("callback invoked") }
		}},
		{"verify_connection", func(c *tls.Config) {
			c.VerifyConnection = func(tls.ConnectionState) error { panic("callback invoked") }
		}},
		{"clock", func(c *tls.Config) { c.Time = time.Now }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := f.inputTLS.Clone()
			c.Certificates = append([]tls.Certificate(nil), c.Certificates...)
			tc.change(c)
			_, err := New(Config{TLSConfig: c, ClientRoots: [][]byte{f.ca.Raw}, RequestRetirement: func(a.DataHello, error) {}})
			if !errors.Is(err, ErrConfiguration) {
				t.Fatal(err)
			}
		})
	}
	for _, roots := range [][][]byte{nil, {}, {[]byte("not a certificate")}} {
		_, err := New(Config{TLSConfig: f.inputTLS, ClientRoots: roots, RequestRetirement: func(a.DataHello, error) {}})
		if !errors.Is(err, ErrConfiguration) {
			t.Fatal(err)
		}
	}
}

func TestTLSSnapshotOwnsCertificateKeyAndRoots(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	b, k := f.binding()
	// Prepare independently parsed client roots and its certificate before mutating
	// every caller-owned server identity/root representation after New.
	clientRoots := x509.NewCertPool()
	root, err := x509.ParseCertificate(append([]byte(nil), f.ca.Raw...))
	must(t, err)
	clientRoots.AddCert(root)
	clientCertificate := f.cert(k)
	f.inputTLS.MinVersion = tls.VersionTLS12
	f.inputTLS.MaxVersion = tls.VersionTLS12
	f.inputTLS.ClientAuth = tls.NoClientCert
	clear(f.inputTLS.Certificates[0].Certificate[0])
	clear(f.inputTLS.Certificates[0].PrivateKey.(ed25519.PrivateKey))
	f.ca.PublicKey = key(t).Public()
	clear(f.ca.Raw)
	left, right := net.Pipe()
	defer right.Close()
	client := tls.Client(right, &tls.Config{Certificates: []tls.Certificate{clientCertificate}, RootCAs: clientRoots, ServerName: "storage.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	must(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	done := make(chan error, 1)
	go func() { done <- f.s.Serve(context.Background(), f.a, left) }()
	var hello w.ServerHello
	must(t, w.ReadFrame(client, &hello))
	must(t, w.WriteFrame(client, &w.ClientHello{Authority: a.DataHello{Epoch: hello.Epoch, Binding: b}, Profile: w.RequiredProfile()}))
	var reply w.RootReply
	must(t, w.ReadFrame(client, &reply))
	if client.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("caller changed private TLS config")
	}
	client.NetConn().Close()
	wait(t, done)
}

func TestServeRejectsAlreadyWrappedTLS(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	for _, serverSide := range []bool{false, true} {
		left, right := net.Pipe()
		var wrapped *tls.Conn
		if serverSide {
			wrapped = tls.Server(left, f.s.config.TLSConfig)
		} else {
			wrapped = tls.Client(left, &tls.Config{})
		}
		if err := f.s.Serve(context.Background(), f.a, wrapped); !errors.Is(err, ErrConfiguration) {
			t.Fatal(err)
		}
		right.Close()
	}
}
