package storageclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func testID(n byte) a.ID { return a.ID("00000000-0000-4000-8000-00000000000" + string(n)) }
func testEntry(node w.NodeID, directory bool) w.Entry {
	mode := uint32(0100644)
	if directory {
		mode = 0040755
	}
	return w.Entry{Node: node, Generation: 1, Object: w.ObjectID{byte(node)}, Attr: w.Attr{Ino: uint64(node) + 100, Mode: mode, Nlink: 1, BlockSize: 4096}}
}
func certificate(t *testing.T, ca *x509.Certificate, key ed25519.PrivateKey, server bool) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	use := x509.ExtKeyUsageClientAuth
	name := "client"
	if server {
		use = x509.ExtKeyUsageServerAuth
		name = "server"
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{use}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
func tlsPair(t *testing.T) (Config, *tls.Conn) {
	t.Helper()
	return tlsPairWithClientConn(t, nil)
}

func tlsPairWithClientConn(t *testing.T, wrap func(net.Conn) net.Conn) (Config, *tls.Conn) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	clientCert, serverCert := certificate(t, ca, key, false), certificate(t, ca, key, true)
	cc := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, RootCAs: roots, ServerName: "server", Certificates: []tls.Certificate{clientCert}}
	sc := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, Certificates: []tls.Certificate{serverCert}}
	left, right := net.Pipe()
	if wrap != nil {
		left = wrap(left)
	}
	client, server := tls.Client(left, cc), tls.Server(right, sc)
	t.Cleanup(func() { left.Close(); right.Close() })
	_ = left.SetDeadline(time.Now().Add(3 * time.Second))
	_ = right.SetDeadline(time.Now().Add(3 * time.Second))
	handshake := make(chan error, 1)
	go func() { handshake <- server.Handshake() }()
	if err = client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err = <-handshake; err != nil {
		t.Fatal(err)
	}
	_ = left.SetDeadline(time.Time{})
	_ = right.SetDeadline(time.Time{})
	serverLeaf, _ := x509.ParseCertificate(serverCert.Certificate[0])
	pin, _ := a.PublicKeyFingerprint(serverLeaf.PublicKey)
	clientLeaf, _ := x509.ParseCertificate(clientCert.Certificate[0])
	clientPin, _ := a.PublicKeyFingerprint(clientLeaf.PublicKey)
	binding := a.Binding{Store: testID('1'), Volume: testID('2'), Attachment: testID('3'), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: testID('4'), Key: clientPin, Role: a.RuntimeRole, Mode: a.ReadWrite}
	return Config{Conn: client, TLSConfig: cc, ServerPin: pin, Authority: a.DataHello{Epoch: testID('5'), Binding: binding}, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: 0x1ffffffffff, Limits: DefaultLimits(), Timeout: time.Second, Invalidate: func(context.Context, Notification) error { return nil }}, server
}
func fixture(t *testing.T, change func(*Config), serve func(*tls.Conn)) *Client {
	t.Helper()
	return fixtureWithClientConn(t, nil, change, serve)
}

func fixtureWithClientConn(t *testing.T, wrap func(net.Conn) net.Conn, change func(*Config), serve func(*tls.Conn)) *Client {
	t.Helper()
	cfg, server := tlsPairWithClientConn(t, wrap)
	if change != nil {
		change(&cfg)
	}
	stop := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		if err := w.WriteFrame(server, &w.ServerHello{Epoch: cfg.Authority.Epoch, Version: w.Version, Profile: w.RequiredProfile()}); err != nil {
			return
		}
		var hello w.ClientHello
		if err := w.ReadFrame(server, &hello); err != nil {
			return
		}
		if hello.Authority != cfg.Authority {
			t.Error("changed A-binding")
		}
		if err := w.WriteFrame(server, &w.RootReply{Root: testEntry(99, true)}); err != nil {
			return
		}
		if serve != nil {
			serve(server)
		}
		<-stop
	}()
	c, err := New(cfg)
	if err != nil {
		close(stop)
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); close(stop); <-joined })
	return c
}
func caller(c *Client) Snapshot {
	return Snapshot{owner: c, valid: true, present: true, caller: w.Caller{FSUID: 1000, FSGID: 1000, Groups: []uint32{1000, 1001}, EffectiveCaps: 0}}
}
func none(c *Client) Snapshot { return Snapshot{owner: c, valid: true} }
func rpcServer(s *tls.Conn, handler func(w.Request) w.Reply) {
	for {
		var req w.Request
		if err := w.ReadFrame(s, &req); err != nil {
			return
		}
		reply := handler(req)
		reply.Sequence = req.Sequence
		reply.Op = req.Body.Operation()
		if err := w.WriteFrame(s, &reply); err != nil {
			return
		}
	}
}
func waitTerminal(t *testing.T, c *Client) {
	t.Helper()
	select {
	case <-c.Terminal():
	case <-time.After(3 * time.Second):
		t.Fatal("not terminal")
	}
}

func TestHandshakeSettings(t *testing.T) {
	for _, name := range []string{"pin", "version", "profile", "resume", "key", "nocert", "unverified"} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := tlsPair(t)
			switch name {
			case "pin":
				cfg.ServerPin = a.Fingerprint(strings.Repeat("0", 64))
			case "version":
				cfg.Version = 2
			case "profile":
				cfg.Profile.Reconnect = true
			case "resume":
				cfg.TLSConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			case "key":
				cfg.Authority.Binding.Key = a.Fingerprint(strings.Repeat("0", 64))
			case "nocert":
				cfg.TLSConfig.Certificates[0].Certificate = nil
			case "unverified":
				cfg.TLSConfig.InsecureSkipVerify = true
			}
			if c, err := New(cfg); err == nil {
				c.Close()
				t.Fatal("accepted invalid settings")
			}
		})
	}
}
func TestHandshakeEpochAndTimeout(t *testing.T) {
	for _, mismatch := range []bool{true, false} {
		t.Run(map[bool]string{true: "epoch", false: "timeout"}[mismatch], func(t *testing.T) {
			cfg, server := tlsPair(t)
			cfg.Timeout = 25 * time.Millisecond
			if mismatch {
				go func() {
					_ = w.WriteFrame(server, &w.ServerHello{Epoch: testID('9'), Version: w.Version, Profile: w.RequiredProfile()})
				}()
			}
			if c, err := New(cfg); err == nil {
				c.Close()
				t.Fatal("handshake accepted")
			}
		})
	}
}
func TestFIFOReadOnlyAndCrossSession(t *testing.T) {
	var mu sync.Mutex
	var sequences []uint64
	c := fixture(t, func(cfg *Config) { cfg.Authority.Binding.Mode = a.ReadOnly }, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply {
			mu.Lock()
			sequences = append(sequences, req.Sequence)
			mu.Unlock()
			return w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
		})
	})
	before := c.Authority()
	changed := c.Authority()
	changed.Binding.Mode = a.ReadWrite
	for i := 0; i < 5; i++ {
		if _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); err != nil {
			t.Fatal(err)
		}
	}
	if c.Authority() != before {
		t.Fatal("mutable binding")
	}
	if _, err := c.Do(caller(c), 0, w.OpenRequest{Node: 99, Flags: w.OpenWriteOnly}); !errors.Is(err, w.ErrReadOnly) {
		t.Fatal(err)
	}
	if _, err := c.Do(caller(&Client{}), 0, w.GetAttrRequest{Node: 99}); !errors.Is(err, ErrCredentials) {
		t.Fatal(err)
	}
	if _, err := c.Do(none(c), w.NodeMetadataAuth, w.SetAttrRequest{Node: 99}); err == nil {
		t.Fatal("NONE metadata mutation")
	}
	mu.Lock()
	defer mu.Unlock()
	for i, seq := range sequences {
		if seq != uint64(i+1) {
			t.Fatal(sequences)
		}
	}
}
func TestTransportTerminal(t *testing.T) {
	for _, kind := range []string{"sequence", "operation", "EOF", "timeout", "cross-volume"} {
		t.Run(kind, func(t *testing.T) {
			c := fixture(t, func(cfg *Config) { cfg.Timeout = 50 * time.Millisecond }, func(s *tls.Conn) {
				var req w.Request
				if err := w.ReadFrame(s, &req); err != nil {
					return
				}
				switch kind {
				case "EOF":
					s.NetConn().Close()
				case "timeout":
					return
				case "cross-volume":
					_ = w.WriteFrame(s, &w.Event{EventSequence: 1, Volume: testID('9'), Object: w.ObjectID{1}, Kind: w.InvalidateAttr, Name: []byte{}})
				default:
					reply := w.Reply{Sequence: req.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
					if kind == "sequence" {
						reply.Sequence++
					} else {
						reply.Op = w.OpFlush
						reply.Body = w.FlushReply{}
					}
					_ = w.WriteFrame(s, &reply)
				}
			})
			if _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); err == nil {
				t.Fatal("transport succeeded")
			}
			waitTerminal(t, c)
			if _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); !errors.Is(err, ErrClosed) {
				t.Fatal("replayed", err)
			}
		})
	}
}
func TestBoundedQueueAndJoinedCalls(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	c := fixture(t, func(cfg *Config) { cfg.Limits.Requests = 1 }, func(s *tls.Conn) {
		var req w.Request
		if w.ReadFrame(s, &req) == nil {
			close(entered)
			<-release
			s.NetConn().Close()
		}
	})
	done := make(chan error, 1)
	go func() { _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); done <- err }()
	<-entered
	if _, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("lost admitted completion")
	}
}
