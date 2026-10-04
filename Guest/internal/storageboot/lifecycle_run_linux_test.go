//go:build linux

package storageboot

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
	"dev.cengine/guest/internal/vsock"
)

// TCP sockets test composition only. They do not establish native CID provenance.
type lifecycleTestListener struct {
	net.Listener
	peer net.Addr
}

func (l lifecycleTestListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return addressed{conn, l.peer}, nil
}
func lifecycleSocket(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}
func lifecycleDial(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func TestLifecyclePlatformRejectsBeforeHello(t *testing.T) {
	for _, peer := range []net.Addr{vsock.Addr{CID: 3}, &vsock.Addr{CID: 2}, stringPeer("2:4106"), &net.TCPAddr{}, nil} {
		l := lifecycleTestListener{lifecycleSocket(t), peer}
		done := make(chan error, 1)
		go func() { _, err := acceptLifecycleHost(context.Background(), l); done <- err }()
		conn := lifecycleDial(t, l)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if n, err := conn.Read(b[:]); n != 0 || err == nil {
			t.Fatal("hello before CID authentication")
		}
		if err := <-done; !errors.Is(err, a.ErrUnauthorized) {
			t.Fatal(err)
		}
	}
}
func TestLifecyclePlatformAcceptCancellation(t *testing.T) {
	l := lifecycleSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := acceptLifecycleHost(ctx, l); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept not interrupted")
	}
}
func TestLifecyclePlatformNoActivationForInvalidOrRepeatedBoot(t *testing.T) {
	var attempt atomic.Bool
	listen := func(uint32) (net.Listener, error) {
		t.Error("invalid boot activated listener")
		return nil, errors.New("unexpected")
	}
	for i := 0; i < 2; i++ {
		if runLifecycle(context.Background(), diskbootstrap.VerifiedBootResult{}, "127.0.0.1", &attempt, listen, net.Listen) == nil {
			t.Fatal("unverified/repeated boot accepted")
		}
	}
	if !attempt.Load() {
		t.Fatal("attempt not consumed")
	}
	var canceled atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(runLifecycle(ctx, diskbootstrap.VerifiedBootResult{}, "127.0.0.1", &canceled, listen, net.Listen), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if LifecyclePort != 4117 || LifecyclePort == Port || LifecyclePort == ControlPort || LifecyclePort == CSRPort {
		t.Fatal("port collision")
	}
}
func TestLifecyclePlatformSocketComposition(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cfg, key := lifecycleTestConfig(t)
	cfg.NowUnixSeconds = uint64(time.Now().Add(-time.Minute).Unix())
	service, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listeners := map[uint32]net.Listener{}
	var data net.Listener
	stop, err := startLifecycleServices(ctx, cancel, service, "127.0.0.1:2049", func(port uint32) (net.Listener, error) {
		l := lifecycleTestListener{lifecycleSocket(t), vsock.Addr{CID: 2}}
		listeners[port] = l
		return l, nil
	}, func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != "127.0.0.1:2049" {
			t.Fatal("wrong DATA address")
		}
		data = lifecycleSocket(t)
		return data, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	}()
	ready, err := service.Ready()
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := p.NewControllerBinding(p.StoreID(cfg.Signed.Grant.Identity.Store), 1)
	csr, _ := key.CSR(binding)
	cert, err := service.IssueController(csr)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := cert.WithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := p.ParseRootDER(ready.TLSRootDER)
	if err != nil {
		t.Fatal(err)
	}
	client, err := c.NewLifecycleClient(ctx, lifecycleDial(t, listeners[LifecyclePort]), c.LifecycleClientConfig{Identity: identity, ServerRoot: ca, ServerKey: ready.ServerKey, Hello: c.LifecycleHello{Version: c.LifecycleControlVersion, Identity: cfg.Signed.Grant.Identity, ServiceEpoch: ready.ServiceEpoch, ControllerEpoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Result(ctx, cfg.Signed.Grant, bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	control, err := c.NewPKILifecycleWorkloadClient(ctx, lifecycleDial(t, listeners[ControlPort]), c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: ca, ServerKey: ready.ServerKey, LifecycleIdentity: cfg.Signed.Grant.Identity, ServiceEpoch: ready.ServiceEpoch, CurrentController: ready.Controller})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if response, err := control.Call(ctx, c.Request{Query: &c.Empty{}}); err != nil || response.Snapshot == nil || response.Snapshot.Schema != a.LifecycleSchemaVersion {
		t.Fatal("v3 workload query", err)
	}
	// Leave real CSR/DATA TLS handshakes idle. Stop must close these too, along
	// with authenticated persistent lifecycle/workload sessions and all listeners.
	csrRaw, dataRaw := lifecycleDial(t, listeners[CSRPort]), lifecycleDial(t, data)
	if err = stop(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []net.Conn{csrRaw, dataRaw} {
		_ = raw.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err = raw.Read(b[:]); err == nil {
			t.Fatal("raw transport not closed")
		}
	}
}
func TestLifecyclePlatformBoundedWorkersAndStop(t *testing.T) {
	l := lifecycleSocket(t)
	entered := make(chan struct{}, lifecycleConnectionLimit+1)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	stop := serveLifecycleEndpoints(context.Background(), func() {}, []lifecycleEndpoint{{l, false, func(context.Context, net.Conn) error { entered <- struct{}{}; <-release; return nil }}}, 20*time.Millisecond)
	for i := 0; i < lifecycleConnectionLimit; i++ {
		lifecycleDial(t, l)
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("worker missing")
		}
	}
	excess := lifecycleDial(t, l)
	_ = excess.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := excess.Read(b[:]); err == nil {
		t.Fatal("unbounded admission")
	}
	if err := stop(); !errors.Is(err, a.ErrBusy) {
		t.Fatal("blocked worker reported success", err)
	}
	once.Do(func() { close(release) })
}
func TestLifecyclePlatformBindFailureClosesEarlierListeners(t *testing.T) {
	first := lifecycleSocket(t)
	_, err := startLifecycleServices(context.Background(), func() {}, &s.LifecycleService{}, "127.0.0.1:0", func(port uint32) (net.Listener, error) {
		if port == LifecyclePort {
			return first, nil
		}
		return nil, errors.New("bind")
	}, net.Listen, time.Second)
	if err == nil {
		t.Fatal("bind failure succeeded")
	}
	if conn, err := net.DialTimeout("tcp", first.Addr().String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("listener leaked")
	}
}
