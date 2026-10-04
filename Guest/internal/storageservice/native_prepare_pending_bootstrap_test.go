//go:build cengine_native_faulttest

package storageservice

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

// Actual service PKI/control/CSR plus authority authentication on the host. This
// proves bootstrap epoch ordering, not ext4 provision, native crash or FUSE replay.
func TestNativePendingBootstrapIssuesOnlyAfterReopen(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	meta, err := f.s.Scope()
	must(t, err)
	expected := a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: meta.Store.ID, Epoch: meta.Epoch, Controller: meta.Controller}, OpenRevision: meta.OpenRevision}
	must(t, f.s.Close())
	f.s, err = ReopenLifecycle(f.cfg, meta.Identity, f.initial, expected)
	must(t, err)
	t.Cleanup(func() { must(t, f.s.Close()) })
	ready, err := f.s.Ready()
	must(t, err)
	if ready.ServiceEpoch == expected.Epoch || ready.Controller != expected.Controller {
		t.Fatal("wrong initial reopen")
	}
	controllerBinding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	must(t, err)
	csr, err := f.key.CSR(controllerBinding)
	must(t, err)
	cert, err := f.s.IssueController(csr)
	must(t, err)
	identity, err := cert.WithKey(f.key)
	must(t, err)
	root, err := p.ParseRootDER(ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	must(t, err)
	raw, done := pendingProtocolPair(t, f.s.ServeControl)
	client, err := c.NewPKILifecycleWorkloadClient(context.Background(), raw, c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: root, ServerKey: ready.ServerKey, LifecycleIdentity: meta.Identity, ServiceEpoch: ready.ServiceEpoch, CurrentController: ready.Controller})
	must(t, err)
	call := func(req c.Request) c.Response {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		response, err := client.Call(ctx, req)
		must(t, err)
		return response
	}
	volume, prepare := id(t), id(t)
	call(c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: ready.Store.ID, Volume: volume, Name: "pending"}})
	key, err := p.NewAttachmentKey(p.PrepareRole)
	must(t, err)
	hello := a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: id(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(t), Key: fingerprint(t, key), Role: a.PrepareRole, Mode: a.ReadWrite, Prepare: prepare}}
	call(c.Request{ReservePrepare: &a.ReserveRequest{Operation: id(t), Prepare: prepare, Attachments: []a.Binding{hello.Binding}}})
	call(c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: hello.Binding}})
	binding, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err = key.CSR(binding)
	must(t, err)
	rawCSR, csrDone := pendingProtocolPair(t, f.s.ServeAttachmentCSR)
	issued, err := RequestLifecycleAttachmentCertificate(context.Background(), rawCSR, identity, ready, meta.Identity, hello, csr)
	must(t, err)
	must(t, csrDone())
	attachment, err := issued.WithKey(key)
	must(t, err)
	must(t, client.Close())
	if err := done(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal("control bootstrap did not close cleanly", err)
	}
	authenticate := func(h a.DataHello) error {
		cfg, err := p.ServerTLSConfig(f.s.owner.identity, f.s.owner.issuer.Root())
		must(t, err)
		raw, join := pendingProtocolPair(t, func(ctx context.Context, raw net.Conn) error {
			principal, err := f.s.owner.authority.AuthenticateData(ctx, tls.Server(raw, cfg), h)
			if err != nil {
				return err
			}
			guard, err := f.s.owner.authority.Admit(principal, h.Binding.Volume, true)
			if err == nil {
				guard.Release()
			}
			return err
		})
		cfgClient, err := p.ClientTLSConfig(attachment, root, server, ready.ServerKey)
		must(t, err)
		conn := tls.Client(raw, cfgClient)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		must(t, conn.HandshakeContext(ctx))
		defer conn.Close()
		return join()
	}
	stale := hello
	stale.Epoch = expected.Epoch
	if err := authenticate(stale); !errors.Is(err, a.ErrUnauthorized) {
		t.Fatal("stale epoch admitted", err)
	}
	must(t, authenticate(hello))
	// The bug's original ordering must stay fenced; changing Hello.Epoch cannot
	// reactivate the same old issued A after another genuine service reopen.
	meta, err = f.s.Scope()
	must(t, err)
	must(t, f.s.Close())
	f.s, err = ReopenLifecycle(f.cfg, meta.Identity, f.initial, a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: ready.Store.ID, Epoch: ready.ServiceEpoch, Controller: ready.Controller}, OpenRevision: meta.OpenRevision})
	must(t, err)
	current, err := f.s.Ready()
	must(t, err)
	// Lower-authority TLS key possession deliberately trusts the retained issued
	// certificate, just as the failed native setup did; attachment state still wins.
	root, err = p.ParseRootDER(current.TLSRootDER)
	must(t, err)
	server, err = p.NewServerBinding(p.StoreID(current.Store.ID), p.ServiceEpoch(current.ServiceEpoch))
	must(t, err)
	oldRoot, err := p.ParseRootDER(ready.TLSRootDER)
	must(t, err)
	cfg, err := p.ServerTLSConfig(f.s.owner.identity, oldRoot)
	must(t, err)
	hello.Epoch = current.ServiceEpoch
	raw, join := pendingProtocolPair(t, func(ctx context.Context, raw net.Conn) error {
		principal, err := f.s.owner.authority.AuthenticateData(ctx, tls.Server(raw, cfg), hello)
		if principal != nil {
			t.Error("retiring attachment got principal")
		}
		return err
	})
	cfgClient, err := p.ClientTLSConfig(attachment, root, server, current.ServerKey)
	must(t, err)
	conn := tls.Client(raw, cfgClient)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	must(t, conn.HandshakeContext(ctx))
	if err := join(); !errors.Is(err, a.ErrBlocked) {
		t.Fatal("reopened old A was reactivated", err)
	}
}

func pendingProtocolPair(t *testing.T, serve func(context.Context, net.Conn) error) (net.Conn, func() error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, err)
	defer listener.Close()
	must(t, listener.SetDeadline(time.Now().Add(3*time.Second)))
	client, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	must(t, err)
	peer, err := listener.Accept()
	must(t, err)
	done := make(chan error, 1)
	go func() { defer peer.Close(); done <- serve(context.Background(), peer) }()
	waited := false
	var result error
	join := func() error {
		if !waited {
			select {
			case result = <-done:
				waited = true
			case <-time.After(5 * time.Second):
				t.Fatal("pending protocol worker not joined")
			}
		}
		return result
	}
	t.Cleanup(func() { client.Close(); peer.Close(); _ = join() })
	return client, join
}
