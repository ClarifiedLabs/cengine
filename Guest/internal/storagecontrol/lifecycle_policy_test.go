package storagecontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

func TestLifecycleTLSFrozenSignedOperations(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	cfg := f.sc
	s, e := NewLifecycleServer(f.authority, cfg)
	must(t, e)
	// Constructor snapshots by value, including every nested grant field.
	cfg.SuccessorGrant.ID = id(t)
	cfg.ControllerKey = cfg.SuccessorKey
	old := lifecycleConnect(t, s, f.cc)
	_, e = old.call(context.Background(), lifecycleRequest{Result: &lifecycleResultRequest{f.takeover.Grant, make([]byte, 32)}})
	remote(t, e, Unauthorized)
	next := lifecycleConnect(t, s, f.successor())
	_, e = next.Result(context.Background(), f.retire.Grant, make([]byte, 32))
	remote(t, e, Unauthorized)
	for _, change := range []func(*a.LifecycleGrant){
		func(g *a.LifecycleGrant) { g.ID = id(t) }, func(g *a.LifecycleGrant) { g.Serial++ },
		func(g *a.LifecycleGrant) { g.Identity.Generation++ }, func(g *a.LifecycleGrant) { g.ExpectedEpoch++ },
		func(g *a.LifecycleGrant) { g.NewKey = f.initial.Grant.NewKey },
	} {
		g := f.takeover.Grant
		change(&g)
		signed := lifecycleSign(t, f.bootstrap, g)
		_, e = next.call(context.Background(), lifecycleRequest{Takeover: &signed})
		remote(t, e, Unauthorized)
	}
	_, e = next.Takeover(context.Background(), f.takeover)
	must(t, e)
	for _, change := range []func(*a.LifecycleGrant){
		func(g *a.LifecycleGrant) { g.ID = id(t) }, func(g *a.LifecycleGrant) { g.Serial++ },
		func(g *a.LifecycleGrant) { g.Identity.Generation++ }, func(g *a.LifecycleGrant) { g.ExpectedEpoch++ },
		func(g *a.LifecycleGrant) { g.NewKey = f.initial.Grant.NewKey },
	} {
		g := f.retire.Grant
		change(&g)
		signed := lifecycleSign(t, f.bootstrap, g)
		_, e = next.call(context.Background(), lifecycleRequest{Retire: &signed})
		remote(t, e, Unauthorized)
	}
	bad := f.retire
	bad.Signature = bytes.Repeat([]byte{0}, 64)
	remote(t, next.Retire(context.Background(), bad), Unauthorized)
	_, e = next.Result(context.Background(), f.retire.Grant, make([]byte, 32))
	remote(t, e, Unauthorized)
	must(t, next.Retire(context.Background(), f.retire))
	_, e = next.Result(context.Background(), f.retire.Grant, make([]byte, 32))
	must(t, e)
}

func TestLifecycleTLSRejectsActualDataRole(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	k, e := p.NewAttachmentKey(p.RuntimeRole)
	must(t, e)
	b, e := p.NewAttachmentBinding(p.StoreID(f.cc.Hello.Identity.Store), p.ServiceEpoch(f.cc.Hello.ServiceEpoch), p.AttachmentTuple{Attachment: p.AttachmentID(id(t)), Volume: p.VolumeID(id(t)), Role: p.RuntimeRole, Mode: p.ReadWrite, Container: p.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Launch: p.LaunchID(id(t))})
	must(t, e)
	// Deliberately pin this data key as controller: exact URI role must still fail.
	cfg := f.sc
	cfg.ControllerKey = pkiPin(t, k)
	cfg.CurrentGrant.NewKey = a.Fingerprint(cfg.ControllerKey.String())
	s, e := NewLifecycleServer(f.authority, cfg)
	must(t, e)
	server, e := p.NewServerBinding(p.StoreID(f.cc.Hello.Identity.Store), p.ServiceEpoch(f.cc.Hello.ServiceEpoch))
	must(t, e)
	tc, e := p.ClientTLSConfig(f.issue(k, b), f.cc.ServerRoot, server, f.cc.ServerKey)
	must(t, e)
	raw, worker := lifecycleServe(t, s)
	conn := tls.Client(raw, tc)
	must(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	must(t, conn.HandshakeContext(context.Background()))
	must(t, writeFrame(conn, f.cc.Hello, 4096, &budget{}))
	var h LifecycleHello
	if e = readFrame(conn, &h, 4096, &budget{}); e == nil {
		t.Fatal("trusted data role became controller")
	}
	worker.wait(t)
	if !errors.Is(worker.err, a.ErrUnauthorized) {
		t.Fatal(worker.err)
	}
}

func TestLifecycleTLSRechecksTimeAndBounds(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	binding := f.cc.Identity.Certificate().Binding()
	csr, e := f.controllerKey.CSR(binding)
	must(t, e)
	expiry := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	cert, e := f.issuer.IssueController(csr, binding, f.now, expiry.Sub(f.now))
	must(t, e)
	f.cc.Identity, e = cert.WithKey(f.controllerKey)
	must(t, e)
	s, e := NewLifecycleServer(f.authority, f.sc)
	must(t, e)
	c := lifecycleConnect(t, s, f.cc)
	_, e = c.Result(context.Background(), f.initial.Grant, make([]byte, 32))
	must(t, e)
	time.Sleep(time.Until(expiry) + 10*time.Millisecond)
	_, e = c.Result(context.Background(), f.initial.Grant, make([]byte, 32))
	remote(t, e, Unauthorized)
	c.Close()
	l, e := lifecycleLimits(Limits{})
	must(t, e)
	l.Connections = 1
	l.ReadTimeout = 20 * time.Millisecond
	cfg := f.sc
	cfg.Limits = l
	if _, err := NewLifecycleServer(f.authority, cfg); !errors.Is(err, ErrConfiguration) {
		t.Fatal("successor admitted without a reserved slot", err)
	}
	cfg.SuccessorGrant, cfg.SuccessorKey, cfg.RetireGrant = a.LifecycleGrant{}, p.Fingerprint{}, a.LifecycleGrant{}
	s, e = NewLifecycleServer(f.authority, cfg)
	must(t, e)
	// Use the original, hour-lived current controller credential after expiry.
	f.cc.Identity = f.issue(f.controllerKey, binding)
	raw, worker := lifecycleServe(t, s)
	c, e = NewLifecycleClient(context.Background(), raw, f.cc)
	must(t, e)
	extra, _ := lifecycleServe(t, s)
	if client, e := NewLifecycleClient(context.Background(), extra, f.cc); e == nil {
		client.Close()
		t.Fatal("slot limit bypass")
	}
	c.Close()
	worker.wait(t) // Closing the idle owner releases its bounded slot.
	for _, mutate := range []func(*LifecycleServerConfig){
		func(c *LifecycleServerConfig) { c.Limits.RequestBytes = lifecycleFrameBytes + 1 },
		func(c *LifecycleServerConfig) { c.Limits.OperationTimeout = time.Hour },
		func(c *LifecycleServerConfig) { c.SuccessorGrant.ExpectedEpoch++ },
		func(c *LifecycleServerConfig) { c.SuccessorKey = c.ControllerKey },
		func(c *LifecycleServerConfig) { c.ServiceEpoch = id(t) },
	} {
		bad := cfg
		mutate(&bad)
		if _, e := NewLifecycleServer(f.authority, bad); !errors.Is(e, ErrConfiguration) {
			t.Fatal("invalid config admitted", e)
		}
	}
}
