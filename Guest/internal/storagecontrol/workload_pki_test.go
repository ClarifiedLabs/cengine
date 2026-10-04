package storagecontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// Bypass constructor prechecks with CA-trusted peers to exercise the actual
// workload server's URI, role, and key policy, not merely client validation.
func TestWorkloadPKIServerRejectsScopeRolesAndKeys(t *testing.T) {
	for _, kind := range []string{"store", "epoch", "key", "data-role"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureFor(t, Limits{}, nil)
			cc := f.config()
			identity := cc.Identity
			binding := identity.Certificate().Binding()
			switch kind {
			case "store":
				binding, _ = p.NewControllerBinding(p.StoreID(id(t)), 1)
				identity = f.issue(f.controllerKey, binding)
			case "epoch":
				binding, _ = p.NewControllerBinding(p.StoreID(f.store), 2)
				identity = f.issue(f.controllerKey, binding)
			case "key":
				identity = f.issue(f.successorKey, binding)
			case "data-role":
				k, err := p.NewAttachmentKey(p.RuntimeRole)
				must(t, err)
				binding, err = p.NewAttachmentBinding(p.StoreID(f.store), p.ServiceEpoch(cc.ServiceEpoch), p.AttachmentTuple{Attachment: p.AttachmentID(id(t)), Volume: p.VolumeID(id(t)), Role: p.RuntimeRole, Mode: p.ReadWrite, Container: p.ContainerID(strings.Repeat("a", 64)), Launch: p.LaunchID(id(t))})
				must(t, err)
				identity = f.issue(k, binding)
			}
			raw, worker := servePKI(t, f.server)
			server, err := p.NewServerBinding(p.StoreID(f.store), p.ServiceEpoch(cc.ServiceEpoch))
			must(t, err)
			var conn *tls.Conn
			if kind == "data-role" {
				cfg, err := p.ClientTLSConfig(identity, cc.ServerRoot, server, cc.ServerKey)
				must(t, err)
				conn = tls.Client(raw, cfg)
			} else {
				conn, err = p.NewControllerTLSClient(raw, identity, cc.ServerRoot, server, cc.ServerKey)
				must(t, err)
			}
			must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
			must(t, conn.HandshakeContext(context.Background()))
			must(t, writeFrame(conn, f.hello(), 4096, &budget{}))
			var reply HelloReply
			if err := readFrame(conn, &reply, 4096, &budget{}); err == nil && reply.Error == "" {
				t.Fatal("invalid peer admitted")
			}
			raw.Close()
			if worker.wait(t) == nil {
				t.Fatal("server accepted invalid peer")
			}
		})
	}
}

func TestWorkloadPKIClientRejectsSameKeyWrongServerScope(t *testing.T) {
	for _, kind := range []string{"store", "service", "pin"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			sc, cc := workloadConfigs(f)
			store, epoch := p.StoreID(cc.LifecycleIdentity.Store), p.ServiceEpoch(cc.ServiceEpoch)
			if kind == "store" {
				store = p.StoreID(id(t))
			}
			if kind == "service" {
				epoch = p.ServiceEpoch(id(t))
			}
			binding, err := p.NewServerBinding(store, epoch)
			must(t, err)
			k := f.serverKey
			if kind == "pin" {
				k, err = p.NewServerKey()
				must(t, err)
			}
			cfg, err := p.ServerTLSConfig(f.issue(k, binding), sc.ClientRoot)
			must(t, err)
			left, right := tcpPair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer left.Close()
				conn := tls.Server(left, cfg)
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = conn.HandshakeContext(context.Background())
			}()
			if client, err := NewPKILifecycleWorkloadClient(context.Background(), right, cc); err == nil {
				client.Close()
				t.Error("wrong server accepted")
			}
			right.Close()
			<-done
		})
	}
}

func TestWorkloadPKIConfigurationIsolation(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	sc, cc := workloadConfigs(f)
	server, err := NewPKILifecycleWorkloadServer(f.authority, sc)
	must(t, err)
	binding, err := p.NewServerBinding(p.StoreID(cc.LifecycleIdentity.Store), p.ServiceEpoch(cc.ServiceEpoch))
	must(t, err)
	if cfg, err := p.ClientTLSConfig(cc.Identity, cc.ServerRoot, binding, cc.ServerKey); !errors.Is(err, p.ErrInvalid) || cfg != nil {
		t.Fatal("controller credential-bearing TLS config exported")
	}
	cfg, err := p.ServerTLSConfig(sc.Identity, sc.ClientRoot)
	must(t, err)
	der, root := sc.Identity.Certificate().DER(), sc.ClientRoot.DER()
	sc = PKILifecycleWorkloadServerConfig{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			clear(der)
			clear(root)
			clear(cfg.Certificates[0].PrivateKey.(ed25519.PrivateKey))
			clear(cfg.Certificates[0].Certificate[0])
			cfg.ClientCAs = nil
		}
	}()
	raw, worker := servePKI(t, server)
	client, err := NewPKILifecycleWorkloadClient(context.Background(), raw, cc)
	must(t, err)
	cc = PKILifecycleWorkloadClientConfig{}
	call(t, client, Request{Query: &Empty{}})
	client.Close()
	worker.wait(t)
	<-done
}

func TestWorkloadPKIClientRejectsMetadataAndClosesRaw(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	_, cc := workloadConfigs(f)
	for _, change := range []func(*PKILifecycleWorkloadClientConfig){
		func(c *PKILifecycleWorkloadClientConfig) { c.LifecycleIdentity.Store = id(t) },
		func(c *PKILifecycleWorkloadClientConfig) { c.LifecycleIdentity.Generation = 0 },
		func(c *PKILifecycleWorkloadClientConfig) { c.ServiceEpoch = "invalid" },
		func(c *PKILifecycleWorkloadClientConfig) { c.CurrentController.Epoch++ },
		func(c *PKILifecycleWorkloadClientConfig) { c.CurrentController.Key = f.takeover.Grant.NewKey },
		func(c *PKILifecycleWorkloadClientConfig) { c.Identity = f.sc.Identity },
	} {
		config := cc
		change(&config)
		left, right := net.Pipe()
		if client, err := NewPKILifecycleWorkloadClient(context.Background(), right, config); !errors.Is(err, ErrConfiguration) {
			if client != nil {
				client.Close()
			}
			t.Fatal("bad client metadata accepted", err)
		}
		_ = left.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := left.Read(b[:]); err == nil {
			t.Fatal("failed constructor did not close raw")
		}
		left.Close()
	}
}

func TestWorkloadTLSRejectsDualRoleLeaves(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	cert, err := x509.ParseCertificate(f.sc.Identity.Certificate().DER())
	must(t, err)
	cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	if validLeaf(cert, x509.ExtKeyUsageServerAuth) || validLeaf(cert, x509.ExtKeyUsageClientAuth) {
		t.Fatal("dual-role leaf accepted")
	}
}

func TestLifecycleTakeoverFencesWorkloadAndRequiresFreshPolicy(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	old, worker, err := f.connectWorker(f.server, f.config())
	must(t, err)
	lifecycle, err := NewLifecycleServer(f.authority, f.sc)
	must(t, err)
	successor := lifecycleConnect(t, lifecycle, f.successor())
	controller, err := successor.Takeover(context.Background(), f.takeover)
	must(t, err)
	_, err = old.Call(context.Background(), Request{Query: &Empty{}})
	remote(t, err, Unauthorized)
	old.Close()
	worker.wait(t)
	if client, err := f.connect(f.config()); err == nil {
		client.Close()
		t.Fatal("stale workload hello admitted")
	}
	sc, cc := workloadConfigs(f.lifecycleFixture)
	sc.CurrentController, cc.CurrentController = controller, controller
	cc.Identity = f.successor().Identity
	server, err := NewPKILifecycleWorkloadServer(f.authority, sc)
	must(t, err)
	raw, freshWorker := servePKI(t, server)
	fresh, err := NewPKILifecycleWorkloadClient(context.Background(), raw, cc)
	must(t, err)
	if call(t, fresh, Request{Query: &Empty{}}).Snapshot.Controller != (a.Controller{Epoch: 2, Key: f.takeover.Grant.NewKey}) {
		t.Fatal("fresh policy did not observe successor")
	}
	fresh.Close()
	freshWorker.wait(t)
}
