package storageservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

type lifecycleFixture struct {
	s       *LifecycleService
	cfg     Config
	root    ed25519.PrivateKey
	key     p.Key
	initial a.SignedLifecycleGrant
}

func lifecycleSign(t *testing.T, key ed25519.PrivateKey, g a.LifecycleGrant) a.SignedLifecycleGrant {
	t.Helper()
	message, err := a.LifecycleGrantSigningBytes(g)
	must(t, err)
	return a.SignedLifecycleGrant{Grant: g, Signature: ed25519.Sign(key, message)}
}
func newLifecycleServiceFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	path := t.TempDir()
	must(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	must(t, err)
	t.Cleanup(func() { root.Close() })
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	bootstrap, err := p.NewBootstrapPublicKey(pub)
	must(t, err)
	key, err := p.NewControllerKey()
	must(t, err)
	bindingKey, err := p.NewControllerKey()
	must(t, err)
	cfg := Config{Root: root, DeviceUUID: "lifecycle-service-test", Store: id(t), Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
	g := a.LifecycleGrant{Operation: a.LifecycleInitialize, ID: id(t), Identity: a.LifecycleIdentity{Store: cfg.Store, Generation: 7, Binding: fingerprint(t, bindingKey)}, Serial: 1, NewKey: fingerprint(t, key)}
	initial := lifecycleSign(t, private, g)
	s, err := InitializeLifecycle(cfg, initial)
	must(t, err)
	f := &lifecycleFixture{s, cfg, private, key, initial}
	t.Cleanup(func() { must(t, f.s.Close()) })
	return f
}
func lifecycleCSR(t *testing.T, key p.Key, store a.ID, epoch uint64) []byte {
	t.Helper()
	b, err := p.NewControllerBinding(p.StoreID(store), p.ControllerEpoch(epoch))
	must(t, err)
	csr, err := key.CSR(b)
	must(t, err)
	return csr
}
func lifecycleCredential(t *testing.T, f *lifecycleFixture) p.Identity {
	t.Helper()
	r, err := f.s.Ready()
	must(t, err)
	cert, err := f.s.IssueController(lifecycleCSR(t, f.key, r.Store.ID, r.Controller.Epoch))
	must(t, err)
	identity, err := cert.WithKey(f.key)
	must(t, err)
	return identity
}
func lifecycleConnect(t *testing.T, s *LifecycleService, identity p.Identity, epoch uint64) (*c.LifecycleClient, func() error) {
	t.Helper()
	r, err := s.Ready()
	must(t, err)
	m, err := s.Scope()
	must(t, err)
	root, err := p.ParseRootDER(r.TLSRootDER)
	must(t, err)
	raw, join := serve(t, s.ServeLifecycle)
	client, err := c.NewLifecycleClient(context.Background(), raw, c.LifecycleClientConfig{Identity: identity, ServerRoot: root, ServerKey: r.ServerKey, Hello: c.LifecycleHello{Version: c.LifecycleControlVersion, Identity: m.Identity, ServiceEpoch: r.ServiceEpoch, ControllerEpoch: epoch}})
	must(t, err)
	return client, join
}
func lifecycleWorkload(t *testing.T, s *LifecycleService, identity p.Identity) (*c.Client, func() error) {
	t.Helper()
	r, err := s.Ready()
	must(t, err)
	root, err := p.ParseRootDER(r.TLSRootDER)
	must(t, err)
	meta, err := s.Scope()
	must(t, err)
	raw, join := serve(t, s.ServeControl)
	client, err := c.NewPKILifecycleWorkloadClient(context.Background(), raw, c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: root, ServerKey: r.ServerKey, LifecycleIdentity: meta.Identity, ServiceEpoch: r.ServiceEpoch, CurrentController: r.Controller})
	must(t, err)
	return client, join
}

func TestLifecycleServiceSustainedTLSComposition(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	ctx := context.Background()
	identity := lifecycleCredential(t, f)
	current, join := lifecycleConnect(t, f.s, identity, 1)
	grant := f.initial.Grant
	for i := 0; i < 2; i++ {
		_, err := current.Result(ctx, grant, bytes.Repeat([]byte{byte(i)}, 32))
		must(t, err)
	}
	workload, workJoin := lifecycleWorkload(t, f.s, identity)
	created := call(t, workload, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.cfg.Store, Volume: id(t), Name: "managed"}})
	if created.VolumeReceipt.Schema != a.SchemaVersion {
		t.Fatal("workload receipt schema changed")
	}
	query := call(t, workload, c.Request{Query: &c.Empty{}})
	meta, err := f.s.Scope()
	must(t, err)
	if query.Snapshot.Schema != a.LifecycleSchemaVersion || query.LifecycleIdentity == nil || *query.LifecycleIdentity != meta.Identity || query.Snapshot.Controller != meta.Controller || query.Snapshot.Epoch != meta.Epoch || query.Snapshot.Volumes[created.VolumeReceipt.Volume.ID] != created.VolumeReceipt.Volume {
		t.Fatal("workload query lost bound authority snapshot")
	}
	if err := f.s.Close(); !errors.Is(err, a.ErrBusy) {
		t.Fatal("closed active composed service", err)
	}
	for i := 0; i < 65; i++ {
		key, err := p.NewControllerKey()
		must(t, err)
		next := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: grant.Identity, Serial: grant.Serial + 1, ExpectedEpoch: uint64(i + 1), NewKey: fingerprint(t, key)}
		signed := lifecycleSign(t, f.root, next)
		csr := lifecycleCSR(t, key, f.cfg.Store, uint64(i+2))
		if i == 0 {
			for _, change := range []func(*a.LifecycleGrant){
				func(g *a.LifecycleGrant) { g.Identity.Generation++ },
				func(g *a.LifecycleGrant) { g.Identity.Binding = g.NewKey },
				func(g *a.LifecycleGrant) { g.ExpectedEpoch++ },
				func(g *a.LifecycleGrant) { g.Serial = grant.Serial },
				func(g *a.LifecycleGrant) { g.NewKey = grant.NewKey },
			} {
				wrong := next
				change(&wrong)
				if _, err = f.s.AuthorizeSuccessor(lifecycleSign(t, f.root, wrong), csr); err == nil {
					t.Fatal("accepted wrong successor tuple")
				}
			}
			wrongCSR := lifecycleCSR(t, f.key, f.cfg.Store, 2)
			if _, err = f.s.AuthorizeSuccessor(signed, wrongCSR); err == nil {
				t.Fatal("issued successor to wrong CSR key")
			}
		}
		cert, err := f.s.AuthorizeSuccessor(signed, csr)
		must(t, err)
		if i == 0 {
			changed := next
			changed.ID = id(t)
			if _, err = f.s.AuthorizeSuccessor(lifecycleSign(t, f.root, changed), csr); !errors.Is(err, a.ErrConflict) {
				t.Fatal("replaced pending", err)
			}
			bad := signed
			bad.Signature = make([]byte, 64)
			if _, err = f.s.AuthorizeSuccessor(bad, csr); err == nil {
				t.Fatal("bad ROOT accepted")
			}
			if err = f.s.ReconcileController(lifecycleController(next)); !errors.Is(err, a.ErrConflict) {
				t.Fatal("assertion performed takeover", err)
			}
		}
		identity, err = cert.WithKey(key)
		must(t, err)
		successor, successorJoin := lifecycleConnect(t, f.s, identity, uint64(i+2))
		if i == 0 {
			raw, excessJoin := serve(t, f.s.ServeLifecycle)
			if err = excessJoin(); !errors.Is(err, c.ErrLimit) {
				t.Fatal("endpoint replacement escaped shared slots", err)
			}
			raw.Close()
		}
		expected, err := successor.Takeover(ctx, signed)
		must(t, err)
		if _, err = current.Result(ctx, grant, make([]byte, 32)); err == nil {
			t.Fatal("stale live session retained authority")
		}
		if i == 0 {
			if err = f.s.ReconcileController(expected); !errors.Is(err, a.ErrBusy) {
				t.Fatal("replaced active workload endpoint", err)
			}
			if _, err = workload.Call(ctx, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.cfg.Store, Volume: id(t), Name: "stale"}}); err == nil {
				t.Fatal("stale workload mutation")
			}
			workload.Close()
			workJoin()
		}
		endpoint := f.s.endpoint
		must(t, f.s.ReconcileController(expected)) // both lifecycle connections remain live
		if f.s.endpoint != endpoint {
			t.Fatal("reconcile detached the persistent successor endpoint")
		}
		reconciled, reconciledJoin := lifecycleWorkload(t, f.s, identity)
		if got := call(t, reconciled, c.Request{Query: &c.Empty{}}); got.Snapshot.Controller != expected || len(got.Snapshot.Volumes) != 1 {
			t.Fatal("reconciled workload query lost state")
		}
		reconciled.Close()
		reconciledJoin()
		_, err = successor.Result(ctx, next, make([]byte, 32))
		must(t, err)
		current.Close()
		join()
		current, join, grant, f.key = successor, successorJoin, next, key
	}
	retirement := a.LifecycleGrant{Operation: a.LifecycleRetire, ID: id(t), Identity: grant.Identity, Serial: grant.Serial + 1, ExpectedEpoch: 66, NewKey: grant.NewKey}
	signed := lifecycleSign(t, f.root, retirement)
	badRetirement := signed
	badRetirement.Signature = make([]byte, 64)
	if err := f.s.AuthorizeRetirement(badRetirement); err == nil {
		t.Fatal("unsigned retirement accepted")
	}
	must(t, f.s.AuthorizeRetirement(signed)) // no idle-lifecycle requirement
	replacement := retirement
	replacement.ID = id(t)
	if err := f.s.AuthorizeRetirement(lifecycleSign(t, f.root, replacement)); !errors.Is(err, a.ErrConflict) {
		t.Fatal("replaced pending retirement", err)
	}
	// The HostBootFresh child never reconnects after authorization/reconcile.
	// Exercise its existing TLS client rather than hiding policy detachment with
	// a newly connected terminal client.
	must(t, current.Retire(ctx, signed))
	for i := 0; i < 2; i++ {
		_, err := current.Result(ctx, retirement, bytes.Repeat([]byte{byte(i)}, 32))
		must(t, err)
	}
	if _, err = current.Result(ctx, grant, make([]byte, 32)); err == nil {
		t.Fatal("pre-seal result reused after retirement")
	}
	meta, err = f.s.Scope()
	must(t, err)
	if !meta.Sealed || meta.CurrentGrant != grant || meta.RetirementGrant != retirement {
		t.Fatal("wrong terminal metadata")
	}
	if _, err = f.s.IssueController(lifecycleCSR(t, f.key, f.cfg.Store, 66)); err == nil {
		t.Fatal("ordinary credential after seal")
	}
	if err = f.s.Close(); !errors.Is(err, a.ErrBusy) {
		t.Fatal("closed live result connections", err)
	}
	current.Close()
	join()
	must(t, f.s.Close())
	if _, err = OpenLifecycle(f.cfg, grant.Identity, lifecycleSign(t, f.root, grant)); err == nil {
		t.Fatal("opened terminal registry")
	}
}

func TestLifecycleServiceRetirementRequiresOrdinaryAttachmentDrain(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	identity := lifecycleCredential(t, f)
	workload, join := lifecycleWorkload(t, f.s, identity)
	volume := id(t)
	call(t, workload, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.cfg.Store, Volume: volume, Name: "attachment"}})
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	binding := a.Binding{Store: f.cfg.Store, Volume: volume, Attachment: id(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(t), Key: fingerprint(t, key), Role: a.RuntimeRole, Mode: a.ReadWrite}
	call(t, workload, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: binding}})
	r, err := f.s.Ready()
	must(t, err)
	hello := a.DataHello{Epoch: r.ServiceEpoch, Binding: binding}
	pb, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err := key.CSR(pb)
	must(t, err)
	raw, csrJoin := serve(t, f.s.ServeAttachmentCSR)
	_, err = RequestLifecycleAttachmentCertificate(context.Background(), raw, identity, r, f.initial.Grant.Identity, hello, csr)
	must(t, err)
	must(t, csrJoin())
	g := a.LifecycleGrant{Operation: a.LifecycleRetire, ID: id(t), Identity: f.initial.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: f.initial.Grant.NewKey}
	signed := lifecycleSign(t, f.root, g)
	client, lcJoin := lifecycleConnect(t, f.s, identity, 1)
	_, err = client.Result(context.Background(), f.initial.Grant, make([]byte, 32))
	must(t, err)
	must(t, f.s.AuthorizeRetirement(signed))
	if err = client.Retire(context.Background(), signed); err == nil {
		t.Fatal("retired active attachment")
	}
	_, err = workload.Call(context.Background(), c.Request{Retire: &a.RetireRequest{Operation: id(t), Store: binding.Store, Volume: binding.Volume, Attachment: binding.Attachment, Launch: binding.Launch}})
	workload.Close()
	join()
	if runtime.GOOS != "linux" {
		// The real managed resource barrier is ENOSYS here. Never replace it
		// with a fake successful sync or silently claim native drain coverage.
		if err == nil {
			t.Fatal("unsupported resource barrier fabricated drain")
		}
		err = client.Retire(context.Background(), signed)
		var remote *c.RemoteError
		if !errors.As(err, &remote) || remote.Code == c.Unauthorized {
			t.Fatal("failed resource barrier bypassed or arm invisible to persistent client", err)
		}
		t.Logf("persistent client reached unsupported native barrier, not authorization failure: %v", err)
		client.Close()
		lcJoin()
		return
	}
	must(t, err)
	must(t, client.Retire(context.Background(), signed))
	_, err = client.Result(context.Background(), g, make([]byte, 32))
	must(t, err)
	client.Close()
	lcJoin()
}

func lifecycleServiceJournal(t *testing.T, f *lifecycleFixture) map[string]string {
	t.Helper()
	path := filepath.Join(f.cfg.Root.Name(), ".cengine-storage-authority")
	entries, err := os.ReadDir(path)
	must(t, err)
	out := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		must(t, err)
		out[entry.Name()] = string(data)
	}
	return out
}

func TestLifecycleServiceOpenAdmissionPreservesBytesAndEpoch(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	key, err := p.NewControllerKey()
	must(t, err)
	g := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: f.initial.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: fingerprint(t, key)}
	current := lifecycleSign(t, f.root, g)
	cert, err := f.s.AuthorizeSuccessor(current, lifecycleCSR(t, key, f.cfg.Store, 2))
	must(t, err)
	identity, err := cert.WithKey(key)
	must(t, err)
	client, join := lifecycleConnect(t, f.s, identity, 2)
	controller, err := client.Takeover(context.Background(), current)
	must(t, err)
	client.Close()
	join()
	must(t, f.s.ReconcileController(controller))
	before, err := f.s.Scope()
	must(t, err)
	must(t, f.s.Close())
	journal := lifecycleServiceJournal(t, f)
	for name, mutate := range map[string]func(*a.LifecycleGrant){
		"stale-initialize": func(g *a.LifecycleGrant) { *g = f.initial.Grant },
		"grant-id":         func(g *a.LifecycleGrant) { g.ID = id(t) },
		"serial":           func(g *a.LifecycleGrant) { g.Serial++ },
		"controller-epoch": func(g *a.LifecycleGrant) { g.ExpectedEpoch++ },
		"controller-key":   func(g *a.LifecycleGrant) { g.NewKey = f.initial.Grant.NewKey },
		"generation":       func(g *a.LifecycleGrant) { g.Identity.Generation++ },
		"binding":          func(g *a.LifecycleGrant) { g.Identity.Binding = g.NewKey },
		"retirement":       func(g *a.LifecycleGrant) { g.Operation = a.LifecycleRetire },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := g
			mutate(&wrong)
			got, err := OpenLifecycle(f.cfg, wrong.Identity, lifecycleSign(t, f.root, wrong))
			if got != nil || !errors.Is(err, a.ErrConflict) {
				t.Fatalf("wrong grant: service=%v err=%v", got, err)
			}
			if !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
				t.Fatal("rejected lifecycle grant changed journal bytes/E/revision")
			}
		})
	}
	f.s, err = OpenLifecycle(f.cfg, g.Identity, current)
	must(t, err)
	after, err := f.s.Scope()
	must(t, err)
	if after.Epoch == before.Epoch || after.Revision != before.Revision+1 || after.CurrentGrant != g || after.Controller != before.Controller {
		t.Fatal("rejected grant consumed E/revision or valid reopen changed ownership")
	}
	must(t, f.s.Close())
	journal = lifecycleServiceJournal(t, f)
	expected := a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: after.Store.ID, Epoch: after.Epoch, Controller: after.Controller}, OpenRevision: after.OpenRevision}
	for name, mutate := range map[string]func(*a.ExpectedLifecycleStartup){
		"store":         func(e *a.ExpectedLifecycleStartup) { e.Store = id(t) },
		"stale-E":       func(e *a.ExpectedLifecycleStartup) { e.Epoch = before.Epoch },
		"controller":    func(e *a.ExpectedLifecycleStartup) { e.Controller.Epoch++ },
		"key":           func(e *a.ExpectedLifecycleStartup) { e.Controller.Key = f.initial.Grant.NewKey },
		"stale-anchor":  func(e *a.ExpectedLifecycleStartup) { e.OpenRevision = before.OpenRevision },
		"future-anchor": func(e *a.ExpectedLifecycleStartup) { e.OpenRevision++ },
		"max-anchor":    func(e *a.ExpectedLifecycleStartup) { e.OpenRevision = ^uint64(0) },
	} {
		t.Run("predecessor/"+name, func(t *testing.T) {
			wrong := expected
			mutate(&wrong)
			got, err := ReopenLifecycle(f.cfg, g.Identity, current, wrong)
			if got != nil || !errors.Is(err, a.ErrConflict) {
				t.Fatalf("wrong predecessor: service=%v err=%v", got, err)
			}
			if !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
				t.Fatal("rejected lifecycle predecessor changed journal bytes/E/revision")
			}
		})
	}
	for _, missing := range []a.ExpectedLifecycleStartup{
		{ExpectedStartup: expected.ExpectedStartup},
		{ExpectedStartup: expected.ExpectedStartup, OpenRevision: 0},
	} {
		got, err := ReopenLifecycle(f.cfg, g.Identity, current, missing)
		if got != nil || !errors.Is(err, a.ErrInvalid) || !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
			t.Fatal("missing/zero anchor changed persistent evidence", err)
		}
	}
	f.s, err = ReopenLifecycle(f.cfg, g.Identity, current, expected)
	must(t, err)
	next, err := f.s.Scope()
	must(t, err)
	if next.Epoch == expected.Epoch || next.Revision != after.Revision+1 || next.OpenRevision != next.Revision || next.CurrentGrant != g || next.Controller != expected.Controller {
		t.Fatal("guarded reopen did not advance only E/revision")
	}
	must(t, f.s.Close())
	journal = lifecycleServiceJournal(t, f)
	got, err := ReopenLifecycle(f.cfg, g.Identity, current, expected)
	if got != nil || !errors.Is(err, a.ErrConflict) || !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
		t.Fatal("consumed predecessor replay changed persistent evidence", err)
	}
}

func TestLifecycleServiceFreshOpenAndZeroBoundaries(t *testing.T) {
	var zero LifecycleService
	if _, err := zero.Ready(); err == nil {
		t.Fatal("zero ready")
	}
	if _, err := zero.Scope(); err == nil {
		t.Fatal("zero scope")
	}
	if _, err := zero.IssueController(nil); err == nil {
		t.Fatal("zero issue")
	}
	if err := zero.Close(); err == nil {
		t.Fatal("zero close")
	}
	f := newLifecycleServiceFixture(t)
	before, err := f.s.Ready()
	must(t, err)
	before.TLSRootDER[0] ^= 1
	again, err := f.s.Ready()
	must(t, err)
	if bytes.Equal(before.TLSRootDER, again.TLSRootDER) {
		t.Fatal("aliased public root")
	}
	must(t, f.s.Close())
	if _, err = a.OpenLifecycleCurrent(a.Config{Root: f.cfg.Root, DeviceID: f.cfg.DeviceUUID, BootstrapKey: f.cfg.Bootstrap.PublicKey(), Barrier: f.s.owner.resources.Barrier}, a.SignedLifecycleGrant{}); !errors.Is(err, a.ErrInvalid) {
		t.Fatal("unsigned open adopted lifecycle", err)
	}
	wrong := f.initial.Grant.Identity
	wrong.Generation++
	if _, err = OpenLifecycle(f.cfg, wrong, f.initial); err == nil {
		t.Fatal("stale identity accepted")
	}
	bad := f.initial
	bad.Signature = make([]byte, 64)
	if _, err = OpenLifecycle(f.cfg, bad.Grant.Identity, bad); err == nil {
		t.Fatal("bad ROOT accepted on open")
	}
	changed := f.initial.Grant
	changed.ID = id(t)
	if _, err = OpenLifecycle(f.cfg, changed.Identity, lifecycleSign(t, f.root, changed)); err == nil {
		t.Fatal("wrong exact current grant")
	}
	f.s, err = OpenLifecycle(f.cfg, f.initial.Grant.Identity, f.initial)
	must(t, err)
	after, err := f.s.Ready()
	must(t, err)
	if again.ServiceEpoch == after.ServiceEpoch || again.ServerKey == after.ServerKey {
		t.Fatal("reopen did not rotate service")
	}
	legacy := newFixture(t)
	must(t, legacy.s.Close())
	cfg := legacy.cfg
	cfg.Store = f.cfg.Store
	if _, err = OpenLifecycle(cfg, f.initial.Grant.Identity, f.initial); err == nil {
		t.Fatal("adopted v1")
	}
}
