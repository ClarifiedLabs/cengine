package storageservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	w "dev.cengine/guest/internal/storagewire"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func id(t *testing.T) a.ID { t.Helper(); value, err := a.NewID(); must(t, err); return value }
func fingerprint(t *testing.T, key p.Key) a.Fingerprint {
	t.Helper()
	pin, err := key.Fingerprint()
	must(t, err)
	return a.Fingerprint(pin.String())
}

type fixture struct {
	s          *fixtureService
	cfg        Config
	root       *os.File
	controller p.Key
	bootstrap  ed25519.PrivateKey
	ready      Ready
	identity   p.Identity
}

func newFixture(t *testing.T) *fixture {
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
	cfg := Config{Root: root, DeviceUUID: "native-service-test", Store: id(t), Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
	bindingKey, err := p.NewControllerKey()
	must(t, err)
	current := lifecycleSign(t, private, a.LifecycleGrant{Operation: a.LifecycleInitialize, ID: id(t), Identity: a.LifecycleIdentity{Store: cfg.Store, Generation: 1, Binding: fingerprint(t, bindingKey)}, Serial: 1, NewKey: fingerprint(t, key)})
	owner, err := InitializeLifecycle(cfg, current)
	must(t, err)
	s, err := fixtureOwner(owner, current)
	must(t, err)
	f := &fixture{s: s, cfg: cfg, root: root, controller: key, bootstrap: private}
	t.Cleanup(func() { must(t, s.Close()) })
	f.refresh(t)
	return f
}
func (f *fixture) refresh(t *testing.T) {
	t.Helper()
	var err error
	f.ready, err = f.s.Ready()
	must(t, err)
	b, err := p.NewControllerBinding(p.StoreID(f.ready.Store.ID), p.ControllerEpoch(f.ready.Controller.Epoch))
	must(t, err)
	csr, err := f.controller.CSR(b)
	must(t, err)
	cert, err := f.s.IssueController(csr)
	must(t, err)
	f.identity, err = cert.WithKey(f.controller)
	must(t, err)
}

// TCP rather than net.Pipe avoids TLS close-notify coupling to peer scheduling.
func serve(t *testing.T, worker func(context.Context, net.Conn) error) (net.Conn, func() error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	raw, err := net.Dial("tcp", listener.Addr().String())
	must(t, err)
	peer, err := listener.Accept()
	must(t, err)
	listener.Close()
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- worker(ctx, peer) }()
	var result error
	waited := false
	wait := func() error {
		if !waited {
			select {
			case result = <-done:
				waited = true
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not join")
			}
		}
		return result
	}
	t.Cleanup(func() { raw.Close(); cancel(); wait() })
	return raw, wait
}
func (f *fixture) connect(t *testing.T) (*c.Client, func() error) {
	t.Helper()
	return lifecycleWorkload(t, f.s.lifecycle, f.identity)
}
func call(t *testing.T, client *c.Client, req c.Request) c.Response {
	t.Helper()
	r, err := client.Call(context.Background(), req)
	must(t, err)
	return r
}

func TestExplicitLifecyclePublicReadyAndNativeControl(t *testing.T) {
	f := newFixture(t)
	copy := f.ready
	copy.TLSRootDER[0] ^= 1
	copy.ServerDER[0] ^= 1
	ready, err := f.s.Ready()
	must(t, err)
	if bytes.Equal(copy.TLSRootDER, ready.TLSRootDER) || bytes.Equal(copy.ServerDER, ready.ServerDER) {
		t.Fatal("public metadata aliases owner")
	}
	f.ready = ready
	client, wait := f.connect(t)
	if err := f.s.Close(); !errors.Is(err, a.ErrBusy) {
		t.Fatal("closed active control", err)
	}
	state := call(t, client, c.Request{Query: &c.Empty{}}).Snapshot
	if state.Epoch != ready.ServiceEpoch || state.Store != ready.Store || state.Controller != ready.Controller {
		t.Fatal("authority metadata mismatch")
	}
	client.Close()
	wait()
	must(t, f.s.Close())
	if _, err := f.s.Ready(); !errors.Is(err, a.ErrClosed) {
		t.Fatal(err)
	}
	reopened, err := f.open(f.cfg, ready.Controller)
	must(t, err)
	defer func() { must(t, reopened.Close()) }()
	next, err := reopened.Ready()
	must(t, err)
	if next.ServiceEpoch == ready.ServiceEpoch || bytes.Equal(next.TLSRootDER, ready.TLSRootDER) || next.ServerKey == ready.ServerKey || next.Controller != ready.Controller {
		t.Fatal("Open did not rotate private service generation")
	}
	if _, err := InitializeLifecycle(f.cfg, f.s.current); err == nil {
		t.Fatal("Initialize adopted existing state")
	}
}

func TestMissingOpenNeverInitializes(t *testing.T) {
	f := newFixture(t)
	path := t.TempDir()
	must(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	cfg := f.cfg
	cfg.Root = root
	if _, err = f.open(cfg, f.ready.Controller); !errors.Is(err, a.ErrMissing) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(path, ".cengine-storage-authority")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Open created registry", err)
	}
}

func TestCurrentCSRRejectsAnotherKeyAndScope(t *testing.T) {
	f := newFixture(t)
	other, err := p.NewControllerKey()
	must(t, err)
	for _, kind := range []string{"key", "store", "epoch"} {
		store, epoch, key := f.ready.Store.ID, uint64(1), f.controller
		if kind == "key" {
			key = other
		}
		if kind == "store" {
			store = id(t)
		}
		if kind == "epoch" {
			epoch = 2
		}
		b, err := p.NewControllerBinding(p.StoreID(store), p.ControllerEpoch(epoch))
		must(t, err)
		csr, err := key.CSR(b)
		must(t, err)
		if _, err = f.s.IssueController(csr); err == nil {
			t.Fatal("issued changed " + kind)
		}
	}
}

func TestSignedSuccessorTakeoverRequiresReconnectAndRegistryReconcile(t *testing.T) {
	f := newFixture(t)
	attachment, attachmentKey := f.attachment(t)
	oldIdentity, oldReady := f.identity, f.ready
	next, err := p.NewControllerKey()
	must(t, err)
	binding, err := p.NewControllerBinding(p.StoreID(f.ready.Store.ID), 2)
	must(t, err)
	csr, err := next.CSR(binding)
	must(t, err)
	grant := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: f.s.current.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: fingerprint(t, next)}
	req := lifecycleSign(t, f.bootstrap, grant)
	bad := req
	bad.Signature = make([]byte, 64)
	if _, err = f.s.lifecycle.AuthorizeSuccessor(bad, csr); err == nil {
		t.Fatal("unsigned grant accepted")
	}
	cert, err := f.s.lifecycle.AuthorizeSuccessor(req, csr)
	must(t, err)
	_, err = f.s.lifecycle.AuthorizeSuccessor(req, csr)
	must(t, err)
	changed := grant
	changed.ID = id(t)
	alternate := lifecycleSign(t, f.bootstrap, changed)
	if _, err = f.s.lifecycle.AuthorizeSuccessor(alternate, csr); !errors.Is(err, a.ErrConflict) {
		t.Fatal("pending grant replaced", err)
	}
	expected := a.Controller{Epoch: 2, Key: grant.NewKey}
	if err = f.s.lifecycle.ReconcileController(expected); !errors.Is(err, a.ErrConflict) {
		t.Fatal("daemon assertion advanced generation", err)
	}
	identity, err := cert.WithKey(next)
	must(t, err)
	// Retain an actual old workload connection: it, not the result session,
	// must be joined before the fixed workload endpoint can be replaced.
	oldControl, oldJoin := f.connect(t)
	client, wait := lifecycleConnect(t, f.s.lifecycle, identity, 2)
	if _, err = client.Takeover(context.Background(), alternate); err == nil {
		t.Fatal("alternate signed grant ID consumed")
	}
	before, err := f.s.authority.StartupMetadata()
	must(t, err)
	if before.Controller.Epoch != 1 {
		t.Fatal("alternate grant mutated authority")
	}
	result, err := client.Takeover(context.Background(), req)
	must(t, err)
	if result != expected {
		t.Fatal("wrong successor result")
	}
	if err = f.s.lifecycle.ReconcileController(expected); !errors.Is(err, a.ErrBusy) {
		t.Fatal("overlapping workload endpoint generation", err)
	}
	if _, err = oldControl.Call(context.Background(), c.Request{Query: &c.Empty{}}); err == nil {
		t.Fatal("old controller retained authority")
	}
	oldControl.Close()
	oldJoin()
	must(t, f.s.lifecycle.ReconcileController(expected))
	client.Close()
	wait()
	f.s.current = req
	f.controller = next
	f.refresh(t)
	current, join := f.connect(t)
	state := call(t, current, c.Request{Query: &c.Empty{}}).Snapshot
	if state.Controller != expected {
		t.Fatal("fresh query wrong controller")
	}
	current.Close()
	join()
	if _, err = f.s.lifecycle.AuthorizeSuccessor(req, csr); err == nil {
		t.Fatal("old grant reauthorized")
	}
	attachmentBinding, err := d.AttachmentBinding(attachment)
	must(t, err)
	attachmentCSR, err := attachmentKey.CSR(attachmentBinding)
	must(t, err)
	raw, join := serve(t, f.s.ServeAttachmentCSR)
	if _, err = RequestLifecycleAttachmentCertificate(context.Background(), raw, oldIdentity, oldReady, grant.Identity, attachment, attachmentCSR); err == nil {
		t.Fatal("stale controller obtained attachment credential")
	}
	if join() == nil {
		t.Fatal("credential endpoint accepted stale controller")
	}
}

func (f *fixture) attachment(t *testing.T) (a.DataHello, p.Key) {
	t.Helper()
	client, wait := f.connect(t)
	defer func() { client.Close(); wait() }()
	volume := id(t)
	call(t, client, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.ready.Store.ID, Volume: volume, Name: "data"}})
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	binding := a.Binding{Store: f.ready.Store.ID, Volume: volume, Attachment: id(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(t), Key: fingerprint(t, key), Role: a.RuntimeRole, Mode: a.ReadWrite}
	call(t, client, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: binding}})
	return a.DataHello{Epoch: f.ready.ServiceEpoch, Binding: binding}, key
}
func TestNativeAttachmentCSRChecksRegistryThenTypedDataRejectsWrongURI(t *testing.T) {
	f := newFixture(t)
	hello, key := f.attachment(t)
	binding, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	raw, wait := serve(t, f.s.ServeAttachmentCSR)
	cert, err := RequestLifecycleAttachmentCertificate(context.Background(), raw, f.identity, f.ready, f.s.current.Grant.Identity, hello, csr)
	must(t, err)
	must(t, wait())
	_, err = cert.WithKey(key)
	must(t, err)
	changed := hello
	changed.Binding.Launch = id(t)
	badBinding, err := d.AttachmentBinding(changed)
	must(t, err)
	badCSR, err := key.CSR(badBinding)
	must(t, err)
	raw, wait = serve(t, f.s.ServeAttachmentCSR)
	if _, err = RequestLifecycleAttachmentCertificate(context.Background(), raw, f.identity, f.ready, f.s.current.Grant.Identity, changed, badCSR); err == nil {
		t.Fatal("issued unregistered changed tuple")
	}
	if wait() == nil {
		t.Fatal("server accepted changed tuple")
	}
	// Use the real private test issuer to create a CA-valid same-key wrong-URI
	// attacker credential. Production exposes no issuer or generic Issue method.
	badCert, err := f.s.issuer.IssueAttachment(badCSR, badBinding, f.cfg.Now, f.cfg.Lifetime)
	must(t, err)
	badIdentity, err := badCert.WithKey(key)
	must(t, err)
	root, err := p.ParseRootDER(f.ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(f.ready.Store.ID), p.ServiceEpoch(f.ready.ServiceEpoch))
	must(t, err)
	cfg, err := p.ClientTLSConfig(badIdentity, root, server, f.ready.ServerKey)
	must(t, err)
	raw, wait = serve(t, f.s.ServeData)
	conn := tls.Client(raw, cfg)
	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	must(t, conn.Handshake())
	var greeting w.ServerHello
	must(t, w.ReadFrame(conn, &greeting))
	must(t, w.WriteFrame(conn, &w.ClientHello{Authority: hello, Profile: w.RequiredProfile()}))
	var reply w.RootReply
	if err = w.ReadFrame(conn, &reply); err == nil {
		t.Fatal("wrong full URI admitted")
	}
	raw.Close()
	if wait() == nil {
		t.Fatal("data server accepted wrong URI")
	}
	select {
	case <-f.s.Notifications():
		t.Fatal("unauthenticated attacker generated retirement")
	default:
	}
	client, join := f.connect(t)
	state := call(t, client, c.Request{Query: &c.Empty{}}).Snapshot
	client.Close()
	join()
	if state.Attachments[hello.Binding.Attachment].Phase != a.Active {
		t.Fatal("invalid data TLS changed authority")
	}
}

func TestNativeDataFailureNotifiesWithoutRetiring(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native unsupported managed setup, not Linux ext4 coverage")
	}
	f := newFixture(t)
	hello, key := f.attachment(t)
	binding, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	raw, wait := serve(t, f.s.ServeAttachmentCSR)
	cert, err := RequestLifecycleAttachmentCertificate(context.Background(), raw, f.identity, f.ready, f.s.current.Grant.Identity, hello, csr)
	must(t, err)
	must(t, wait())
	identity, err := cert.WithKey(key)
	must(t, err)
	root, err := p.ParseRootDER(f.ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(f.ready.Store.ID), p.ServiceEpoch(f.ready.ServiceEpoch))
	must(t, err)
	cfg, err := p.ClientTLSConfig(identity, root, server, f.ready.ServerKey)
	must(t, err)
	// Model a full, unconsumed notification backlog; the next actual TLS
	// failure must keep its worker charged until the host accepts that notice.
	for i := 0; i < cap(f.s.notifications); i++ {
		f.s.notifications <- RetirementNotification{Hello: hello}
	}
	raw, wait = serve(t, f.s.ServeData)
	conn := tls.Client(raw, cfg)
	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	must(t, conn.Handshake())
	var greeting w.ServerHello
	must(t, w.ReadFrame(conn, &greeting))
	must(t, w.WriteFrame(conn, &w.ClientHello{Authority: hello, Profile: w.RequiredProfile()}))
	var reply w.RootReply
	if err = w.ReadFrame(conn, &reply); err == nil {
		t.Fatal("Darwin fabricated Linux managed setup")
	}
	raw.Close()
	if err := f.s.Close(); !errors.Is(err, a.ErrBusy) {
		t.Fatal("full notification queue released DATA worker", err)
	}
	for i := 0; i < cap(f.s.notifications); i++ {
		<-f.s.Notifications()
	}
	if wait() == nil {
		t.Fatal("missing setup failure")
	}
	select {
	case notice := <-f.s.Notifications():
		if notice.Hello != hello {
			t.Fatal("notification lost exact binding")
		}
	case <-time.After(time.Second):
		t.Fatal("missing retirement notification")
	}
	client, join := f.connect(t)
	state := call(t, client, c.Request{Query: &c.Empty{}}).Snapshot
	client.Close()
	join()
	record := state.Attachments[hello.Binding.Attachment]
	if record.Phase != a.Active || record.Receipt != nil {
		t.Fatal("socket loss or notification fabricated drain")
	}
	if !f.s.resources.Idle() {
		t.Fatal("failed setup retained resources")
	}
}

func TestCredentialFrameBoundsAndCanonicalNumbers(t *testing.T) {
	for _, payload := range []string{`{"version":1,"version":1,"certificate":null}`, `{"version":1,"certificate":null,"other":0}`, `{"version":1.0,"certificate":null}`} {
		var stream bytes.Buffer
		var head [4]byte
		binary.BigEndian.PutUint32(head[:], uint32(len(payload)))
		stream.Write(head[:])
		stream.WriteString(payload)
		var out attachmentCSRReply
		if readCredential(&stream, &out) == nil {
			t.Fatal("accepted noncanonical frame")
		}
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], credentialFrameLimit+1)
	var out attachmentCSRReply
	if readCredential(bytes.NewReader(head[:]), &out) == nil {
		t.Fatal("accepted oversized frame")
	}
}
