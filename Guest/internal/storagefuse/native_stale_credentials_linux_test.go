//go:build linux && (amd64 || arm64)

package storagefuse_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// This is a component test, not a VM/recovery or physical-power-loss claim.
// It needs real ext4, Linux identity capabilities, and the managed metadata
// session kernel ABI (/dev/fuse). Ordinary nonroot tests skip; the fixed native
// acceptance runner requires root and rejects every skip. Root runs require the
// explicit disposable /scratch profile, never the host's default temp directory.
func TestNativeIssuedDataTLSRejectsRetiredAndPreviousServiceCredentials(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root in the disposable managed-FUSE kernel fixture")
	}
	if filepath.Clean(os.TempDir()) != "/scratch" {
		t.Fatal("set TMPDIR=/scratch; the native fixture never uses the host's default temp directory")
	}
	var uts unix.Utsname
	staleMust(t, unix.Uname(&uts))
	if !strings.HasPrefix(string(bytes.TrimRight(uts.Release[:], "\x00")), "6.18.") {
		t.Fatal("requires the patched Linux 6.18 kernel")
	}
	var fs unix.Statfs_t
	staleMust(t, unix.Statfs("/scratch", &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("/scratch must be actual ext4")
	}
	path, err := os.MkdirTemp("/scratch", "storagefuse-stale-credentials-")
	staleMust(t, err)
	// Registered first, so all DATA/control joins and service/root closes run
	// before removal. Any assertion or teardown failure retains private evidence.
	t.Cleanup(func() {
		if !t.Failed() {
			staleMust(t, os.RemoveAll(path))
		}
	})
	staleMust(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	staleMust(t, err)
	t.Cleanup(func() { staleMust(t, root.Close()) })
	public, rootKey, err := ed25519.GenerateKey(rand.Reader)
	staleMust(t, err)
	bootstrap, err := p.NewBootstrapPublicKey(public)
	staleMust(t, err)
	controllerKey, err := p.NewControllerKey()
	staleMust(t, err)
	cfg := s.Config{Root: root, DeviceUUID: "stale-data-tls-test", Store: staleID(t), Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
	current := staleLifecycleGrant(t, rootKey, cfg.Store, controllerKey)
	service, err := s.InitializeLifecycle(cfg, current)
	staleMust(t, err)
	t.Cleanup(func() { staleMust(t, service.Close()) })
	ready, err := service.Ready()
	staleMust(t, err)
	controller, control, closeControl := staleControl(t, service, ready, controllerKey)
	volume := staleID(t)
	staleCall(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: staleID(t), Store: ready.Store.ID, Volume: volume, Name: "data"}})

	// The workload owns this generated key; only its CSR crosses the real
	// authenticated credential endpoint. Retain the exact issued identity.
	hello, oldIdentity, retireOld := staleAttachment(t, service, ready, controller, control, volume)
	conn, join := staleDataTLS(t, service, ready, oldIdentity, false)
	staleAdmit(t, conn, hello)
	staleCreate(t, conn, 1, "before-retire")
	staleExists(t, path, "before-retire")
	retireOld()
	before := staleCall(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	if before.Epoch != hello.Epoch || before.Attachments[hello.Binding.Attachment].Phase != a.Drained {
		t.Fatal("retirement did not retain the same service epoch and drain the attachment")
	}

	// The already authenticated connection must recheck admission for each RPC.
	request := staleCreateRequest(2, "retired-live")
	staleMust(t, w.WriteFrame(conn, &request))
	staleRejectRead(t, conn)
	if err := join(); !errors.Is(err, a.ErrBlocked) {
		t.Fatalf("retired live connection: want server admission ErrBlocked, got %v", err)
	}
	staleAbsent(t, path, "retired-live")

	// A new TCP/TLS connection with that same valid certificate must also fail
	// registry authentication, not TLS validation or the one-connection conflict.
	replay, replayJoin := staleDataTLS(t, service, ready, oldIdentity, false)
	var greeting w.ServerHello
	staleMust(t, w.ReadFrame(replay, &greeting))
	if greeting.Epoch != hello.Epoch {
		t.Fatal("same-E replay reached a different generation")
	}
	staleAttempt(t, replay, hello, "retired-reconnect")
	staleRejectRead(t, replay)
	if err := replayJoin(); !errors.Is(err, a.ErrBlocked) {
		t.Fatalf("retired reconnect: want server authentication ErrBlocked, got %v", err)
	}
	staleAbsent(t, path, "retired-reconnect")
	after := staleCall(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	if after.Revision != before.Revision || after.Attachments[hello.Binding.Attachment].Phase != a.Drained {
		t.Fatal("retired credential changed the authority registry")
	}
	predecessor := staleLifecyclePredecessor(t, service, current)
	closeControl()
	staleMust(t, service.Close())

	next, err := s.ReopenLifecycle(cfg, predecessor.Identity, predecessor.Current, predecessor.Expected)
	staleMust(t, err)
	t.Cleanup(func() { staleMust(t, next.Close()) })
	nextReady, err := next.Ready()
	staleMust(t, err)
	if nextReady.ServiceEpoch == ready.ServiceEpoch || bytes.Equal(nextReady.TLSRootDER, ready.TLSRootDER) || nextReady.ServerKey == ready.ServerKey || nextReady.Store != ready.Store || nextReady.Controller != ready.Controller {
		t.Fatal("reopen did not rotate only the private service generation")
	}

	// Deliberately trust the NEW root, E-bound server identity, and SPKI pin.
	// Thus this cannot pass because an old client rejected the changed server.
	// Force presentation of the OLD certificate despite the new CA-name hints;
	// otherwise crypto/tls may send no certificate, proving the wrong rejection.
	stale, staleJoin := staleDataTLS(t, next, nextReady, oldIdentity, true)
	staleAttempt(t, stale, hello, "previous-epoch")
	staleRejectRead(t, stale)
	serverErr := staleJoin()
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	if !errors.As(serverErr, &verification) || !errors.As(serverErr, &unknown) {
		t.Fatalf("want successor SERVER rejection of old certificate chain, got %T: %v", serverErr, serverErr)
	}
	if len(verification.UnverifiedCertificates) != 1 || !bytes.Equal(verification.UnverifiedCertificates[0].Raw, oldIdentity.Certificate().DER()) {
		t.Fatal("successor did not verify/reject the exact retained old DATA certificate")
	}
	staleAbsent(t, path, "previous-epoch")

	// Positive control: the successor can issue and admit fresh credentials and
	// perform the same real filesystem mutation, not merely reject all clients.
	currentController, currentControl, closeCurrent := staleControl(t, next, nextReady, controllerKey)
	currentState := staleCall(t, currentControl, c.Request{Query: &c.Empty{}}).Snapshot
	if currentState.Epoch != nextReady.ServiceEpoch || currentState.Revision != nextReady.Revision || currentState.Attachments[hello.Binding.Attachment].Phase != a.Drained {
		t.Fatal("old-E attempt changed the successor registry")
	}
	freshHello, freshIdentity, retireFresh := staleAttachment(t, next, nextReady, currentController, currentControl, volume)
	fresh, freshJoin := staleDataTLS(t, next, nextReady, freshIdentity, false)
	staleAdmit(t, fresh, freshHello)
	staleCreate(t, fresh, 1, "after-reopen")
	staleExists(t, path, "after-reopen")
	staleExists(t, path, "before-retire")
	retireFresh()
	staleMust(t, fresh.NetConn().Close())
	freshJoin()
	closeCurrent()
	staleMust(t, next.Close())
}

func staleMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func staleID(t *testing.T) a.ID {
	t.Helper()
	id, err := a.NewID()
	staleMust(t, err)
	return id
}

// Only public durable reopen inputs cross the native fault child's evidence file.
// Retain the exact ROOT-signed grant; metadata alone is not authorization.
type staleLifecycleReopen struct {
	Identity a.LifecycleIdentity
	Current  a.SignedLifecycleGrant
	Expected a.ExpectedLifecycleStartup
}

func staleLifecycleGrant(t *testing.T, root ed25519.PrivateKey, store a.ID, controller p.Key) a.SignedLifecycleGrant {
	t.Helper()
	bindingKey, err := p.NewControllerKey()
	staleMust(t, err)
	binding, err := bindingKey.Fingerprint()
	staleMust(t, err)
	key, err := controller.Fingerprint()
	staleMust(t, err)
	grant := a.LifecycleGrant{Operation: a.LifecycleInitialize, ID: staleID(t), Identity: a.LifecycleIdentity{Store: store, Generation: 1, Binding: a.Fingerprint(binding.String())}, Serial: 1, NewKey: a.Fingerprint(key.String())}
	message, err := a.LifecycleGrantSigningBytes(grant)
	staleMust(t, err)
	return a.SignedLifecycleGrant{Grant: grant, Signature: ed25519.Sign(root, message)}
}

func staleLifecyclePredecessor(t *testing.T, service *s.LifecycleService, current a.SignedLifecycleGrant) staleLifecycleReopen {
	t.Helper()
	meta, err := service.Scope()
	staleMust(t, err)
	if meta.CurrentGrant != current.Grant || meta.Identity != current.Grant.Identity || meta.OpenRevision == 0 {
		t.Fatal("reopen predecessor differs from exact signed current grant")
	}
	return staleLifecycleReopen{Identity: meta.Identity, Current: current, Expected: a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: meta.Store.ID, Epoch: meta.Epoch, Controller: meta.Controller}, OpenRevision: meta.OpenRevision}}
}

// All server goroutines own actual loopback TCP peers, are bounded, and joined.
func staleTCP(t *testing.T, worker func(context.Context, net.Conn) error) (net.Conn, func() error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	staleMust(t, err)
	defer listener.Close()
	staleMust(t, listener.SetDeadline(time.Now().Add(5*time.Second)))
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	staleMust(t, err)
	t.Cleanup(func() { raw.Close() })
	peer, err := listener.Accept()
	staleMust(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- worker(ctx, peer) }()
	var result error
	waited := false
	join := func() error {
		if !waited {
			select {
			case result = <-done:
				waited = true
			case <-time.After(10 * time.Second):
				t.Fatal("TLS server did not join")
			}
		}
		return result
	}
	t.Cleanup(func() { raw.Close(); peer.Close(); cancel(); join() })
	return raw, join
}

func staleTrust(t *testing.T, ready s.Ready) (p.Root, p.Binding) {
	t.Helper()
	root, err := p.ParseRootDER(ready.TLSRootDER)
	staleMust(t, err)
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	staleMust(t, err)
	return root, server
}

func staleControl(t *testing.T, service *s.LifecycleService, ready s.Ready, key p.Key) (p.Identity, *c.Client, func()) {
	t.Helper()
	binding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	staleMust(t, err)
	csr, err := key.CSR(binding)
	staleMust(t, err)
	cert, err := service.IssueController(csr)
	staleMust(t, err)
	identity, err := cert.WithKey(key)
	staleMust(t, err)
	root, _ := staleTrust(t, ready)
	meta, err := service.Scope()
	staleMust(t, err)
	raw, join := staleTCP(t, service.ServeControl)
	client, err := c.NewPKILifecycleWorkloadClient(context.Background(), raw, c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: root, ServerKey: ready.ServerKey, LifecycleIdentity: meta.Identity, ServiceEpoch: ready.ServiceEpoch, CurrentController: ready.Controller})
	staleMust(t, err)
	return identity, client, func() { staleMust(t, client.Close()); join() }
}

func staleCall(t *testing.T, client *c.Client, request c.Request) c.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.Call(ctx, request)
	staleMust(t, err)
	return response
}

func staleAttachment(t *testing.T, service *s.LifecycleService, ready s.Ready, controller p.Identity, control *c.Client, volume a.ID) (a.DataHello, p.Identity, func()) {
	t.Helper()
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	staleMust(t, err)
	pin, err := key.Fingerprint()
	staleMust(t, err)
	hello := a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: staleID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: staleID(t), Key: a.Fingerprint(pin.String()), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	staleCall(t, control, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: staleID(t), Binding: hello.Binding}})
	retired := false
	retire := func() {
		if !retired {
			staleRetire(t, control, hello)
			retired = true
		}
	}
	// DATA cleanups registered later close/join first; the earlier control
	// cleanup runs last, leaving real retirement available on assertion failure.
	t.Cleanup(retire)
	binding, err := d.AttachmentBinding(hello)
	staleMust(t, err)
	csr, err := key.CSR(binding)
	staleMust(t, err)
	meta, err := service.Scope()
	staleMust(t, err)
	raw, join := staleTCP(t, service.ServeAttachmentCSR)
	cert, err := s.RequestLifecycleAttachmentCertificate(context.Background(), raw, controller, ready, meta.Identity, hello, csr)
	staleMust(t, err)
	staleMust(t, join())
	identity, err := cert.WithKey(key)
	staleMust(t, err)
	return hello, identity, retire
}

func staleDataTLS(t *testing.T, service *s.LifecycleService, ready s.Ready, identity p.Identity, forceCertificate bool) (*tls.Conn, func() error) {
	t.Helper()
	root, server := staleTrust(t, ready)
	cfg, err := p.ClientTLSConfig(identity, root, server, ready.ServerKey)
	staleMust(t, err)
	presented := false
	if forceCertificate {
		cert := cfg.Certificates[0]
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			presented = true
			return &cert, nil
		}
	}
	raw, join := staleTCP(t, service.ServeData)
	conn := tls.Client(raw, cfg)
	staleMust(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	staleMust(t, conn.Handshake())
	// TLS 1.3 client completion is NOT server acceptance of its client cert.
	// This assertion proves the client accepted the configured current server.
	staleMust(t, p.VerifyServer(conn.ConnectionState(), root, server, ready.ServerKey))
	if forceCertificate && !presented {
		t.Fatal("old DATA certificate was not presented")
	}
	return conn, join
}

func staleAdmit(t *testing.T, conn *tls.Conn, hello a.DataHello) {
	t.Helper()
	var greeting w.ServerHello
	staleMust(t, w.ReadFrame(conn, &greeting))
	if greeting.Epoch != hello.Epoch {
		t.Fatal("wrong DATA service epoch")
	}
	staleMust(t, w.WriteFrame(conn, &w.ClientHello{Authority: hello, Profile: w.RequiredProfile()}))
	var root w.RootReply
	staleMust(t, w.ReadFrame(conn, &root))
	if root.Root.Node != 1 {
		t.Fatal("unexpected DATA root node")
	}
}

func staleCreateRequest(sequence uint64, name string) w.Request {
	return w.Request{Sequence: sequence, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{FSUID: 0, FSGID: 0, Groups: []uint32{}}}, Body: w.CreateRequest{Parent: 1, Name: []byte(name), Flags: w.OpenCreate | w.OpenReadWrite, Mode: 0600}}
}

func staleCreate(t *testing.T, conn *tls.Conn, sequence uint64, name string) {
	t.Helper()
	request := staleCreateRequest(sequence, name)
	staleMust(t, w.WriteFrame(conn, &request))
	message, err := w.ReadServerFrame(conn)
	staleMust(t, err)
	reply, ok := message.(*w.Reply)
	if !ok {
		t.Fatalf("mutation did not reply before invalidations: %T", message)
	}
	staleMust(t, w.ValidateReplyFor(request, *reply))
	if reply.Errno != 0 {
		t.Fatalf("create %q: errno=%d", name, reply.Errno)
	}
}

func staleRetire(t *testing.T, control *c.Client, hello a.DataHello) {
	t.Helper()
	b := hello.Binding
	receipt := staleCall(t, control, c.Request{Retire: &a.RetireRequest{Operation: staleID(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}}).Receipt
	if receipt == nil || receipt.Store != b.Store || receipt.Volume != b.Volume || receipt.Attachment != b.Attachment {
		t.Fatal("missing exact control-plane drain receipt")
	}
}

func staleAttempt(t *testing.T, conn *tls.Conn, hello a.DataHello, name string) {
	t.Helper()
	// Pipeline a valid mutation behind the claimed identity. A TLS rejection may
	// stop the write before any application bytes are accepted; the authoritative
	// result is the joined server error plus the absent filesystem mutation.
	var payload bytes.Buffer
	staleMust(t, w.WriteFrame(&payload, &w.ClientHello{Authority: hello, Profile: w.RequiredProfile()}))
	request := staleCreateRequest(1, name)
	staleMust(t, w.WriteFrame(&payload, &request))
	_, err := conn.Write(payload.Bytes())
	t.Logf("attempt %s write: %v", name, err)
}

func staleRejectRead(t *testing.T, conn *tls.Conn) {
	t.Helper()
	// Drain any invalidations queued by the earlier successful create, but no
	// successful reply/root may follow the stale mutation/identity attempt.
	for {
		message, err := w.ReadServerFrame(conn)
		if err != nil {
			var remote *net.OpError
			if errors.Is(err, io.EOF) || errors.Is(err, unix.ECONNRESET) || (errors.As(err, &remote) && remote.Op == "remote error") {
				return
			}
			// In particular, ReadServerFrame rejects a RootReply as ErrInvalid.
			// That is unexpected admission, NOT evidence of transport rejection.
			t.Fatalf("stale peer did not terminate with EOF/reset/TLS alert: %v", err)
		}
		if _, ok := message.(*w.Event); !ok {
			t.Fatalf("stale credential received application response: %T", message)
		}
	}
}

func staleAbsent(t *testing.T, root, name string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(root, "volumes", "data", name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale mutation %q exists or cannot be checked: %v", name, err)
	}
}

func staleExists(t *testing.T, root, name string) {
	t.Helper()
	info, err := os.Lstat(filepath.Join(root, "volumes", "data", name))
	staleMust(t, err)
	if !info.Mode().IsRegular() {
		t.Fatalf("positive mutation %q is not a regular file", name)
	}
}
