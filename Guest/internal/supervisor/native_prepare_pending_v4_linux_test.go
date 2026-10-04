//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
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

var prepareV4PendingWorker = flag.Bool("native-prepare-v4-pending-worker", false, "owned pending provision marker worker")

type prepareV4PendingEvidence struct {
	Hello  a.DataHello
	Intent a.CopyIntent
	Scope  a.LifecycleMetadata
}

// The crash setup uses the real authority API, not a fabricated journal or a
// Dispatch replacement. Recovery goes through issued DATA TLS, the actual FUSE
// mount, and native PREPARE ioctls in the pinned mount-creator/initializer child.
// This is NOT a natural in-flight DATA-server crash or power-loss test.
func TestNativePendingProvisionFreshMountReplayV4(t *testing.T) {
	prepareV4Profile(t)
	base, err := os.MkdirTemp("/scratch", "prepare-pending-v4-")
	prepareV4Must(t, err)
	safe := true
	t.Cleanup(func() {
		info, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			safe = false
		}
		for _, line := range strings.Split(string(info), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 4 && strings.HasPrefix(fields[4], base+"/") {
				safe = false
			}
		}
		if safe && !t.Failed() {
			prepareV4Must(t, os.RemoveAll(base))
		} else {
			t.Logf("retained pending replay evidence: %s", base)
		}
	})
	for _, name := range []string{"store/volumes", "rootfs/seed", "mounts"} {
		prepareV4Must(t, os.MkdirAll(filepath.Join(base, name), 0700))
	}
	seed := filepath.Join(base, "rootfs/seed")
	for _, name := range []string{"a", "z"} {
		prepareV4Must(t, os.WriteFile(filepath.Join(seed, name), []byte("issued-prepare-"+name+"\n"), 0640))
	}
	prepareV4Must(t, unix.Chmod(seed, 0750))
	prepareV4Must(t, unix.Setxattr(seed, "user.prepare", []byte("source-root"), 0))
	root, err := os.Open(filepath.Join(base, "store"))
	prepareV4Must(t, err)
	defer root.Close()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	bootstrap, err := p.NewBootstrapPublicKey(private.Public().(ed25519.PublicKey))
	prepareV4Must(t, err)
	controllerKey, err := p.NewControllerKey()
	prepareV4Must(t, err)
	cfg := s.Config{Root: root, DeviceUUID: prepareV4BackingUUID(t, int(root.Fd())), Store: prepareV4ID(t), Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
	current := nativeLifecycleGrant(t, cfg.Store, private, controllerKey)
	service, err := s.InitializeLifecycle(cfg, current)
	prepareV4Must(t, err)
	t.Cleanup(func() {
		if safe {
			prepareV4Must(t, service.Close())
		}
	})
	ready, err := service.Ready()
	prepareV4Must(t, err)
	controller, control, closeControl := prepareV4Control(t, service, ready, controllerKey)
	volume := prepareV4ID(t)
	prepareV4Call(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: prepareV4ID(t), Store: ready.Store.ID, Volume: volume, Name: "data"}})
	fd, err := unix.MemfdCreate("pending-issued-credential", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	prepareV4Must(t, err)
	sealed := os.NewFile(uintptr(fd), "pending-issued-credential")
	defer sealed.Close()
	closeControl()
	ready, err = service.Ready()
	prepareV4Must(t, err)
	scope, err := service.Scope()
	prepareV4Must(t, err)
	prepareV4Must(t, service.Close())

	// Reopen fences every old attachment. Reserve/register/issue only AFTER the
	// worker owns the new epoch. The parent alone holds the controller private key;
	// only public bootstrap/CSR values cross the inherited setup channels. The
	// attachment credential is sealed before the worker is allowed to read it.
	report, err := os.OpenFile(filepath.Join(base, "pending-marker.json"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	prepareV4Must(t, err)
	defer report.Close()
	output, err := os.OpenFile(filepath.Join(base, "pending-worker-output.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	prepareV4Must(t, err)
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativePendingProvisionMarkerWorkerV4$", "-test.timeout=25s", "-native-prepare-v4-pending-worker")
	cmd.Env = []string{"TMPDIR=/scratch"}
	setup, setupFile := prepareV4PendingPair(t)
	controlRaw, controlFile := prepareV4PendingPair(t)
	csrRaw, csrFile := prepareV4PendingPair(t)
	cmd.ExtraFiles = []*os.File{sealed, root, report, setupFile, controlFile, csrFile}
	capture := &prepareV4Output{file: output, remaining: 64 << 10}
	cmd.Stdout, cmd.Stderr = capture, capture
	cmd.WaitDelay = 2 * time.Second
	prepareV4Must(t, cmd.Start())
	// Exactly one Wait also covers any failed bootstrap, without abandoning a child.
	waited := false
	var waitErr error
	wait := func() error {
		if !waited {
			waitErr = cmd.Wait()
			waited = true
		}
		return waitErr
	}
	t.Cleanup(func() { cancel(); setup.Close(); controlRaw.Close(); csrRaw.Close(); _ = wait() })
	for _, file := range []*os.File{setupFile, controlFile, csrFile} {
		prepareV4Must(t, file.Close())
	}
	deadline, _ := ctx.Deadline()
	for _, conn := range []net.Conn{setup, controlRaw, csrRaw} {
		prepareV4Must(t, conn.SetDeadline(deadline))
	}
	controllerBinding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	prepareV4Must(t, err)
	controllerCSR, err := controllerKey.CSR(controllerBinding)
	prepareV4Must(t, err)
	prepareV4Must(t, pendingBootstrapWrite(setup, pendingBootstrapRequest{Ready: ready, Scope: scope, Current: current, CSR: controllerCSR}))
	var boot pendingBootstrapReply
	prepareV4Must(t, pendingBootstrapRead(setup, &boot))
	if !pendingLifecycleScopeMatches(boot.Ready, boot.Scope, current.Grant) || boot.Ready.Store != ready.Store || boot.Ready.Controller != ready.Controller || boot.Ready.ServiceEpoch == ready.ServiceEpoch || boot.Scope.OpenRevision != scope.Revision+1 {
		t.Fatal("wrong pending worker startup")
	}
	controller, err = pendingControllerIdentity(boot.Certificate, controllerBinding, controllerKey)
	prepareV4Must(t, err)
	trust, _ := prepareV4Trust(t, boot.Ready)
	control, err = c.NewPKILifecycleWorkloadClient(ctx, controlRaw, c.PKILifecycleWorkloadClientConfig{Identity: controller, ServerRoot: trust, ServerKey: boot.Ready.ServerKey, LifecycleIdentity: boot.Scope.Identity, ServiceEpoch: boot.Ready.ServiceEpoch, CurrentController: boot.Ready.Controller})
	prepareV4Must(t, err)
	old, key := prepareV4Binding(t, boot.Ready, volume)
	prepareV4Call(t, control, c.Request{ReservePrepare: &a.ReserveRequest{Operation: prepareV4ID(t), Prepare: old.Binding.Prepare, Attachments: []a.Binding{old.Binding}}})
	prepareV4Call(t, control, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: prepareV4ID(t), Binding: old.Binding}})
	attachmentBinding, err := d.AttachmentBinding(old)
	prepareV4Must(t, err)
	attachmentCSR, err := key.CSR(attachmentBinding)
	prepareV4Must(t, err)
	certificate, err := s.RequestLifecycleAttachmentCertificate(ctx, csrRaw, controller, boot.Ready, boot.Scope.Identity, old, attachmentCSR)
	prepareV4Must(t, err)
	identity, err := certificate.WithKey(key)
	prepareV4Must(t, err)
	prepareV4Must(t, control.Close())
	prepareV4Must(t, json.NewEncoder(sealed).Encode(prepareV4Credentials(t, old, boot.Ready, identity)))
	_, err = sealed.Seek(0, io.SeekStart)
	prepareV4Must(t, err)
	_, err = unix.FcntlInt(sealed.Fd(), unix.F_ADD_SEALS, prepareV4BootstrapSeals)
	prepareV4Must(t, err)
	prepareV4Must(t, pendingBootstrapWrite(setup, pendingBootstrapGo{Sealed: true}))
	err = wait() // real Wait; no defer/drain runs in the os.Exit crash child
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 || cmd.ProcessState == nil || ctx.Err() != nil {
		t.Fatalf("pending marker worker failed: %v (output retained)", err)
	}
	prepareV4Must(t, sealed.Close())
	_, err = report.Seek(0, io.SeekStart)
	prepareV4Must(t, err)
	var evidence prepareV4PendingEvidence
	decoder := json.NewDecoder(io.LimitReader(report, 16385))
	decoder.DisallowUnknownFields()
	prepareV4Must(t, decoder.Decode(&evidence))
	if decoder.Decode(new(any)) != io.EOF || evidence.Hello != old || evidence.Scope.Identity != boot.Scope.Identity || evidence.Scope.CurrentGrant != current.Grant || evidence.Scope.OpenRevision != boot.Scope.OpenRevision || evidence.Scope.Epoch != boot.Ready.ServiceEpoch || evidence.Scope.Controller != boot.Ready.Controller || evidence.Hello.Epoch == ready.ServiceEpoch || evidence.Intent.Owner != old.Binding || evidence.Intent.Epoch != evidence.Hello.Epoch || evidence.Intent.Phase != a.CopyBound {
		t.Fatal("wrong durable crash witness")
	}
	markers, err := filepath.Glob(filepath.Join(base, "store", "*", "copy-operation"))
	prepareV4Must(t, err)
	if len(markers) != 1 {
		t.Fatalf("missing authentic durable operation marker: %v", markers)
	}
	marker, err := os.ReadFile(markers[0])
	prepareV4Must(t, err)
	var record struct {
		Action  string
		Intent  a.ID
		Binding a.Binding
		Epoch   a.ID
		Before  a.CopyIntent
	}
	prepareV4Must(t, json.Unmarshal(marker, &record))
	if record.Action != a.CopyOperationProvision || record.Intent != evidence.Intent.ID || record.Binding != old.Binding || record.Epoch != evidence.Hello.Epoch || record.Before.Phase != a.CopyBegun || record.Before.ID != evidence.Intent.ID || record.Before.Owner != old.Binding || record.Before.Epoch != old.Epoch || record.Before.Root != evidence.Intent.Root {
		t.Fatal("crash did not retain the exact provision marker")
	}
	service, err = s.ReopenLifecycle(cfg, scope.Identity, current, a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: boot.Scope.Store.ID, Epoch: boot.Scope.Epoch, Controller: boot.Scope.Controller}, OpenRevision: boot.Scope.OpenRevision})
	prepareV4Must(t, err)
	freshReady, err := service.Ready()
	prepareV4Must(t, err)
	freshScope, err := service.Scope()
	prepareV4Must(t, err)
	if !pendingLifecycleScopeMatches(freshReady, freshScope, current.Grant) || freshScope.OpenRevision <= boot.Scope.OpenRevision || freshReady.ServiceEpoch == evidence.Hello.Epoch || freshReady.Store != ready.Store || freshReady.Controller != ready.Controller {
		t.Fatal("wrong reopened generation")
	}
	if _, err := os.Stat(markers[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("startup did not reconstruct/clear operation slot", err)
	}
	controller, control, closeControl = prepareV4Control(t, service, freshReady, controllerKey)
	defer closeControl()
	receipt := prepareV4Drain(t, control, evidence.Hello)
	fresh, freshKey := prepareV4Binding(t, freshReady, volume)
	if fresh.Binding.Prepare == old.Binding.Prepare || fresh.Binding.Attachment == old.Binding.Attachment || fresh.Binding.Key == old.Binding.Key {
		t.Fatal("successor identity reused")
	}
	prepareV4Call(t, control, c.Request{ReplacePrepare: &a.ReplaceRequest{Operation: prepareV4ID(t), Prepare: old.Binding.Prepare, Receipts: []a.Receipt{receipt}, Successor: a.ReserveRequest{Operation: prepareV4ID(t), Prepare: fresh.Binding.Prepare, Attachments: []a.Binding{fresh.Binding}}}})
	snapshot := prepareV4Call(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	if snapshot.Prepares[old.Binding.Prepare].Phase != a.Replaced || snapshot.Attachments[old.Binding.Attachment].Phase != a.Drained {
		t.Fatal("replacement lacks durable predecessor drain")
	}
	mountBootstrap, cert, join := prepareV4MountBootstrap(t, base, service, freshReady, controller, control, fresh, freshKey, evidence.Intent)
	if string(cert) == string(identity.Certificate().DER()) {
		t.Fatal("reused predecessor certificate")
	}
	recovered, mount := prepareV4OwnInitializer(t, base, fresh, "positive", mountBootstrap, &safe)
	mount.assertGone(t)
	join()
	freshReceipt := prepareV4Drain(t, control, fresh)
	if recovered.InitializerError != "" {
		t.Fatal(recovered.InitializerError)
	}
	prepareV4VerifyTree(t, filepath.Join(base, "store/volumes/data"), seed)
	prepareV4Complete(t, control, fresh, freshReceipt)
}

func TestNativePendingProvisionMarkerWorkerV4(t *testing.T) {
	if !*prepareV4PendingWorker {
		return
	}
	prepareV4Profile(t)
	sealed, root, report := os.NewFile(3, "pending-credential"), os.NewFile(4, "pending-store"), os.NewFile(5, "pending-evidence")
	setup := prepareV4PendingInherited(t, 6)
	controlRaw := prepareV4PendingInherited(t, 7)
	csrRaw := prepareV4PendingInherited(t, 8)
	var boot pendingBootstrapRequest
	prepareV4Must(t, pendingBootstrapRead(setup, &boot))
	bootstrap, err := p.NewBootstrapPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	prepareV4Must(t, err)
	cfg := s.Config{Root: root, DeviceUUID: prepareV4BackingUUID(t, int(root.Fd())), Store: boot.Ready.Store.ID, Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
	if !pendingLifecycleScopeMatches(boot.Ready, boot.Scope, boot.Current.Grant) {
		t.Fatal("wrong retained lifecycle bootstrap")
	}
	service, err := s.ReopenLifecycle(cfg, boot.Scope.Identity, boot.Current, a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: boot.Scope.Store.ID, Epoch: boot.Scope.Epoch, Controller: boot.Scope.Controller}, OpenRevision: boot.Scope.OpenRevision})
	prepareV4Must(t, err)
	ready, err := service.Ready()
	prepareV4Must(t, err)
	scope, err := service.Scope()
	prepareV4Must(t, err)
	if !pendingLifecycleScopeMatches(ready, scope, boot.Current.Grant) || ready.ServiceEpoch == boot.Ready.ServiceEpoch || scope.OpenRevision != boot.Scope.Revision+1 {
		t.Fatal("wrong reopened lifecycle incarnation")
	}
	controllerCertificate, err := service.IssueController(boot.CSR)
	prepareV4Must(t, err)
	controlDone, csrDone := make(chan error, 1), make(chan error, 1)
	go func() { controlDone <- service.ServeControl(context.Background(), controlRaw) }()
	go func() { csrDone <- service.ServeAttachmentCSR(context.Background(), csrRaw) }()
	prepareV4Must(t, pendingBootstrapWrite(setup, pendingBootstrapReply{Ready: ready, Scope: scope, Certificate: controllerCertificate.DER()}))
	var proceed pendingBootstrapGo
	prepareV4Must(t, pendingBootstrapRead(setup, &proceed))
	if !proceed.Sealed {
		t.Fatal("pending credential not ready")
	}
	controlErr := <-controlDone
	if controlErr != nil && !errors.Is(controlErr, io.EOF) {
		prepareV4Must(t, controlErr)
	}
	prepareV4Must(t, <-csrDone)
	seals, err := unix.FcntlInt(sealed.Fd(), unix.F_GET_SEALS, 0)
	prepareV4Must(t, err)
	if seals != prepareV4BootstrapSeals {
		t.Fatal("unsealed pending credentials")
	}
	var credentials prepareV4MountCredentials
	decoder := json.NewDecoder(io.LimitReader(sealed, 32769))
	decoder.DisallowUnknownFields()
	prepareV4Must(t, decoder.Decode(&credentials))
	if decoder.Decode(new(any)) != io.EOF || credentials.Pending != nil {
		t.Fatal("invalid pending worker bootstrap")
	}
	if credentials.Hello.Epoch != ready.ServiceEpoch || credentials.Ready.Store != ready.Store || credentials.Ready.Controller != ready.Controller {
		t.Fatal("wrong issued crash owner")
	}
	binding, err := d.AttachmentBinding(credentials.Hello)
	prepareV4Must(t, err)
	identity, err := p.ParseIdentityDER(credentials.Certificate, credentials.Key, binding)
	prepareV4Must(t, err)
	trust, serverBinding := prepareV4Trust(t, ready)
	clientTLS, err := p.ClientTLSConfig(identity, trust, serverBinding, ready.ServerKey)
	prepareV4Must(t, err)
	hello := credentials.Hello
	var intent a.CopyIntent
	raw, join := prepareV4TCP(t, func(ctx context.Context, raw net.Conn) error {
		var err error
		intent, err = service.NativePendingProvision(ctx, raw, hello)
		return err
	})
	conn := tls.Client(raw, clientTLS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prepareV4Must(t, conn.HandshakeContext(ctx))
	prepareV4Must(t, join())
	prepareV4Must(t, json.NewEncoder(report).Encode(prepareV4PendingEvidence{Hello: hello, Intent: intent, Scope: scope}))
	prepareV4Must(t, report.Sync())
	os.Exit(73) // no obligation completion, guard release, authority close or drain
}

// Runs only in the fresh mount's pinned creator, before any initializer root open.
// default_permissions may require GETATTR before OPENDIR on this cold root.
func prepareV4PendingRootProbe(t *testing.T, path string, hello a.DataHello, before a.CopyIntent) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	prepareV4Must(t, err)
	defer unix.Close(fd)
	begun, err := managedPrepareIoctl(fd, w.PrepareRequest{Action: w.BeginCopy})
	prepareV4Must(t, err)
	want := before
	want.Owner, want.Epoch = hello.Binding, hello.Epoch
	if begun.Pending != w.BindCopyTransaction || begun.Intent != want || begun.Root != before.Root {
		t.Fatal("fresh root Begin lost exact pending provision", begun)
	}
	buffer := make([]byte, 4096)
	if _, err := unix.ReadDirent(fd, buffer); !errors.Is(err, unix.EBUSY) {
		t.Fatal("auxiliary Begin released pending DATA fence", err)
	}
	bound, err := managedPrepareIoctl(fd, w.PrepareRequest{Action: w.BindCopyTransaction, Intent: before.ID})
	prepareV4Must(t, err)
	if bound.Intent != want || bound.Root != before.Root || bound.Identity != before.Transaction {
		t.Fatal("exact provision replay changed durable identity/metadata")
	}
	again, err := managedPrepareIoctl(fd, w.PrepareRequest{Action: w.BeginCopy})
	prepareV4Must(t, err)
	if again.Pending != 0 || again.Intent != want {
		t.Fatal("successful replay did not clear pending operation")
	}
	if _, err := unix.ReadDirent(fd, buffer); err != nil {
		t.Fatal("exact replay did not release ordinary DATA", err)
	}
}

// Private inherited socketpairs: no new listener, endpoint selector or key file.
func prepareV4PendingPair(t *testing.T) (net.Conn, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	prepareV4Must(t, err)
	parent, child := os.NewFile(uintptr(fds[0]), "pending-parent"), os.NewFile(uintptr(fds[1]), "pending-child")
	conn, err := net.FileConn(parent)
	prepareV4Must(t, parent.Close())
	prepareV4Must(t, err)
	t.Cleanup(func() { conn.Close(); child.Close() })
	return conn, child
}
func prepareV4PendingInherited(t *testing.T, fd uintptr) net.Conn {
	t.Helper()
	file := os.NewFile(fd, "pending-private-channel")
	conn, err := net.FileConn(file)
	prepareV4Must(t, file.Close())
	prepareV4Must(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}
