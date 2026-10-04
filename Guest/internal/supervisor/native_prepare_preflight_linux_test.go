//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"dev.cengine/guest/internal/protocol"
	a "dev.cengine/guest/internal/storageauthority"
	cl "dev.cengine/guest/internal/storageclient"
	c "dev.cengine/guest/internal/storagecontrol"
	f "dev.cengine/guest/internal/storagefuse"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Tagged test-binary-only closed cases; no production flag or global IO hook.
var nativePrepareChild = flag.String("native-prepare-child", "", "owned initializer: positive, first-publication, recovery")

func TestNativeIssuedPrepareInitializerPreflight(t *testing.T) {
	if *nativePrepareChild != "" {
		t.Fatal("child selector requires the exact child test")
	}
	prepareProfile(t)
	for _, name := range []string{"positive", "first-publication-fresh-attachment"} {
		if !t.Run(name, func(t *testing.T) { preparePreflight(t, name != "positive") }) {
			return // never continue after a failed/unjoined fixture
		}
	}
}

func prepareProfile(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires disposable native Linux root fixture")
	}
	if filepath.Clean(os.TempDir()) != "/scratch" {
		t.Fatal("requires TMPDIR=/scratch")
	}
	var uts unix.Utsname
	prepareMust(t, unix.Uname(&uts))
	if !strings.HasPrefix(string(bytes.TrimRight(uts.Release[:], "\x00")), "6.18.") {
		t.Fatal("requires patched Linux 6.18")
	}
	var fs unix.Statfs_t
	prepareMust(t, unix.Statfs("/scratch", &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("requires real ext4 /scratch")
	}
}

func preparePreflight(t *testing.T, interrupt bool) {
	base, err := os.MkdirTemp("/scratch", "prepare-preflight-")
	prepareMust(t, err)
	safe := true
	t.Cleanup(func() {
		// Never recurse through a surviving mount, including a failed construction.
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
			prepareMust(t, os.RemoveAll(base))
		} else {
			t.Logf("retained prepare evidence: %s", base)
		}
	})
	for _, name := range []string{"store/volumes", "rootfs/seed", "mounts"} {
		prepareMust(t, os.MkdirAll(filepath.Join(base, name), 0700))
	}
	seed := filepath.Join(base, "rootfs/seed")
	for _, name := range []string{"a", "z"} {
		prepareMust(t, os.WriteFile(filepath.Join(seed, name), []byte("issued-prepare-"+name+"\n"), 0640))
	}
	prepareMust(t, unix.Chmod(seed, 0750))
	prepareMust(t, unix.Setxattr(seed, "user.prepare", []byte("source-root"), 0))
	root, err := os.Open(filepath.Join(base, "store"))
	prepareMust(t, err)
	t.Cleanup(func() { prepareMust(t, root.Close()) })
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	bootstrap, err := p.NewBootstrapPublicKey(private.Public().(ed25519.PublicKey))
	prepareMust(t, err)
	controllerKey, err := p.NewControllerKey()
	prepareMust(t, err)
	cfg := s.Config{Root: root, DeviceUUID: "native-issued-prepare-preflight", Store: prepareID(t), Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
	current := nativeLifecycleGrant(t, cfg.Store, private, controllerKey)
	service, err := s.InitializeLifecycle(cfg, current)
	prepareMust(t, err)
	t.Cleanup(func() {
		if safe {
			if err := service.Close(); err != nil {
				safe = false
				t.Error(err)
			}
		}
	})
	ready, err := service.Ready()
	prepareMust(t, err)
	controller, control, closeControl := prepareControl(t, service, ready, controllerKey)
	defer closeControl()
	volume := prepareID(t)
	prepareCall(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: prepareID(t), Store: ready.Store.ID, Volume: volume, Name: "data"}})
	backing := filepath.Join(base, "store/volumes/data")
	old, key := prepareBinding(t, ready, volume)
	reserve := a.ReserveRequest{Operation: prepareID(t), Prepare: old.Binding.Prepare, Attachments: []a.Binding{old.Binding}}
	prepareCall(t, control, c.Request{ReservePrepare: &reserve})
	mount, cert, join := prepareMount(t, base, service, ready, controller, control, old, key, &safe)
	mode := "positive"
	if interrupt {
		mode = "first-publication"
	}
	before := prepareOwnInitializer(t, base, old, mode, &safe)
	if !interrupt {
		prepareVerifyTree(t, backing, seed)
		prepareMust(t, mount.CloseGracefully(context.Background()))
		prepareJoinedMount(t, mount)
		join()
		receipt := prepareDrain(t, control, old)
		prepareComplete(t, control, old, receipt)
		return
	}
	if before.Stage != "first-publication" || before.Count != 1 || before.Hello != old {
		t.Fatal("wrong one-shot checkpoint evidence")
	}
	// This manifest was made by the actual initializer, never staged by the test.
	journal := filepath.Join(backing, confinedCopyTransactionName, confinedCopyManifestName)
	manifestBytes, err := os.ReadFile(journal)
	prepareMust(t, err)
	var manifest confinedCopyManifest
	prepareMust(t, json.Unmarshal(manifestBytes, &manifest))
	if manifest.Version != 3 || manifest.Root == nil || len(manifest.Entries) != 2 {
		t.Fatal("missing actual version-3 two-entry journal")
	}
	if before.Root.Filesystem != manifest.Root.Filesystem || before.Root.Inode != manifest.Root.Inode {
		t.Fatal("checkpoint root differs from real journal")
	}
	prepareMust(t, os.WriteFile(filepath.Join(base, "interrupted-manifest.json"), manifestBytes, 0600))
	prepareExpectBytes(t, filepath.Join(backing, "a"), "issued-prepare-a\n")
	if _, err := os.Stat(filepath.Join(backing, "z")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("more than first entry published", err)
	}
	prepareExpectBytes(t, filepath.Join(backing, confinedCopyTransactionName, confinedCopyStagingName, "z"), "issued-prepare-z\n")
	// Joined initializer SIGKILL does not drain DATA. Abort/join the exact mount,
	// then require the production controller's real barrier-backed receipt.
	prepareMust(t, mount.Close())
	prepareJoinedMount(t, mount)
	join()
	receipt := prepareDrain(t, control, old)
	afterDrain, err := os.ReadFile(journal)
	prepareMust(t, err)
	if !bytes.Equal(manifestBytes, afterDrain) {
		t.Fatal("drain rewrote copy-up journal")
	}
	fresh, freshKey := prepareBinding(t, ready, volume)
	if fresh.Binding.Prepare == old.Binding.Prepare || fresh.Binding.Attachment == old.Binding.Attachment || fresh.Binding.Key == old.Binding.Key {
		t.Fatal("successor identity reused")
	}
	successor := a.ReserveRequest{Operation: prepareID(t), Prepare: fresh.Binding.Prepare, Attachments: []a.Binding{fresh.Binding}}
	prepareCall(t, control, c.Request{ReplacePrepare: &a.ReplaceRequest{Operation: prepareID(t), Prepare: old.Binding.Prepare, Receipts: []a.Receipt{receipt}, Successor: successor}})
	snapshot := prepareCall(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	if snapshot.Prepares[old.Binding.Prepare].Phase != a.Replaced || snapshot.Attachments[old.Binding.Attachment].Phase != a.Drained {
		t.Fatal("replacement lacks durable predecessor drain")
	}
	freshMount, freshCert, freshJoin := prepareMount(t, base, service, ready, controller, control, fresh, freshKey, &safe)
	if bytes.Equal(cert, freshCert) || mount.Mountpoint() == freshMount.Mountpoint() {
		t.Fatal("certificate or mount reused")
	}
	recovered := prepareOwnInitializer(t, base, fresh, "recovery", &safe)
	t.Logf("first-publication journal SHA256=%x old-root=%+v fresh-root=%+v old-entries=%+v fresh-entries=%+v", sha256.Sum256(manifestBytes), before.Root, recovered.Root, before.Entries, recovered.Entries)
	// Always drain genuinely joined recovery, even when production identity guards
	// reject it. A returned initializer error is diagnostic, NOT successful recovery.
	prepareMust(t, freshMount.CloseGracefully(context.Background()))
	prepareJoinedMount(t, freshMount)
	freshJoin()
	freshReceipt := prepareDrain(t, control, fresh)
	if recovered.InitializerError != "" {
		t.Fatalf("real fresh-P/A initializer recovery failed (identity checks unchanged): %s", recovered.InitializerError)
	}
	prepareVerifyTree(t, backing, seed) // detects silent handle-mismatch/skipped rollback
	prepareComplete(t, control, fresh, freshReceipt)
}

func prepareBinding(t *testing.T, ready s.Ready, volume a.ID) (a.DataHello, p.Key) {
	key, err := p.NewAttachmentKey(p.PrepareRole)
	prepareMust(t, err)
	pin, err := key.Fingerprint()
	prepareMust(t, err)
	return a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: prepareID(t), Prepare: prepareID(t), Container: a.ContainerID(strings.Repeat("b", 64)), Launch: prepareID(t), Key: a.Fingerprint(pin.String()), Role: a.PrepareRole, Mode: a.ReadWrite}}, key
}

func prepareMount(t *testing.T, base string, service *s.LifecycleService, ready s.Ready, controller p.Identity, control *c.Client, hello a.DataHello, key p.Key, safe *bool) (*f.Mounted, []byte, func() error) {
	t.Helper()
	prepareCall(t, control, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: prepareID(t), Binding: hello.Binding}})
	binding, err := d.AttachmentBinding(hello)
	prepareMust(t, err)
	csr, err := key.CSR(binding)
	prepareMust(t, err)
	raw, csrJoin := prepareTCP(t, service.ServeAttachmentCSR)
	scope, err := service.Scope()
	prepareMust(t, err)
	cert, err := s.RequestLifecycleAttachmentCertificate(context.Background(), raw, controller, ready, scope.Identity, hello, csr)
	prepareMust(t, err)
	prepareMust(t, csrJoin())
	identity, err := cert.WithKey(key)
	prepareMust(t, err)
	root, server := prepareTrust(t, ready)
	cfg, err := p.ClientTLSConfig(identity, root, server, ready.ServerKey)
	prepareMust(t, err)
	raw, join := prepareTCP(t, service.ServeData)
	conn := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = conn.HandshakeContext(ctx)
	cancel()
	prepareMust(t, err)
	parent := filepath.Join(base, "mounts", string(hello.Binding.Attachment))
	prepareMust(t, os.Mkdir(parent, 0700))
	mount, err := f.Mount(f.Config{Client: cl.Config{Conn: conn, TLSConfig: cfg, ServerPin: a.Fingerprint(ready.ServerKey.String()), Authority: hello, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: (uint64(1) << (unix.CAP_LAST_CAP + 1)) - 1, Limits: cl.DefaultLimits(), Timeout: 15 * time.Second}, Mountpoint: filepath.Join(parent, "root"), Retire: func(error) {}})
	prepareMust(t, err)
	t.Cleanup(func() {
		if !*safe {
			return
		} // an unjoined initializer still owns its mount
		if err := mount.Close(); err != nil {
			*safe = false
			t.Error(err)
			return
		}
		select {
		case <-mount.Done():
		default:
			*safe = false
			t.Error("cleanup mount unjoined")
		}
		// Cleanup never invents retirement/completion after an assertion failure.
	})
	return mount, cert.DER(), join
}

func prepareJoinedMount(t *testing.T, m *f.Mounted) {
	t.Helper()
	select {
	case <-m.Done():
	default:
		t.Fatal("mount close returned without actual join")
	}
}
func prepareDrain(t *testing.T, control *c.Client, h a.DataHello) a.Receipt {
	t.Helper()
	b := h.Binding
	r := prepareCall(t, control, c.Request{Retire: &a.RetireRequest{Operation: prepareID(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}}).Receipt
	if r == nil || r.Schema != a.SchemaVersion || r.Store != b.Store || r.Volume != b.Volume || r.Attachment != b.Attachment || r.Prepare != b.Prepare || r.Prepare == "" || r.Revision == 0 {
		t.Fatal("missing exact real PREPARE drain receipt")
	}
	snap := prepareCall(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	record := snap.Attachments[b.Attachment]
	if record.Phase != a.Drained || record.Receipt == nil || *record.Receipt != *r {
		t.Fatal("receipt not in durable authority snapshot")
	}
	return *r
}
func prepareComplete(t *testing.T, control *c.Client, h a.DataHello, r a.Receipt) {
	prepareCall(t, control, c.Request{CompletePrepare: &a.CompleteRequest{Operation: prepareID(t), Prepare: h.Binding.Prepare, Receipts: []a.Receipt{r}, Attestation: a.Attestation{Prepare: h.Binding.Prepare, Succeeded: true, CleanCopyUp: true}}})
}
func prepareExpectBytes(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	prepareMust(t, err)
	if string(b) != want {
		t.Fatal("wrong bytes", path)
	}
}
func prepareVerifyTree(t *testing.T, backing, source string) {
	t.Helper()
	entries, err := os.ReadDir(backing)
	prepareMust(t, err)
	if len(entries) != 2 || entries[0].Name() != "a" || entries[1].Name() != "z" {
		t.Fatal("partial tree or retained journal", entries)
	}
	for _, name := range []string{"a", "z"} {
		prepareExpectBytes(t, filepath.Join(backing, name), "issued-prepare-"+name+"\n")
	}
	var got, want unix.Stat_t
	prepareMust(t, unix.Stat(backing, &got))
	prepareMust(t, unix.Stat(source, &want))
	if got.Mode != want.Mode || got.Uid != want.Uid || got.Gid != want.Gid || got.Mtim != want.Mtim {
		t.Fatal("root metadata differs", got, want)
	}
	b := make([]byte, 64)
	n, err := unix.Getxattr(backing, "user.prepare", b)
	prepareMust(t, err)
	if string(b[:n]) != "source-root" {
		t.Fatal("root xattr differs")
	}
}

// No PREPARE deadline: only connection setup and fixture joins are budgeted.
func prepareTCP(t *testing.T, worker func(context.Context, net.Conn) error) (net.Conn, func() error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	prepareMust(t, err)
	defer listener.Close()
	prepareMust(t, listener.SetDeadline(time.Now().Add(5*time.Second)))
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	prepareMust(t, err)
	peer, err := listener.Accept()
	prepareMust(t, err)
	done := make(chan error, 1)
	go func() { done <- worker(context.Background(), peer) }()
	waited := false
	var result error
	join := func() error {
		if !waited {
			select {
			case result = <-done:
				waited = true
			case <-time.After(10 * time.Second):
				t.Fatal("owned TLS server did not join")
			}
		}
		return result
	}
	t.Cleanup(func() { raw.Close(); peer.Close(); join() })
	return raw, join
}

// Bounded logs and one creating OS thread through the sole real cmd.Wait.
// A timeout/kill request never substitutes for actual process exit observation.
type prepareOutput struct {
	mu        sync.Mutex
	file      *os.File
	remaining int
}

func (o *prepareOutput) Write(b []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := min(len(b), o.remaining)
	if n > 0 {
		if _, err := o.file.Write(b[:n]); err != nil {
			return 0, err
		}
		o.remaining -= n
	}
	return len(b), nil
}

func prepareOwnInitializer(t *testing.T, base string, hello a.DataHello, mode string, safe *bool) nativePrepareEvidence {
	t.Helper()
	rootfs, err := os.Open(filepath.Join(base, "rootfs"))
	prepareMust(t, err)
	defer rootfs.Close()
	mounts, err := os.Open(filepath.Join(base, "mounts"))
	prepareMust(t, err)
	defer mounts.Close()
	ack, writer, err := os.Pipe()
	prepareMust(t, err)
	defer ack.Close()
	defer writer.Close()
	report, err := os.OpenFile(filepath.Join(base, mode+"-evidence.json"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	prepareMust(t, err)
	defer report.Close()
	plan, err := os.OpenFile(filepath.Join(base, mode+"-tuple.json"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	prepareMust(t, err)
	defer plan.Close()
	prepareMust(t, json.NewEncoder(plan).Encode(hello))
	prepareMust(t, plan.Sync())
	_, err = plan.Seek(0, io.SeekStart)
	prepareMust(t, err)
	output, err := os.OpenFile(filepath.Join(base, mode+"-output.txt"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	prepareMust(t, err)
	defer output.Close()
	binary, err := os.Executable()
	prepareMust(t, err)
	cmd := exec.Command(binary, "-test.run=^TestNativePrepareInitializerChild$", "-test.timeout=45s", "-native-prepare-child="+mode)
	cmd.Env = []string{"TMPDIR=/scratch"}
	cmd.ExtraFiles = []*os.File{rootfs, mounts, writer, report, plan}
	capture := &prepareOutput{file: output, remaining: 64 << 10}
	cmd.Stdout, cmd.Stderr = capture, capture
	cmd.WaitDelay = 2 * time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	started, done := make(chan error, 1), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		err := cmd.Wait()
		done <- err
		if cmd.ProcessState == nil {
			select {}
		}
	}()
	prepareMust(t, <-started)
	joined := false
	defer func() {
		if !joined {
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
				joined = cmd.ProcessState != nil
			case <-time.After(10 * time.Second):
			}
		}
		if pidfd >= 0 {
			unix.Close(pidfd)
		}
		if !joined {
			*safe = false
			t.Error("unjoined initializer: retain fixture; no retirement")
		}
	}()
	prepareMust(t, writer.Close())
	if pidfd < 0 {
		t.Fatal("owned initializer missing pidfd")
	}
	if mode == "first-publication" {
		prepareMust(t, ack.SetReadDeadline(time.Now().Add(30*time.Second)))
		var one [1]byte
		_, err := io.ReadFull(ack, one[:])
		prepareMust(t, err)
		if one[0] != 1 {
			t.Fatal("wrong semantic checkpoint")
		}
		// Persist the checkpoint observation and its parent directory before killing.
		dir, err := os.Open(base)
		prepareMust(t, err)
		prepareMust(t, dir.Sync())
		prepareMust(t, dir.Close())
		prepareMust(t, unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0))
	}
	select {
	case err = <-done:
		joined = cmd.ProcessState != nil
	case <-time.After(50 * time.Second):
		t.Fatal("initializer fixture budget exceeded")
	}
	if !joined {
		t.Fatal("Wait did not observe owned exit")
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatal("missing actual Wait status")
	}
	if mode == "first-publication" {
		if !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("checkpoint did not end by owned SIGKILL", err)
		}
	} else if err != nil {
		t.Fatal("initializer child failed; private output retained", err)
	}
	data, err := io.ReadAll(io.LimitReader(report, 8193))
	prepareMust(t, err)
	if len(data) > 8192 {
		t.Fatal("child evidence exceeded bound")
	}
	var evidence nativePrepareEvidence
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	prepareMust(t, decoder.Decode(&evidence))
	if decoder.Decode(new(any)) != io.EOF || evidence.Hello != hello {
		t.Fatal("child evidence tuple differs")
	}
	return evidence
}

func TestNativePrepareInitializerChild(t *testing.T) {
	mode := *nativePrepareChild
	if mode == "" {
		t.Skip("owned initializer child only")
	}
	if mode != "positive" && mode != "first-publication" && mode != "recovery" {
		t.Fatal("unknown closed initializer case")
	}
	prepareProfile(t)
	plan := os.NewFile(7, "owned-prepare-tuple")
	if plan == nil {
		t.Fatal("missing tuple descriptor")
	}
	defer plan.Close()
	var hello a.DataHello
	decoder := json.NewDecoder(io.LimitReader(plan, 4097))
	decoder.DisallowUnknownFields()
	prepareMust(t, decoder.Decode(&hello))
	if decoder.Decode(new(any)) != io.EOF || hello.Binding.Prepare == "" || hello.Binding.Role != a.PrepareRole || hello.Binding.Mode != a.ReadWrite {
		t.Fatal("not an exact PREPARE binding")
	}
	_, err := d.AttachmentBinding(hello)
	prepareMust(t, err)
	// Fixed inherited directory roots, not arbitrary caller path arguments. The
	// same private initializer used by managed boot opens A/root and takes flock.
	rootfs, base := "/proc/self/fd/3/.", "/proc/self/fd/4/."
	mount := protocol.Mount{Source: "data", Destination: "/seed", ManagedAttachment: string(hello.Binding.Attachment)}
	var checkpoint *confinedPublication
	evidence := nativePrepareEvidence{Hello: hello, Stage: mode}
	if mode == "first-publication" {
		checkpoint = &confinedPublication{hello: hello}
	}
	if mode == "recovery" {
		root, err := openManagedRoot(base, mount.ManagedAttachment)
		prepareMust(t, err)
		evidence, err = nativePrepareObserve(root.fd, hello, mode, 0)
		prepareMust(t, err)
		prepareMust(t, root.close())
	}
	err = initializeManagedVolumeAt(rootfs, base, mount, checkpoint)
	if err != nil {
		evidence.InitializerError = err.Error()
	}
	// A first-publication return is always failure: actual journal creation may
	// expose unsupported NameToHandleAt before the requested stage is reached.
	if mode == "first-publication" {
		t.Fatalf("initializer never held first-publication checkpoint: %v", err)
	}
	prepareMust(t, nativePrepareWriteEvidence(evidence))
	if mode == "positive" && err != nil {
		t.Fatal(fmt.Errorf("real issued-PREPARE initializer positive control: %w", err))
	}
}
