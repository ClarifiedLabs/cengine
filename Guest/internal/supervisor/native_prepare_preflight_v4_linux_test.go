//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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
	"unsafe"

	"dev.cengine/guest/internal/protocol"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	f "dev.cengine/guest/internal/storagefuse"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Tagged test-binary-only closed cases; no production flag or global IO hook.
var nativePrepareV4Child = flag.String("native-prepare-v4-child", "", "owned initializer: positive, first-publication, recovery")

func TestNativeIssuedPrepareInitializerPreflightV4(t *testing.T) {
	if *nativePrepareV4Child != "" {
		t.Fatal("child selector requires the exact child test")
	}
	prepareV4Profile(t)
	for _, name := range []string{"positive", "first-publication-fresh-attachment"} {
		if !t.Run(name, func(t *testing.T) { prepareV4Preflight(t, name != "positive") }) {
			return // never continue after a failed/unjoined fixture
		}
	}
}

func prepareV4Profile(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("requires disposable native Linux root fixture")
	}
	if filepath.Clean(os.TempDir()) != "/scratch" {
		t.Fatal("requires TMPDIR=/scratch")
	}
	var uts unix.Utsname
	prepareV4Must(t, unix.Uname(&uts))
	if !strings.HasPrefix(string(bytes.TrimRight(uts.Release[:], "\x00")), "6.18.") {
		t.Fatal("requires patched Linux 6.18")
	}
	var fs unix.Statfs_t
	prepareV4Must(t, unix.Statfs("/scratch", &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("requires real ext4 /scratch")
	}
}

func prepareV4Preflight(t *testing.T, interrupt bool) {
	base, err := os.MkdirTemp("/scratch", "prepare-preflight-")
	prepareV4Must(t, err)
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
			prepareV4Must(t, os.RemoveAll(base))
		} else {
			t.Logf("retained prepare evidence: %s", base)
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
	t.Cleanup(func() { prepareV4Must(t, root.Close()) })
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
			if err := service.Close(); err != nil {
				safe = false
				t.Error(err)
			}
		}
	})
	ready, err := service.Ready()
	prepareV4Must(t, err)
	controller, control, closeControl := prepareV4Control(t, service, ready, controllerKey)
	defer closeControl()
	volume := prepareV4ID(t)
	prepareV4Call(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: prepareV4ID(t), Store: ready.Store.ID, Volume: volume, Name: "data"}})
	backing := filepath.Join(base, "store/volumes/data")
	old, key := prepareV4Binding(t, ready, volume)
	reserve := a.ReserveRequest{Operation: prepareV4ID(t), Prepare: old.Binding.Prepare, Attachments: []a.Binding{old.Binding}}
	prepareV4Call(t, control, c.Request{ReservePrepare: &reserve})
	bootstrapMount, cert, join := prepareV4MountBootstrap(t, base, service, ready, controller, control, old, key)
	mode := "positive"
	if interrupt {
		mode = "first-publication"
	}
	before, mount := prepareV4OwnInitializer(t, base, old, mode, bootstrapMount, &safe)
	if !interrupt {
		prepareV4VerifyTree(t, backing, seed)
		mount.assertGone(t) // child proved CloseGracefully and Done before its joined exit
		join()
		receipt := prepareV4Drain(t, control, old)
		prepareV4Complete(t, control, old, receipt)
		return
	}
	if before.Stage != "first-publication" || before.Count != 1 || before.Hello != old {
		t.Fatal("wrong one-shot checkpoint evidence")
	}
	// This manifest was made by the actual initializer, never staged by the test.
	journal := filepath.Join(backing, confinedCopyTransactionName, confinedCopyManifestName)
	manifestBytes, err := os.ReadFile(journal)
	prepareV4Must(t, err)
	var manifest managedCopyManifest
	prepareV4Must(t, json.Unmarshal(manifestBytes, &manifest))
	if manifest.Version != 4 || manifest.Root == nil || len(manifest.Entries) != 2 {
		t.Fatal("missing actual version-4 two-entry journal")
	}
	prepareV4Must(t, validateManagedManifest(manifest))
	if manifest.Physical.Store != ready.Store.ID || manifest.Physical.Volume != volume || manifest.Physical.BackingUUID == ([16]byte{}) || !validManagedObject(manifest.Physical.Root) {
		t.Fatal("journal lacks authenticated physical store/volume identity")
	}
	if before.Root.Filesystem != manifest.Root.Filesystem || before.Root.Inode != manifest.Root.Inode {
		t.Fatal("checkpoint root differs from real journal")
	}
	prepareV4Must(t, os.WriteFile(filepath.Join(base, "interrupted-manifest.json"), manifestBytes, 0600))
	prepareV4ExpectBytes(t, filepath.Join(backing, "a"), "issued-prepare-a\n")
	if _, err := os.Stat(filepath.Join(backing, "z")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("more than first entry published", err)
	}
	prepareV4ExpectBytes(t, filepath.Join(backing, confinedCopyTransactionName, confinedCopyStagingName, "z"), "issued-prepare-z\n")
	// SIGKILL also kills the child-owned FUSE server. Actual Wait joins that
	// process; abort the pinned exact mount, then join DATA. Neither is a drain
	// receipt: still require the production controller's real durability barrier.
	mount.abort(t)
	join()
	receipt := prepareV4Drain(t, control, old)
	afterDrain, err := os.ReadFile(journal)
	prepareV4Must(t, err)
	if !bytes.Equal(manifestBytes, afterDrain) {
		t.Fatal("drain rewrote copy-up journal")
	}
	fresh, freshKey := prepareV4Binding(t, ready, volume)
	if fresh.Binding.Prepare == old.Binding.Prepare || fresh.Binding.Attachment == old.Binding.Attachment || fresh.Binding.Key == old.Binding.Key {
		t.Fatal("successor identity reused")
	}
	successor := a.ReserveRequest{Operation: prepareV4ID(t), Prepare: fresh.Binding.Prepare, Attachments: []a.Binding{fresh.Binding}}
	prepareV4Call(t, control, c.Request{ReplacePrepare: &a.ReplaceRequest{Operation: prepareV4ID(t), Prepare: old.Binding.Prepare, Receipts: []a.Receipt{receipt}, Successor: successor}})
	snapshot := prepareV4Call(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	if snapshot.Prepares[old.Binding.Prepare].Phase != a.Replaced || snapshot.Attachments[old.Binding.Attachment].Phase != a.Drained {
		t.Fatal("replacement lacks durable predecessor drain")
	}
	freshBootstrap, freshCert, freshJoin := prepareV4MountBootstrap(t, base, service, ready, controller, control, fresh, freshKey)
	recovered, freshMount := prepareV4OwnInitializer(t, base, fresh, "recovery", freshBootstrap, &safe)
	if bytes.Equal(cert, freshCert) || mount.path == freshMount.path {
		t.Fatal("certificate or mount reused")
	}
	t.Logf("first-publication journal SHA256=%x old-root=%+v fresh-root=%+v old-entries=%+v fresh-entries=%+v", sha256.Sum256(manifestBytes), before.Root, recovered.Root, before.Entries, recovered.Entries)
	// Always drain genuinely joined recovery, even when production identity guards
	// reject it. A returned initializer error is diagnostic, NOT successful recovery.
	freshMount.assertGone(t) // actual child CloseGracefully + Done, never inferred drain
	freshJoin()
	freshReceipt := prepareV4Drain(t, control, fresh)
	if recovered.InitializerError != "" {
		t.Fatalf("real fresh-P/A initializer recovery failed (identity checks unchanged): %s", recovered.InitializerError)
	}
	prepareV4VerifyTree(t, backing, seed) // detects silent handle-mismatch/skipped rollback
	prepareV4Complete(t, control, fresh, freshReceipt)
}

func prepareV4Binding(t *testing.T, ready s.Ready, volume a.ID) (a.DataHello, p.Key) {
	key, err := p.NewAttachmentKey(p.PrepareRole)
	prepareV4Must(t, err)
	pin, err := key.Fingerprint()
	prepareV4Must(t, err)
	return a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: prepareV4ID(t), Prepare: prepareV4ID(t), Container: a.ContainerID(strings.Repeat("b", 64)), Launch: prepareV4ID(t), Key: a.Fingerprint(pin.String()), Role: a.PrepareRole, Mode: a.ReadWrite}}, key
}

func prepareV4JoinedMount(t *testing.T, m *f.Mounted) {
	t.Helper()
	select {
	case <-m.Done():
	default:
		t.Fatal("mount close returned without actual join")
	}
}
func prepareV4Drain(t *testing.T, control *c.Client, h a.DataHello) a.Receipt {
	t.Helper()
	b := h.Binding
	r := prepareV4Call(t, control, c.Request{Retire: &a.RetireRequest{Operation: prepareV4ID(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}}).Receipt
	if r == nil || r.Schema != a.SchemaVersion || r.Store != b.Store || r.Volume != b.Volume || r.Attachment != b.Attachment || r.Prepare != b.Prepare || r.Prepare == "" || r.Revision == 0 {
		t.Fatal("missing exact real PREPARE drain receipt")
	}
	snap := prepareV4Call(t, control, c.Request{Query: &c.Empty{}}).Snapshot
	record := snap.Attachments[b.Attachment]
	if record.Phase != a.Drained || record.Receipt == nil || *record.Receipt != *r {
		t.Fatal("receipt not in durable authority snapshot")
	}
	return *r
}
func prepareV4Complete(t *testing.T, control *c.Client, h a.DataHello, r a.Receipt) {
	prepareV4Call(t, control, c.Request{CompletePrepare: &a.CompleteRequest{Operation: prepareV4ID(t), Prepare: h.Binding.Prepare, Receipts: []a.Receipt{r}, Attestation: a.Attestation{Prepare: h.Binding.Prepare, Succeeded: true, CleanCopyUp: true}}})
}
func prepareV4ExpectBytes(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	prepareV4Must(t, err)
	if string(b) != want {
		t.Fatal("wrong bytes", path)
	}
}
func prepareV4VerifyTree(t *testing.T, backing, source string) {
	t.Helper()
	entries, err := os.ReadDir(backing)
	prepareV4Must(t, err)
	if len(entries) != 2 || entries[0].Name() != "a" || entries[1].Name() != "z" {
		t.Fatal("partial tree or retained journal", entries)
	}
	for _, name := range []string{"a", "z"} {
		prepareV4ExpectBytes(t, filepath.Join(backing, name), "issued-prepare-"+name+"\n")
	}
	var got, want unix.Stat_t
	prepareV4Must(t, unix.Stat(backing, &got))
	prepareV4Must(t, unix.Stat(source, &want))
	if got.Mode != want.Mode || got.Uid != want.Uid || got.Gid != want.Gid || got.Mtim != want.Mtim {
		t.Fatal("root metadata differs", got, want)
	}
	b := make([]byte, 64)
	n, err := unix.Getxattr(backing, "user.prepare", b)
	prepareV4Must(t, err)
	if string(b[:n]) != "source-root" {
		t.Fatal("root xattr differs")
	}
}

// No PREPARE deadline: only connection setup and fixture joins are budgeted.
func prepareV4TCP(t *testing.T, worker func(context.Context, net.Conn) error) (net.Conn, func() error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	prepareV4Must(t, err)
	defer listener.Close()
	prepareV4Must(t, listener.SetDeadline(time.Now().Add(5*time.Second)))
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	prepareV4Must(t, err)
	peer, err := listener.Accept()
	prepareV4Must(t, err)
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
type prepareV4Output struct {
	mu        sync.Mutex
	file      *os.File
	remaining int
}

func (o *prepareV4Output) Write(b []byte) (int, error) {
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

func prepareV4OwnInitializer(t *testing.T, base string, hello a.DataHello, mode string, bootstrap *prepareV4Bootstrap, safe *bool, snapshotProgress ...func()) (nativePrepareEvidence, *prepareV4ChildMount) {
	t.Helper()
	snapshotFence := mode == "snapshot-fd" || mode == "snapshot-mmap" || mode == "snapshot-atime" || mode == "snapshot-queue" || mode == "snapshot-death"
	if (mode == "snapshot-foreign" && len(snapshotProgress) != 1) || (snapshotFence && len(snapshotProgress) != 2) || (mode != "snapshot-foreign" && !snapshotFence && len(snapshotProgress) != 0) {
		t.Fatal("snapshot progress is confined to the closed RTM-101 case")
	}
	mounted := &prepareV4ChildMount{path: bootstrap.path}
	rootfs, err := os.Open(filepath.Join(base, "rootfs"))
	prepareV4Must(t, err)
	defer rootfs.Close()
	mounts, err := os.Open(filepath.Join(base, "mounts"))
	prepareV4Must(t, err)
	defer mounts.Close()
	ack, writer, err := os.Pipe()
	prepareV4Must(t, err)
	defer ack.Close()
	defer writer.Close()
	report, err := os.OpenFile(filepath.Join(base, mode+"-evidence.json"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	prepareV4Must(t, err)
	defer report.Close()
	plan, err := os.OpenFile(filepath.Join(base, mode+"-tuple.json"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	prepareV4Must(t, err)
	defer plan.Close()
	prepareV4Must(t, json.NewEncoder(plan).Encode(hello))
	prepareV4Must(t, plan.Sync())
	_, err = plan.Seek(0, io.SeekStart)
	prepareV4Must(t, err)
	output, err := os.OpenFile(filepath.Join(base, mode+"-output.txt"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	prepareV4Must(t, err)
	defer output.Close()
	binary, err := os.Executable()
	prepareV4Must(t, err)
	cmd := exec.Command(binary, "-test.run=^TestNativePrepareInitializerChildV4$", "-test.timeout=45s", "-native-prepare-v4-child="+mode)
	cmd.Env = []string{"TMPDIR=/scratch"}
	release, proceed, err := os.Pipe()
	prepareV4Must(t, err)
	defer release.Close()
	defer proceed.Close()
	cmd.ExtraFiles = []*os.File{rootfs, mounts, writer, report, plan, bootstrap.sealed, bootstrap.data, release}
	var snapshotProceed *os.File
	if mode == "snapshot-foreign" || snapshotFence {
		var snapshotRelease *os.File
		snapshotRelease, snapshotProceed, err = os.Pipe()
		prepareV4Must(t, err)
		defer snapshotRelease.Close()
		defer snapshotProceed.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, snapshotRelease) // fixed FD 11, no public hook
	}
	capture := &prepareV4Output{file: output, remaining: 64 << 10}
	cmd.Stdout, cmd.Stderr = capture, capture
	cmd.WaitDelay = 2 * time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	started, done := make(chan error, 1), make(chan error, 1)
	var diagnostic *prepareDiagnosticOwner
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		diagnostic = ownPrepareDiagnostic(cmd.Process.Pid, pidfd)
		started <- nil // publishes the private pidfd duplicate; no proc reads here
		err := cmd.Wait()
		done <- err
		if cmd.ProcessState == nil {
			select {}
		}
	}()
	prepareV4Must(t, <-started)
	reportDiagnostic, stopDiagnostic := observePrepareDiagnostic(t, diagnostic)
	defer stopDiagnostic()
	joined := false
	// Only an acknowledged, non-death snapshot may release its existing owner
	// handshake on assertion failure. This is not a drain or success receipt.
	snapshotHeld := false
	t.Cleanup(func() {
		if !*safe || !joined {
			return
		}
		if mounted.pin != nil {
			// Assertion failures still abort the exact mount, never manufacture a
			// receipt. A failed abort retains all service/backing evidence.
			*safe = false
			if mounted.present(t) {
				mounted.abort(t)
			} else {
				// The child may have already aborted on a bootstrap failure.
				mounted.assertGone(t)
				prepareV4Must(t, mounted.pin.Close())
				mounted.pin = nil
			}
			*safe = true
		} else if mounted.id == 0 || mounted.present(t) {
			*safe = false
			t.Error("child mount teardown unproven; retain fixture")
		}
	})
	defer func() {
		reportDiagnostic() // never waits or extends the existing kill/join budgets
		if !joined {
			released := false
			if snapshotHeld {
				// One byte on the private empty pipe lets the original owner run
				// real FinishCopy before consumer cleanup tries to join blocked IO.
				n, err := snapshotProceed.Write([]byte{5})
				released = err == nil && n == 1
				if !released {
					t.Errorf("snapshot cleanup release failed: n=%d err=%v", n, err)
				}
			}
			if !released && pidfd >= 0 {
				killErr := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
				prepareDiagnosticKillResult(t, "cleanup", killErr)
			}
			select {
			case <-done:
				joined = cmd.ProcessState != nil
			case <-time.After(10 * time.Second):
				// No second wait budget. An unjoined release attempt is retained
				// as unproven teardown, even after this exact-owned kill.
				if released && pidfd >= 0 {
					killErr := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
					prepareDiagnosticKillResult(t, "cleanup", killErr)
				}
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
	prepareV4Must(t, writer.Close())
	prepareV4Must(t, release.Close())
	prepareV4Must(t, bootstrap.data.Close()) // no parent duplicate may keep DATA alive
	prepareV4Must(t, bootstrap.sealed.Close())
	prepareV4Must(t, ack.SetReadDeadline(time.Now().Add(30*time.Second)))
	var mountedAck [1]byte
	_, err = io.ReadFull(ack, mountedAck[:])
	prepareV4Must(t, err)
	if mountedAck[0] != 2 {
		t.Fatal("missing actual child mount construction acknowledgement")
	}
	mounted.capture(t)
	if mode != "first-publication" && mode != "snapshot-death" {
		// O_PATH pins make normal umount busy; retain one only for SIGKILL cleanup.
		prepareV4Must(t, mounted.pin.Close())
		mounted.pin = nil
	}
	if snapshotFence {
		snapshotProgress[0]() // consumers and dirty pages exist before actual BeginCopy
	}
	_, err = proceed.Write([]byte{3})
	prepareV4Must(t, err)
	if pidfd < 0 {
		t.Fatal("owned initializer missing pidfd")
	}
	if mode == "snapshot-foreign" || snapshotFence {
		prepareV4Must(t, ack.SetReadDeadline(time.Now().Add(15*time.Second)))
		var held [1]byte
		_, err = io.ReadFull(ack, held[:])
		prepareV4Must(t, err)
		if held[0] != 4 {
			t.Fatal("missing mounted BeginCopy acknowledgement")
		}
		snapshotHeld = mode != "snapshot-death"
		snapshotProgress[len(snapshotProgress)-1]() // actual independent W while V remains fenced
		if mode == "snapshot-death" {
			// Exact owned initializer death, after the parent observed Begin and
			// real original-consumer fence waits. Never a successful completion.
			killErr := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			prepareDiagnosticKillResult(t, "snapshot-death", killErr)
			prepareV4Must(t, killErr)
		} else {
			_, err = snapshotProceed.Write([]byte{5})
			snapshotHeld = false
			prepareV4Must(t, err)
		}
	}
	if mode == "first-publication" {
		prepareV4Must(t, ack.SetReadDeadline(time.Now().Add(30*time.Second)))
		var one [1]byte
		_, err := io.ReadFull(ack, one[:])
		prepareV4Must(t, err)
		if one[0] != 1 {
			t.Fatal("wrong semantic checkpoint")
		}
		// Persist the checkpoint observation and its parent directory before killing.
		dir, err := os.Open(base)
		prepareV4Must(t, err)
		prepareV4Must(t, dir.Sync())
		prepareV4Must(t, dir.Close())
		reportDiagnostic()
		killErr := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		prepareDiagnosticKillResult(t, "first-publication", killErr)
		prepareV4Must(t, killErr)
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
	if mode == "first-publication" || mode == "snapshot-death" {
		if !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("checkpoint did not end by owned SIGKILL", err)
		}
	} else if err != nil {
		t.Fatal("initializer child failed; private output retained", err)
	}
	data, err := io.ReadAll(io.LimitReader(report, 8193))
	prepareV4Must(t, err)
	if len(data) > 8192 {
		t.Fatal("child evidence exceeded bound")
	}
	var evidence nativePrepareEvidence
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	prepareV4Must(t, decoder.Decode(&evidence))
	if decoder.Decode(new(any)) != io.EOF || evidence.Hello != hello {
		t.Fatal("child evidence tuple differs")
	}
	return evidence, mounted
}

func TestNativePrepareInitializerChildV4(t *testing.T) {
	mode := *nativePrepareV4Child
	if mode == "" {
		t.Fatal("owned initializer child requires its exact selector")
	}
	if mode != "positive" && mode != "first-publication" && mode != "recovery" && mode != "snapshot-foreign" && mode != "snapshot-fd" && mode != "snapshot-mmap" && mode != "snapshot-atime" && mode != "snapshot-queue" && mode != "snapshot-death" {
		t.Fatal("unknown closed initializer case")
	}
	prepareV4Profile(t)
	plan := os.NewFile(7, "owned-prepare-tuple")
	if plan == nil {
		t.Fatal("missing tuple descriptor")
	}
	defer plan.Close()
	var hello a.DataHello
	decoder := json.NewDecoder(io.LimitReader(plan, 4097))
	decoder.DisallowUnknownFields()
	prepareV4Must(t, decoder.Decode(&hello))
	if decoder.Decode(new(any)) != io.EOF || hello.Binding.Prepare == "" || hello.Binding.Role != a.PrepareRole || hello.Binding.Mode != a.ReadWrite {
		t.Fatal("not an exact PREPARE binding")
	}
	_, err := d.AttachmentBinding(hello)
	prepareV4Must(t, err)
	// Fixed inherited directory roots, not arbitrary caller path arguments. The
	// same private initializer used by managed boot opens A/root and takes flock.
	rootfs, base := "/proc/self/fd/3/.", "/proc/self/fd/4/."
	nativeMount := prepareV4ChildConstructMount(t, hello)
	if mode == "snapshot-queue" || mode == "snapshot-death" {
		snapshot101QueueOwner(t, hello, nativeMount, mode)
		return
	}
	if mode == "snapshot-fd" || mode == "snapshot-mmap" || mode == "snapshot-atime" {
		snapshot101FenceOwner(t, hello, nativeMount, mode)
		return
	}
	if mode == "snapshot-foreign" {
		snapshot101ForeignOwner(t, hello, nativeMount)
		return
	}
	mount := protocol.Mount{Source: "data", Destination: "/seed", ManagedAttachment: string(hello.Binding.Attachment)}
	var checkpoint *confinedPublication
	evidence := nativePrepareEvidence{Hello: hello, Stage: mode}
	if mode == "first-publication" {
		checkpoint = &confinedPublication{hello: hello}
	}
	if mode == "recovery" {
		// Observation must follow the real service fence too: the mount already
		// pinned THIS process, so this Begin cannot adopt a first caller.
		fd, err := unix.Open(filepath.Join(base, mount.ManagedAttachment, "root"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		prepareV4Must(t, err)
		root := &confinedRoot{fd: fd}
		copy := &managedCopy{root: root, scope: managedCopyScope{Store: string(hello.Binding.Store), Volume: string(hello.Binding.Volume), Prepare: string(hello.Binding.Prepare), Attachment: string(hello.Binding.Attachment)}, call: managedPrepareIoctl}
		prepareV4Must(t, copy.control(w.BeginCopy))
		evidence, err = nativePrepareObserve(root.fd, hello, mode, 0)
		prepareV4Must(t, err)
		prepareV4Must(t, root.close())
	}
	prepareDiagnosticMark(os.Stderr, prepareInitializeBegin)
	err = initializeManagedVolumeScopedAt(rootfs, base, mount, managedCopyScope{Store: string(hello.Binding.Store), Volume: string(hello.Binding.Volume), Prepare: string(hello.Binding.Prepare), Attachment: string(hello.Binding.Attachment)}, checkpoint)
	prepareDiagnosticMark(os.Stderr, prepareInitializeEnd)
	_ = prepareDiagnosticResult(os.Stderr, prepareInitializeEnd, err)
	if err != nil {
		evidence.InitializerError = err.Error()
	}
	// A first-publication return is always failure: actual journal creation may
	// expose unsupported NameToHandleAt before the requested stage is reached.
	if mode == "first-publication" {
		t.Fatalf("initializer never held first-publication checkpoint: %v", err)
	}
	prepareDiagnosticMark(os.Stderr, prepareCloseBegin)
	prepareV4Must(t, prepareDiagnosticResult(os.Stderr, prepareCloseEnd, nativeMount.CloseGracefully(context.Background())))
	prepareDiagnosticMark(os.Stderr, prepareCloseEnd)
	prepareDiagnosticMark(os.Stderr, prepareJoinBegin)
	prepareV4JoinedMount(t, nativeMount)
	prepareDiagnosticMark(os.Stderr, prepareJoinEnd)
	prepareDiagnosticMark(os.Stderr, prepareEvidenceBegin)
	prepareV4Must(t, nativePrepareWriteEvidence(evidence))
	prepareDiagnosticMark(os.Stderr, prepareEvidenceEnd)
	if mode == "positive" && err != nil {
		t.Fatal(fmt.Errorf("real issued-PREPARE initializer positive control: %w", err))
	}
}

// The successor binds authority setup to the real ext4 superblock UUID. The
// frozen v3 reproducer remains byte-for-byte intact alongside this test.
func prepareV4BackingUUID(t *testing.T, fd int) string {
	t.Helper()
	// Linux 6.18 FS_IOC_GETFSUUID: _IOR(0x15, 0, struct fsuuid2).
	var buffer [17]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x80111500), uintptr(unsafe.Pointer(&buffer[0])))
	if errno != 0 {
		t.Fatal(errno)
	}
	if buffer[0] != 16 {
		t.Fatal("unsupported backing UUID")
	}
	b := buffer[1:]
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
