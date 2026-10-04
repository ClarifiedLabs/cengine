//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	c "dev.cengine/guest/internal/storageclient"
	s "dev.cengine/guest/internal/storageserver"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// This is an actual mount, not ProtocolServer or an injected capture/dispatch.
// Run only in the disposable Linux 6.18 patched-kernel fixture. Root on a stock
// kernel, a non-ext4 /scratch, or without the required capabilities FAILS.
func TestNativeMountedManagedV3(t *testing.T) { nativeMountedManagedV3(t, "") }
func TestNativeMountedManagedV3Graceful(t *testing.T) {
	for _, mode := range []string{"empty", "lookup", "pending-directory"} {
		t.Run(mode, func(t *testing.T) { nativeMountedManagedV3(t, mode) })
	}
}

// Public Mount + real authenticated DATA/authority + native syscalls. These
// prepare-role cases must also close cleanly; the older graceful cases exercised
// neither metadata changes nor completed xattr errno replies. No Session fake or
// synthetic credential/reply supplies the local completion proof.
func TestNativeMountedManagedV3PrepareGraceful(t *testing.T) {
	for _, mode := range []string{"prepare-metadata", "prepare-xattr-absent", "prepare-xattr-range", "prepare-listxattr-range"} {
		t.Run(mode, func(t *testing.T) { nativeMountedManagedV3(t, mode) })
	}
}

// Exercise actual asynchronous kernel RELEASEDIR without injected credentials,
// dispatch, sleeps, or a synthetic response. Hold one real directory FD until
// the shutdown-created sync FD's successful native reply has been observed.
func nativePendingDirectoryClose(t *testing.T, mount *Mounted) {
	t.Helper()
	held, err := os.Open(mount.path)
	nativeMust(t, err)
	defer held.Close()
	d := &mount.lifecycle.directories
	d.mu.Lock()
	before := d.completed
	count := len(d.handles)
	d.mu.Unlock()
	if count != 1 {
		t.Fatalf("unexpected initial directory grants: %d", count)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner := make(chan error, 1)
	go func() { owner <- mount.CloseGracefully(ctx) }()
	for {
		d.mu.Lock()
		completed, changed, failure := d.completed, d.changed, d.err
		d.mu.Unlock()
		if failure != nil {
			t.Fatal(failure)
		}
		if completed > before {
			break
		}
		select {
		case err := <-owner:
			t.Fatalf("unmount overtook live directory release: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-changed:
		}
	}
	select {
	case err := <-owner:
		t.Fatalf("owning close finished while directory open: %v", err)
	default:
	}
	late, lateErr := os.Open(mount.path)
	if lateErr == nil {
		_ = late.Close()
		t.Fatal("post-snapshot OPENDIR grant was admitted")
	}
	if !errors.Is(lateErr, unix.EBUSY) {
		t.Fatalf("late OPENDIR: %v", lateErr)
	}
	secondary, cancelSecondary := context.WithCancel(context.Background())
	cancelSecondary()
	if err := mount.CloseGracefully(secondary); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if mount.fs.stopped.Load() || mount.Err() != nil {
		t.Fatal("secondary waiter aborted the owner")
	}
	nativeMust(t, held.Close()) // real asynchronous callback + RPC + kernel delivery
	nativeMust(t, nativeWait(t, "directory-release graceful close", owner))
	select {
	case <-mount.Done():
	default:
		t.Fatal("graceful close did not join")
	}
	d.mu.Lock()
	count, completed := len(d.handles), d.completed
	d.mu.Unlock()
	if count != 0 || completed != before+2 {
		t.Fatalf("unjoined directory deliveries: grants=%d delivered=%d baseline=%d", count, completed, before)
	}
}

// Fixed words/indices only: the outer setup process keeps stdout private and
// reserves half of its 128 KiB log for an independent kernel-stack observation.
// Do not use t.Log here: its per-line source prefix exhausts that phase budget.
var nativePhaseStarted = time.Now()
var nativePhaseOutput io.Writer = os.Stdout

func nativePhase(stage string, index int, after bool) {
	edge := byte('b')
	if after {
		edge = 'e'
	}
	fmt.Fprintf(nativePhaseOutput, "P %s %d %c %d\n", stage, index, edge, time.Since(nativePhaseStarted).Milliseconds())
}

func nativeMountedManagedV3(t *testing.T, graceful string) {
	if graceful == "sparse-mmap" || graceful == "fsx" {
		output := newNativeChildOutput(os.Stdout)
		nativePhaseOutput = output
		// Registered before fixture cleanup: a blocked receipt sink cannot hold teardown.
		t.Cleanup(func() { nativePhaseOutput = os.Stdout; output.closeLive() })
	}
	report := func(args ...any) {
		if graceful == "sparse-mmap" || graceful == "fsx" {
			fmt.Fprintln(nativePhaseOutput, args...)
			t.Fail()
		} else {
			t.Error(args...)
		}
	}
	reportf := func(format string, args ...any) { report(fmt.Sprintf(format, args...)) }
	logf := func(format string, args ...any) {
		if graceful == "sparse-mmap" || graceful == "fsx" {
			fmt.Fprintf(nativePhaseOutput, format+"\n", args...)
		} else {
			t.Logf(format, args...)
		}
	}
	nativePhase("setup", 0, false)
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root in the disposable managed-FUSE kernel fixture")
	}
	if filepath.Clean(os.TempDir()) != "/scratch" {
		t.Fatal("set TMPDIR=/scratch; the mounted fixture never uses the host's default temp directory")
	}
	var uts unix.Utsname
	nativeMust(t, unix.Uname(&uts))
	release := string(bytes.TrimRight(uts.Release[:], "\x00"))
	if !strings.HasPrefix(release, "6.18.") {
		t.Fatalf("requires the patched Linux 6.18 kernel, got %s", release)
	}
	var fs unix.Statfs_t
	nativeMust(t, unix.Statfs("/scratch", &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("/scratch must be actual ext4, not tmpfs/overlay/a simulated backend")
	}
	base, err := os.MkdirTemp("/scratch", "storagefuse-native-")
	nativeMust(t, err)
	// No unconditional TempDir cleanup: never recurse through a mount left behind
	// by a failed construction or teardown. Preserve evidence instead.
	safeToRemove := true
	t.Cleanup(func() {
		if graceful == "fsx" && t.Failed() {
			safeToRemove = false // retain full private fsx output even on later teardown failure
		}
		if !safeToRemove {
			logf("preserving %s: resources did not cleanly drain", base)
			return
		}
		info, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			reportf("preserving %s: mountinfo: %v", base, err)
			return
		}
		for _, line := range strings.Split(string(info), "\n") {
			p := strings.Fields(line)
			if len(p) > 4 && (p[4] == mountPath(base) || strings.HasPrefix(p[4], mountPath(base)+"/")) {
				reportf("preserving %s: fixture mount still present", base)
				return
			}
		}
		nativePhase("remove", 0, false)
		if err := os.RemoveAll(base); err != nil {
			report(err)
		}
		nativePhase("remove", 0, true)
	})
	nativeMust(t, os.Chmod(base, 0755)) // allow credential-child traversal; still root-owned/non-writable
	backing := filepath.Join(base, "store")
	nativeMust(t, os.Mkdir(backing, 0700)) // nonroot children cannot bypass FUSE
	nativeMust(t, os.Mkdir(filepath.Join(backing, "volumes"), 0755))
	volumePath := filepath.Join(backing, "volumes", "data")
	nativeMust(t, os.Mkdir(volumePath, 0755))
	nativeMust(t, unix.Chmod(volumePath, 0755)) // independent of the test runner's umask
	root, err := os.Open(backing)
	nativeMust(t, err)
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			report(err)
		}
	})

	pki := newNativePKI(t)
	serverKey, controllerKey, attachmentKey := nativeKey(t), nativeKey(t), nativeKey(t)
	serverConfig := pki.serverConfig(t, serverKey)
	serverRetirement := make(chan a.DataHello, 4)
	dataServerConfig := serverConfig.Clone()
	dataServerConfig.ClientCAs = nil // DATA accepts only DER roots; raw controller TLS still needs its pool.
	server, err := s.New(s.Config{TLSConfig: dataServerConfig, ClientRoots: [][]byte{pki.ca.Raw}, RequestRetirement: func(h a.DataHello, _ error) { serverRetirement <- h }})
	nativeMust(t, err)
	storeID, volumeID := nativeID(t), nativeID(t)
	nativePhase("authority", 0, false)
	bootstrap := nativeKey(t)
	authority, err := at.New(t, bootstrap, storeID, nativeFingerprint(t, controllerKey)).Initialize(a.Config{Root: root, DeviceID: nativeCopyDeviceID(t, volumePath), BootstrapKey: bootstrap.Public().(ed25519.PublicKey), Barrier: server.Barrier})
	nativeMust(t, err)
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			safeToRemove = false
			report(err)
		}
	})
	nativePhase("authority", 0, true)
	controller := nativeController(t, authority, pki, serverConfig, controllerKey)
	var volumeStat unix.Stat_t
	nativeMust(t, unix.Stat(volumePath, &volumeStat))
	nativeMust(t, authority.AddVolume(controller, a.VolumeRequest{Operation: nativeID(t), Volume: a.Volume{ID: volumeID, Name: "data", Root: a.RootIdentity{Device: uint64(volumeStat.Dev), Inode: volumeStat.Ino}}}))
	binding := a.Binding{Store: storeID, Volume: volumeID, Attachment: nativeID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: nativeID(t), Key: nativeFingerprint(t, attachmentKey), Role: a.RuntimeRole, Mode: a.ReadWrite}
	if strings.HasPrefix(graceful, "prepare-") {
		binding.Role, binding.Prepare = a.PrepareRole, nativeID(t)
		nativeMust(t, authority.ReservePrepare(controller, a.ReserveRequest{Operation: nativeID(t), Prepare: binding.Prepare, Attachments: []a.Binding{binding}}))
	}
	nativeMust(t, authority.RegisterAttachment(controller, a.RegisterRequest{Operation: nativeID(t), Binding: binding}))
	hello := a.DataHello{Epoch: authority.Epoch(), Binding: binding}
	retireRequest := a.RetireRequest{Operation: nativeID(t), Store: storeID, Volume: volumeID, Attachment: binding.Attachment, Launch: binding.Launch}

	serverRaw, clientRaw := nativeTCPPair(t)
	var interruptGate *nativeInterruptGate
	interruptReplies := make(chan fuse.ReplyDelivery, 64)
	if graceful == "interrupt" {
		interruptGate = &nativeInterruptGate{Conn: serverRaw, entered: make(chan struct{}), proceed: make(chan struct{})}
		serverRaw = interruptGate
	}
	clientConfig := pki.clientConfig(t, attachmentKey)
	clientTLS := tls.Client(clientRaw, clientConfig)
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	// Serve owns the raw connection and constructs TLS from its validated config.
	// Deliberately no prewrapped TLS, raw executor seam, or constructed Caller.
	go func() { serverDone <- server.Serve(ctx, authority, serverRaw) }()
	var mount *mounted
	childExchangeJoined := true
	childReaped := true // RTM-083 may not retire authority while its syscall child is unjoined.
	fuseFDsBefore := nativeFuseFDCount(t)
	var retirementCalls atomic.Int32
	adapterRetirement := make(chan error, 1)
	t.Cleanup(func() {
		if mount != nil {
			nativePhase("cleanup-close", 0, false)
			closed := make(chan error, 1)
			go func() { closed <- mount.Close() }()
			if err := nativeWait(t, "exact mount Close", closed); err != nil {
				safeToRemove = false
				report(err)
			}
			nativePhase("cleanup-close", 0, true)
		}
		_ = clientRaw.Close()
		cancel()
		nativePhase("data-join", 0, false)
		if err := nativeWait(t, "DATA server join", serverDone); errors.Is(err, errNativeJoinTimeout) {
			safeToRemove = false
			report(err)
		} else if err == nil && mount != nil {
			report("terminal DATA session unexpectedly returned success")
		}
		nativePhase("data-join", 0, true)
		if mount != nil {
			expectedRetirements := int32(1)
			if graceful != "" {
				expectedRetirements = 0
			}
			if retirementCalls.Load() != expectedRetirements {
				reportf("adapter retirement calls=%d", retirementCalls.Load())
			}
			select {
			case reason := <-adapterRetirement:
				if reason == nil {
					report("missing terminal reason")
				}
			default:
				if graceful == "" {
					report("missing adapter retirement request")
				}
			}
			select {
			case got := <-serverRetirement:
				if got != hello {
					report("server retired the wrong attachment/epoch")
				}
			default:
				report("missing server retirement request")
			}
		}
		if !sparseRetirementSafe(childReaped, childExchangeJoined) {
			safeToRemove = false
			report("syscall child or exchange unjoined; retirement receipt forbidden")
			return
		}
		drainCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		nativePhase("retire", 0, false)
		receipt, err := authority.Retire(drainCtx, controller, retireRequest)
		nativePhase("retire", 0, true)
		if err != nil {
			safeToRemove = false
			reportf("real controller retirement/barrier: %v", err)
			return
		}
		if receipt.Store != storeID || receipt.Volume != volumeID || receipt.Attachment != binding.Attachment || receipt.Revision == 0 {
			report("wrong drain receipt")
		}
		snapshot, err := authority.Query(controller)
		if err != nil || snapshot.Attachments[binding.Attachment].Phase != a.Drained {
			report("authority did not record DRAINED", err)
		}
		if mount != nil && safeToRemove {
			info, err := os.ReadFile("/proc/self/mountinfo")
			if err != nil || hasMountAt(string(info), mount.path) || hasMountID(string(info), mount.mountID) {
				report("exact mount survived teardown", err)
			}
			if _, err := os.Lstat(mount.path); !os.IsNotExist(err) {
				report("owned mountpoint not removed", err)
			}
			mount.fs.deviceMu.RLock()
			fd := mount.fs.fd
			mount.fs.deviceMu.RUnlock()
			if fd != -1 {
				report("capture descriptor retained after teardown")
			}
			if got := nativeFuseFDCount(t); got != fuseFDsBefore {
				reportf("FUSE descriptors leaked: before=%d after=%d", fuseFDsBefore, got)
			}
		}
	})
	handshakeCtx, stopHandshake := context.WithTimeout(context.Background(), 15*time.Second)
	err = clientTLS.HandshakeContext(handshakeCtx)
	stopHandshake()
	nativeMust(t, err)
	mountConfig := Config{Client: c.Config{Conn: clientTLS, TLSConfig: clientConfig, ServerPin: nativeFingerprint(t, serverKey), Authority: hello, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: (uint64(1) << (unix.CAP_LAST_CAP + 1)) - 1, Limits: c.DefaultLimits(), Timeout: 15 * time.Second}, Mountpoint: filepath.Join(base, "mount"), Retire: func(reason error) {
		retirementCalls.Add(1)
		select {
		case adapterRetirement <- reason:
		default:
		}
	}}
	nativePhase("setup", 0, true)
	nativePhase("mount", 0, false)
	if graceful == "interrupt" {
		nativeMust(t, validateMountConfig(mountConfig))
		mount, err = nativeMountObserved(mountConfig, func(reply fuse.ReplyDelivery) {
			if reply.Opcode == 36 || reply.Interrupted {
				select {
				case interruptReplies <- reply:
				default:
				}
			}
		})
	} else {
		mount, err = Mount(mountConfig)
	}
	nativePhase("mount", 0, true)
	nativeMust(t, err) // ENOSYS/EINVAL/EPERM/profile or ABI-3 capture errors are NOT skips.
	finishPrepare := func() error { return nil }
	if strings.HasPrefix(graceful, "prepare-") {
		finishPrepare = nativeBeginNoopPrepare(t, mount.Mountpoint())
	}
	if graceful != "" {
		if graceful == "pending-directory" {
			nativePendingDirectoryClose(t, mount)
			return
		}
		nativePhase("workload", 0, false)
		switch graceful {
		case "write-burst":
			nativeWriteBurst(t, mount.Mountpoint(), volumePath)
		case "sparse-mmap":
			nativeSparseMmap(t, mount, volumePath, &safeToRemove, &childReaped, &childExchangeJoined)
		case "fsx":
			nativeFsx(t, mount, base, &safeToRemove, &childReaped, &childExchangeJoined)
		case "interrupt":
			nativeInterruptCompletion(t, mount, interruptGate, interruptReplies)
		case "prepare-metadata":
			nativePrepareMetadata(t, mount.Mountpoint(), volumePath)
		case "prepare-xattr-absent":
			if _, err := unix.Getxattr(mount.Mountpoint(), "user.absent", nil); !errors.Is(err, unix.ENODATA) {
				t.Fatal("missing xattr must report ENODATA", err)
			}
		case "prepare-listxattr-range":
			nativeMust(t, unix.Setxattr(mount.Mountpoint(), "user.prepare", []byte("value"), 0))
			if _, err := unix.Listxattr(mount.Mountpoint(), make([]byte, 1)); !errors.Is(err, unix.ERANGE) {
				t.Fatal("short xattr list must report ERANGE", err)
			}
			buf := make([]byte, w.MaxXAttr)
			n, err := unix.Listxattr(mount.Mountpoint(), buf)
			nativeMust(t, err)
			if !bytes.Contains(buf[:n], []byte("user.prepare\x00")) {
				t.Fatal("xattr list retry lost attribute")
			}
		case "prepare-xattr-range":
			value := []byte("complete-value")
			nativeMust(t, unix.Setxattr(mount.Mountpoint(), "user.prepare", value, 0))
			if _, err := unix.Getxattr(mount.Mountpoint(), "user.prepare", make([]byte, 1)); !errors.Is(err, unix.ERANGE) {
				t.Fatal("short xattr buffer must report ERANGE", err)
			}
			buf := make([]byte, len(value))
			n, err := unix.Getxattr(mount.Mountpoint(), "user.prepare", buf)
			nativeMust(t, err)
			if !bytes.Equal(buf[:n], value) {
				t.Fatal("xattr retry lost data")
			}
		}
		if graceful == "lookup" {
			nativeMust(t, os.WriteFile(filepath.Join(volumePath, "graceful-existing"), []byte("payload"), 0600))
			_, err := os.Stat(filepath.Join(mount.path, "graceful-existing"))
			nativeMust(t, err)
		}
		nativePhase("workload", 0, true)
		nativeMust(t, finishPrepare())
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		nativePhase("graceful", 0, false)
		err = mount.CloseGracefully(closeCtx)
		nativePhase("graceful", 0, true)
		nativeMust(t, err)
		select {
		case <-mount.Done():
		default:
			t.Fatal("graceful result before join")
		}
		if mount.Err() != nil {
			t.Fatal(mount.Err())
		}
		return
	}
	if got := nativeFuseFDCount(t); got != fuseFDsBefore+2 {
		t.Fatalf("expected retained+server FUSE descriptors: before=%d after=%d", fuseFDsBefore, got)
	}
	if !mount.fs.negotiated.Load() || mount.client.Authority() != hello {
		t.Fatal("missing actual negotiated profile or immutable binding")
	}
	local, entry := mount.client.Root()
	if local != 1 || entry.Attr.Ino != volumeStat.Ino || entry.Attr.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatal("wrong pinned root")
	}
	info, err := os.ReadFile("/proc/self/mountinfo")
	nativeMust(t, err)
	if !mount.matchesMount(string(info)) || mount.mountID == 0 || mount.connection == 0 {
		t.Fatal("mount not bound to exact pinned descriptor/connection")
	}
	for _, line := range strings.Split(string(info), "\n") {
		p := strings.Fields(line)
		if len(p) > 5 && p[4] == mountPath(mount.path) {
			for _, option := range []string{"request_cred", "managed_close_to_open", "default_permissions", "allow_other", "nosuid", "nodev"} {
				if !strings.Contains(","+strings.ReplaceAll(line, " ", ",")+",", ","+option+",") {
					t.Fatalf("mountinfo missing %s: %s", option, line)
				}
			}
		}
	}
	if _, ok := mount.fs.client.(clientBridge); !ok {
		t.Fatal("test bypassed the real credential client")
	}
	var rootStat unix.Stat_t
	nativeMust(t, unix.Stat(mount.path, &rootStat)) // real GETATTR without FH/captured ioctl
	if rootStat.Ino != volumeStat.Ino {
		t.Fatal("root getattr is not the pinned ext4 inode")
	}

	t.Run("open-unlink-fstat-and-no-fh", func(t *testing.T) { nativeUnlinked(t, mount.path) })
	if !t.Run("shared-mmap-msync-fsync", func(t *testing.T) {
		nativeExecMmap(t, base, mount, volumePath, &safeToRemove)
	}) {
		return // do not issue more filesystem operations after a failed/timed-out child
	}
	t.Run("xattrs-root-directory-mode-zero", func(t *testing.T) { nativeXattrs(t, mount.path) })
	t.Run("abi3-metadata-times-truncate", func(t *testing.T) { nativeMetadata(t, mount.path, volumePath) })
	t.Run("real-process-groups-acl-killpriv", func(t *testing.T) { nativeCredentials(t, base, mount.path, volumePath) })
	if mount.fs.stopped.Load() {
		t.Fatalf("mount terminated during filesystem operations: %v", mount.client.Err())
	}
	logf("actual mounted profile/ABI-3 exercised: kernel=%s mountID=%d connection=%d", release, mount.mountID, mount.connection)
}

func nativeFuseFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	nativeMust(t, err)
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if os.IsNotExist(err) {
			continue
		} // the directory reader's descriptor closed
		nativeMust(t, err)
		if target == "/dev/fuse" {
			count++
		}
	}
	return count
}

func nativeUnlinked(t *testing.T, root string) {
	path := filepath.Join(root, "unlinked")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	nativeMust(t, err)
	defer unix.Close(fd)
	pinned, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	nativeMust(t, err)
	defer unix.Close(pinned)
	payload := []byte("retained-data")
	n, err := unix.Pwrite(fd, payload, 37)
	nativeMust(t, err)
	if n != len(payload) {
		t.Fatal("short pwrite")
	}
	nativeMust(t, unix.Fsync(fd))
	nativeMust(t, unix.Unlink(path))
	for _, handle := range []int{fd, pinned} {
		var st unix.Stat_t
		nativeMust(t, unix.Fstat(handle, &st))
		if st.Nlink != 0 || st.Size != int64(37+len(payload)) {
			t.Fatalf("unlinked fstat fd=%d nlink=%d size=%d", handle, st.Nlink, st.Size)
		}
	}
	buf := make([]byte, len(payload))
	n, err = unix.Pread(fd, buf, 37)
	nativeMust(t, err)
	if n != len(payload) || !bytes.Equal(buf, payload) {
		t.Fatal("unlinked data lost")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unlinked name survived", err)
	}
}

// Only the exec child may touch this mapping: fs/api.go's Deadlocks section and
// go-fuse/fuse/test/cachecontrol_test.go describe the self-mount page-fault hazard.
func nativeMmap(t *testing.T, root, backing string) {
	phase := func(name string, operation func()) {
		t.Helper()
		t.Logf("mmap phase=%s begin pid=%d", name, os.Getpid())
		operation()
		t.Logf("mmap phase=%s done", name)
	}
	path := filepath.Join(root, "mapped")
	fd := -1
	phase("open-create", func() {
		var err error
		fd, err = unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
		nativeMust(t, err)
	})
	defer func() { phase("close", func() { nativeMust(t, unix.Close(fd)) }) }()
	phase("ftruncate", func() { nativeMust(t, unix.Ftruncate(fd, 4096)) })
	var mapped []byte
	phase("mmap", func() {
		var err error
		mapped, err = unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		nativeMust(t, err)
	})
	defer func() { phase("munmap", func() { nativeMust(t, unix.Munmap(mapped)) }) }()
	payload := []byte("actual-shared-writeback")
	phase("mapped-store-page-fault", func() { copy(mapped[137:], payload) })
	phase("msync", func() { nativeMust(t, unix.Msync(mapped, unix.MS_SYNC)) })
	phase("fsync", func() { nativeMust(t, unix.Fsync(fd)) })
	for i, path := range []string{path, filepath.Join(backing, "mapped")} {
		phase([]string{"mounted-readback", "ext4-readback"}[i], func() {
			data, err := os.ReadFile(path)
			nativeMust(t, err)
			if len(data) != 4096 || !bytes.Equal(data[137:137+len(payload)], payload) {
				t.Fatal("mmap offset/count/backing mismatch")
			}
		})
	}
}

// Exercise the mutation/metadata portion of prepare through real kernel FUSE
// callbacks, not an injected supervisor. This is intentionally not a claim that
// the full Workload.Prepare/root-device boot composition ran.
func nativePrepareMetadata(t *testing.T, root, backing string) {
	t.Helper()
	stage := filepath.Join(root, "prepare-stage")
	nativeMust(t, os.Mkdir(stage, 0700))
	seed := filepath.Join(stage, "seed")
	file, err := os.OpenFile(seed, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	nativeMust(t, err)
	defer file.Close()
	payload := []byte("prepared-seed")
	n, err := file.Write(payload)
	nativeMust(t, err)
	if n != len(payload) {
		t.Fatal("short prepare write")
	}
	nativeMust(t, file.Chown(10001, 10002))
	nativeMust(t, file.Chmod(0640))
	nativeMust(t, file.Sync())
	nativeMust(t, file.Close())
	nativeMust(t, os.Rename(seed, filepath.Join(root, "seed")))
	nativeMust(t, os.Remove(stage))
	nativeMust(t, unix.Chown(root, 10001, 10002))
	nativeMust(t, unix.Chmod(root, 0750))
	directory, err := os.Open(root)
	nativeMust(t, err)
	defer directory.Close()
	nativeMust(t, directory.Sync())
	nativeMust(t, directory.Close())
	data, err := os.ReadFile(filepath.Join(backing, "seed"))
	nativeMust(t, err)
	var stat unix.Stat_t
	nativeMust(t, unix.Stat(backing, &stat))
	if !bytes.Equal(data, payload) || stat.Uid != 10001 || stat.Gid != 10002 || stat.Mode&0777 != 0750 {
		t.Fatal("prepare data/root metadata not applied to ext4")
	}
}

func nativeXattrs(t *testing.T, root string) {
	dir, file := filepath.Join(root, "xattr-dir"), filepath.Join(root, "xattr-file")
	nativeMust(t, os.Mkdir(dir, 0700))
	nativeMust(t, os.WriteFile(file, []byte("root-capability-read"), 0600))
	for _, path := range []string{root, dir, file} {
		value := []byte{0, 255, 7, 0}
		nativeMust(t, unix.Setxattr(path, "user.native", value, unix.XATTR_CREATE))
		if path != root {
			nativeMust(t, unix.Chmod(path, 0))
		}
		n, err := unix.Getxattr(path, "user.native", nil)
		nativeMust(t, err)
		if n != len(value) {
			t.Fatal("xattr size probe")
		}
		if _, err := unix.Getxattr(path, "user.native", make([]byte, 1)); !errors.Is(err, unix.ERANGE) {
			t.Fatal("xattr ERANGE lost", err)
		}
		buf := make([]byte, n)
		n, err = unix.Getxattr(path, "user.native", buf)
		nativeMust(t, err)
		if !bytes.Equal(buf[:n], value) {
			t.Fatal("xattr bytes lost")
		}
		n, err = unix.Listxattr(path, nil)
		nativeMust(t, err)
		buf = make([]byte, n)
		n, err = unix.Listxattr(path, buf)
		nativeMust(t, err)
		if !bytes.Contains(buf[:n], []byte("user.native\x00")) {
			t.Fatal("xattr omitted from list")
		}
		nativeMust(t, unix.Removexattr(path, "user.native"))
		if _, err := unix.Getxattr(path, "user.native", nil); !errors.Is(err, unix.ENODATA) {
			t.Fatal("removed xattr survived", err)
		}
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "root-capability-read" {
		t.Fatal("real root capabilities not preserved", err)
	}
}

// exec uses real Linux process credentials and supplementary groups. No wire
// Caller, Snapshot, fake ioctl, or identity-worker substitution exists in this test.
func nativeCredentials(t *testing.T, base, root, backing string) {
	executable, err := os.Executable()
	nativeMust(t, err)
	// go test's build directory may be private. Copy only the executable, never
	// credentials/keys, into the traversable fixture directory for nonroot exec.
	binaryPath := filepath.Join(base, "credential-child.test")
	executableBytes, err := os.ReadFile(executable)
	nativeMust(t, err)
	nativeMust(t, os.WriteFile(binaryPath, executableBytes, 0755))
	nativeMust(t, unix.Chmod(binaryPath, 0755))
	child := func(mode, path string, groups []uint32) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binaryPath, "-test.run=^TestNativeMountedCredentialChild$", "-test.v", "--", "storagefuse-native-child", mode, path)
		cmd.Env = []string{"TMPDIR=/scratch"} // no inherited transport material or host environment
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 11001, Gid: 11001, Groups: groups}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("credential child %s: %v\n%s", mode, err, out)
		}
	}
	// Actual non-atomic OPEN and O_CREAT|O_TRUNC on existing files. The raw probe
	// additionally controls the negative-LOOKUP/CREATE collision interleaving.
	for _, mode := range []string{"open-truncate", "create-truncate"} {
		path := filepath.Join(root, mode)
		disk := filepath.Join(backing, mode)
		nativeMust(t, os.WriteFile(path, []byte("must-truncate"), 0600))
		nativeMust(t, unix.Chown(disk, 11001, 11001))
		nativeMust(t, unix.Chmod(disk, 06770))
		capability := make([]byte, 20)
		binary.LittleEndian.PutUint32(capability, 0x02000001) // revision2/effective
		binary.LittleEndian.PutUint32(capability[4:], 1<<unix.CAP_NET_BIND_SERVICE)
		nativeMust(t, unix.Setxattr(disk, "security.capability", capability, 0))
		var before, after unix.Stat_t
		nativeMust(t, unix.Stat(disk, &before))
		child(mode, path, []uint32{})
		nativeMust(t, unix.Stat(disk, &after))
		if after.Ino != before.Ino || after.Uid != before.Uid || after.Gid != before.Gid || after.Size != 0 || after.Mode&06000 != 0 {
			t.Fatalf("%s changed identity or lost truncate/killpriv: %+v", mode, after)
		}
		if _, err := unix.Getxattr(disk, "security.capability", nil); !errors.Is(err, unix.ENODATA) {
			t.Fatal("truncate retained capability", err)
		}
	}
	groupFile := filepath.Join(root, "group-only")
	nativeMust(t, os.WriteFile(groupFile, []byte("group-authorized"), 0600))
	nativeMust(t, unix.Chown(groupFile, 0, 22001))
	nativeMust(t, unix.Chmod(groupFile, 0040))
	child("read-group", groupFile, []uint32{22001})
	child("deny-open", groupFile, []uint32{}) // checked reopen cannot reuse earlier grant

	for _, directory := range []bool{false, true} {
		path := filepath.Join(root, fmt.Sprintf("owner-zero-%t", directory))
		if directory {
			nativeMust(t, os.Mkdir(path, 0700))
		} else {
			nativeMust(t, os.WriteFile(path, nil, 0600))
		}
		nativeMust(t, unix.Setxattr(path, "user.seed", []byte("present"), 0))
		nativeMust(t, unix.Chown(path, 11001, 11001))
		nativeMust(t, unix.Chmod(path, 0))
		child("owner-zero-xattr", path, []uint32{})
	}
	aclDir := filepath.Join(root, "default-acl")
	nativeMust(t, os.Mkdir(aclDir, 0700))
	nativeMust(t, unix.Chown(aclDir, 11001, 11001))
	nativeMust(t, unix.Setxattr(aclDir, "system.posix_acl_default", nativeACL(7), 0))
	child("acl-inherit", aclDir, []uint32{})
	killpriv := filepath.Join(root, "killpriv")
	nativeMust(t, os.WriteFile(killpriv, []byte("keep"), 0666))
	nativeMust(t, unix.Chmod(killpriv, 06776))
	// Executable SGID exercises both kills. Nonexecutable SGID has a distinct
	// Linux policy and must not be assumed to clear merely because of a write.
	child("write-killpriv", killpriv, []uint32{})
	var st unix.Stat_t
	nativeMust(t, unix.Stat(killpriv, &st))
	if st.Mode&06000 != 0 {
		t.Fatalf("write retained set-ID bits: %#o", st.Mode)
	}
	noop := filepath.Join(root, "chown-minus-one")
	nativeMust(t, os.WriteFile(noop, []byte("keep"), 0600))
	nativeMust(t, unix.Chown(noop, 11001, 11001))
	nativeMust(t, unix.Chmod(noop, 06770))
	child("chown-minus-one", noop, []uint32{})
	nativeMust(t, unix.Stat(noop, &st))
	if st.Uid != 11001 || st.Gid != 11001 || st.Mode&06000 != 0 || st.Size != 4 {
		t.Fatalf("empty-mask chown lost identity/kill semantics: %+v", st)
	}
}
func TestNativeMountedCredentialChild(t *testing.T) {
	args := os.Args
	if len(args) < 4 || args[len(args)-3] != "storagefuse-native-child" {
		t.Skip("internal credential subprocess only")
	}
	mode, path := args[len(args)-2], args[len(args)-1]
	if os.Geteuid() != 11001 || os.Getegid() != 11001 {
		t.Fatal("child identity not installed")
	}
	var words [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	nativeMust(t, unix.Capget(&header, &words[0]))
	if words[0].Effective != 0 || words[1].Effective != 0 {
		t.Fatal("child unexpectedly privileged")
	}
	switch mode {
	case "open-truncate", "create-truncate":
		flags := unix.O_RDWR | unix.O_TRUNC | unix.O_CLOEXEC
		if mode == "create-truncate" {
			flags |= unix.O_CREAT
		}
		fd, err := unix.Open(path, flags, 0600)
		nativeMust(t, err)
		defer unix.Close(fd)
		var st unix.Stat_t
		nativeMust(t, unix.Fstat(fd, &st))
		if st.Size != 0 || st.Uid != 11001 || st.Gid != 11001 || st.Mode&06000 != 0 {
			t.Fatalf("real syscall did not truncate existing inode: %+v", st)
		}
	case "read-group":
		data, err := os.ReadFile(path)
		nativeMust(t, err)
		if string(data) != "group-authorized" {
			t.Fatal("supplementary group read")
		}
	case "deny-open":
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
			t.Fatal("unauthorized checked reopen")
		}
		if !errors.Is(err, unix.EACCES) {
			t.Fatal(err)
		}
	case "owner-zero-xattr":
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
			t.Fatal("mode-zero data open allowed")
		}
		if !errors.Is(err, unix.EACCES) {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := unix.Listxattr(path, buf)
		nativeMust(t, err)
		if !bytes.Contains(buf[:n], []byte("user.seed\x00")) {
			t.Fatal("mode-zero list requires a data-open grant")
		}
		if _, err := unix.Getxattr(path, "user.seed", buf); !errors.Is(err, unix.EACCES) {
			t.Fatal("mode-zero get borrowed root authority", err)
		}
		// Owner-authorized ACL metadata must work without borrowing data-open rights.
		nativeMust(t, unix.Setxattr(path, "system.posix_acl_access", nativeACL(7), 0))
		nativeMust(t, unix.Removexattr(path, "system.posix_acl_access"))
	case "acl-inherit":
		unix.Umask(0077) // private child process only; never the serving process
		file := filepath.Join(path, "inherited")
		fd, err := unix.Open(file, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0666)
		nativeMust(t, err)
		defer unix.Close(fd)
		var st unix.Stat_t
		nativeMust(t, unix.Fstat(fd, &st))
		if st.Mode&0777 != 0666 {
			t.Fatalf("DONT_MASK/default ACL lost: mode=%#o", st.Mode)
		}
	case "chown-minus-one":
		nativeMust(t, unix.Chown(path, -1, -1))
	case "write-killpriv":
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		nativeMust(t, err)
		defer unix.Close(fd)
		n, err := unix.Pwrite(fd, []byte("drop"), 0)
		nativeMust(t, err)
		if n != 4 {
			t.Fatal("short killpriv write")
		}
		nativeMust(t, unix.Fsync(fd))
	default:
		t.Fatal("unknown credential test operation")
	}
}
func nativeACL(permission uint16) []byte {
	// A named user keeps the ACL nontrivial; it cannot collapse into mode bits.
	buf := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(buf, 2)
	for i, tag := range []uint16{1, 2, 4, 16, 32} {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(buf[off:], tag)
		binary.LittleEndian.PutUint16(buf[off+2:], permission)
		id := ^uint32(0)
		if tag == 2 {
			id = 11002
		}
		binary.LittleEndian.PutUint32(buf[off+4:], id)
	}
	return buf
}
func nativeMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func nativeID(t *testing.T) a.ID { t.Helper(); id, err := a.NewID(); nativeMust(t, err); return id }
func nativeKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	nativeMust(t, err)
	return key
}
func nativeFingerprint(t *testing.T, key ed25519.PrivateKey) a.Fingerprint {
	t.Helper()
	fp, err := a.PublicKeyFingerprint(key.Public())
	nativeMust(t, err)
	return fp
}

var errNativeJoinTimeout = errors.New("native mounted fixture join deadline")

func nativeWait(t *testing.T, what string, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(25 * time.Second):
		return fmt.Errorf("%s: %w", what, errNativeJoinTimeout)
	}
}

type nativePKI struct {
	ca   *x509.Certificate
	key  ed25519.PrivateKey
	pool *x509.CertPool
}

func newNativePKI(t *testing.T) nativePKI {
	p := nativePKI{key: nativeKey(t), pool: x509.NewCertPool()}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, p.key.Public(), p.key)
	nativeMust(t, err)
	p.ca, err = x509.ParseCertificate(der)
	nativeMust(t, err)
	p.pool.AddCert(p.ca)
	return p
}
func (p nativePKI) cert(t *testing.T, key ed25519.PrivateKey) tls.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	nativeMust(t, err)
	template := &x509.Certificate{SerialNumber: serial, DNSNames: []string{"storage.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, p.ca, key.Public(), p.key)
	nativeMust(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func (p nativePKI) serverConfig(t *testing.T, key ed25519.PrivateKey) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{p.cert(t, key)}, ClientCAs: p.pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
}
func (p nativePKI) clientConfig(t *testing.T, key ed25519.PrivateKey) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{p.cert(t, key)}, RootCAs: p.pool, ServerName: "storage.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
}
func nativeTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	nativeMust(t, err)
	defer listener.Close()
	nativeMust(t, listener.SetDeadline(time.Now().Add(10*time.Second)))
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), 10*time.Second)
	nativeMust(t, err)
	server, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	return server, client
}
func nativeController(t *testing.T, authority *a.Authority, pki nativePKI, config *tls.Config, key ed25519.PrivateKey) *a.ControllerPrincipal {
	t.Helper()
	serverRaw, clientRaw := nativeTCPPair(t)
	defer serverRaw.Close()
	defer clientRaw.Close()
	server, client := tls.Server(serverRaw, config), tls.Client(clientRaw, pki.clientConfig(t, key))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.HandshakeContext(ctx) }()
	principal, err := authority.AuthenticateController(ctx, server, 1)
	nativeMust(t, err)
	nativeMust(t, nativeWait(t, "controller TLS", done))
	return principal
}

// Real syscalls exercise the ABI3 intent transport; no fake Snapshot or session
// proof is injected. This is compiled here, but requires the separate VM gate.
func nativeMetadata(t *testing.T, root, backing string) {
	path := filepath.Join(root, "abi3-metadata")
	nativeMust(t, os.WriteFile(path, []byte("truncate-me"), 0600))
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	nativeMust(t, err)
	defer unix.Close(fd)
	nativeMust(t, unix.Ftruncate(fd, 4)) // FILE and size, not an opener identity
	explicit := []unix.Timespec{{Sec: 123456, Nsec: 17}, {Sec: 234567, Nsec: 23}}
	nativeMust(t, unix.UtimesNanoAt(unix.AT_FDCWD, path, explicit, 0))
	var st unix.Stat_t
	nativeMust(t, unix.Stat(filepath.Join(backing, "abi3-metadata"), &st))
	if st.Size != 4 || st.Atim != explicit[0] || st.Mtim != explicit[1] {
		t.Fatalf("explicit time/size transport: %+v", st)
	}
	before := time.Now().Unix()
	nativeMust(t, unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{{Nsec: unix.UTIME_OMIT}, {Nsec: unix.UTIME_NOW}}, 0))
	nativeMust(t, unix.Stat(filepath.Join(backing, "abi3-metadata"), &st))
	if st.Atim != explicit[0] || st.Mtim.Sec < before {
		t.Fatalf("NOW/OMIT transport: %+v", st)
	}
	nativeMust(t, unix.UtimesNanoAt(unix.AT_FDCWD, path, nil, 0)) // ATTR_TOUCH
	trunc, err := unix.Open(path, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0)
	nativeMust(t, err)
	nativeMust(t, unix.Close(trunc))
	nativeMust(t, unix.Stat(filepath.Join(backing, "abi3-metadata"), &st))
	if st.Size != 0 {
		t.Fatalf("non-atomic OPEN truncation lost: %+v", st)
	}
}
