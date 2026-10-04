//go:build linux

package disk

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Opt-in only; accepts no supplied device. The exec-created namespace and new
// backing file belong solely to this test in a disposable root Linux VM.
func TestExplicitExt4OwnedLoopRuntime(t *testing.T) {
	if os.Getenv("CENGINE_EXT4_OWNED_LOOP_TEST") != "1" {
		t.Skip("requires explicit CENGINE_EXT4_OWNED_LOOP_TEST=1 on disposable root Linux")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if os.Getenv("CENGINE_EXT4_OWNED_LOOP_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		parentNS, err := os.Open("/proc/self/ns/mnt")
		if err != nil {
			t.Fatal(err)
		}
		defer parentNS.Close()
		budget := 90 * time.Second
		if deadline, ok := t.Deadline(); ok && time.Until(deadline)-5*time.Second < budget {
			budget = time.Until(deadline) - 5*time.Second
		}
		if budget < 5*time.Second {
			t.Fatal("insufficient runtime fixture deadline")
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestExplicitExt4OwnedLoopRuntime$", "-test.v", "-test.timeout="+(budget-time.Second).String())
		cmd.Env = append(os.Environ(), "CENGINE_EXT4_OWNED_LOOP_CHILD=1")
		cmd.ExtraFiles = []*os.File{parentNS} // fd 3 authenticates namespace provenance
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Setpgid: true}
		// Direct log descriptors: no unbounded pipe-draining wait or shared buffer.
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.WaitDelay = time.Second
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Logf("owned loop child pid=%d deadline=%s; artifacts logged by child", cmd.Process.Pid, budget)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // only our exec-created group
				t.Fatalf("isolated runtime test: %v; preserve /run artifacts", err)
			}
		case <-ctx.Done():
			_ = cmd.Cancel()
			// SIGKILL cannot necessarily reap uninterruptible kernel sleep. Never
			// block the runner forever, detach blindly, or traverse its mounts.
			select {
			case err := <-done:
				t.Fatalf("owned child deadline: %v; preserve artifacts", err)
			case <-time.After(3 * time.Second):
				t.Fatalf("owned child pid=%d unreaped after kill; preserve artifacts and terminate disposable VM", cmd.Process.Pid)
			}
		}
		return
	}
	childNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	// Ambient child markers cannot authorize namespace mutation: require the
	// inherited real namespace FD AND compare with our actual direct parent's NS.
	parentNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", os.Getppid()))
	if err != nil {
		t.Fatal(err)
	}
	inheritedNS, err := os.Readlink("/proc/self/fd/3")
	if err != nil {
		t.Fatal("missing inherited parent namespace:", err)
	}
	nsType, err := unix.IoctlRetInt(3, unix.NS_GET_NSTYPE)
	if err != nil || nsType != unix.CLONE_NEWNS || inheritedNS != parentNS || parentNS == childNS {
		t.Fatal("runtime fixture must have its direct parent's namespace FD and a distinct exec-created mount namespace")
	}
	if err := unix.Close(3); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
	_, err = os.Stat("/sbin/mke2fs")
	must(err) // explicit opt-in missing prerequisites are failures, never skips
	dir, err := os.MkdirTemp("/run", "cengine-ext4-owned-loop-")
	must(err)
	t.Logf("owned fixture artifacts: %s (preserved on uncertain cleanup)", dir)
	trusted, err := secureDirectory(dir)
	must(err)
	must(trusted.Close())
	t.Run("trusted ancestors and leaf pinning", TestNativeDestinationLeafAndAncestors)
	lease, err := newOwnedLoop(dir)
	defer func() { runtime.KeepAlive(lease) }()
	must(err) // no cleanup through an uncertain mount or unknown loop
	target, other := filepath.Join(dir, "mnt"), filepath.Join(dir, "other")
	must(os.Mkdir(target, 0700))
	must(os.Mkdir(other, 0700))
	var foreignID uint64
	defer func() {
		if err := lease.cleanup(target, other, foreignID); err != nil {
			t.Errorf("preserving %s and lease on uncertain cleanup: %v", dir, err)
		}
	}()

	// Direct mount of nonzero corrupt data MUST fail without ever formatting.
	corrupt := bytes.Repeat([]byte{0xa5}, 8192)
	_, err = lease.backing.WriteAt(corrupt, 0)
	must(err)
	must(lease.backing.Sync())
	if err := MountExistingExt4(lease.path, target); err == nil {
		t.Fatal("corrupt superblock mounted")
	}
	got := make([]byte, len(corrupt))
	_, err = lease.backing.ReadAt(got, 0)
	must(err)
	if !bytes.Equal(got, corrupt) {
		t.Fatal("MountExisting mutated corrupt control")
	}
	if _, err := InspectExt4Identity(lease.path, target); err == nil {
		t.Fatal("unmounted identity accepted")
	}
	t.Log("corrupt nonzero MountExisting control preserved; explicit initialization next")
	if err := VerifyInheritedMountedExt4(lease.path, target); err == nil {
		t.Fatal("inherited verification accepted an unmounted root")
	}
	must(InitializeExt4(lease.path, target, "owned-test", testUUID, testBytes))
	must(VerifyInheritedMountedExt4(lease.path, target))
	metadata, err := (linuxInheritedMountOps{}).pinDeviceMetadata(lease.path)
	must(err)
	flags, err := unix.FcntlInt(metadata.file.Fd(), unix.F_GETFL, 0)
	must(err)
	if flags&unix.O_PATH == 0 {
		t.Fatal("inherited device pin grants data access")
	}
	var forbidden [1]byte
	if _, err := metadata.file.Read(forbidden[:]); !errors.Is(err, unix.EBADF) {
		t.Fatalf("metadata pin unexpectedly readable: %v", err)
	}
	must(metadata.file.Close())
	mountedPin, err := (linuxInheritedMountOps{}).pinTarget(target)
	must(err)
	wrongDevice := &pinnedDevice{major: metadata.major, minor: metadata.minor + 1}
	if err := (linuxInheritedMountOps{}).verifyTargetDevice(mountedPin, wrongDevice); err == nil {
		t.Fatal("inherited root accepted wrong device identity")
	}
	must(mountedPin.file.Close())
	// This private node belongs only to the fixture; an untrusted node owner
	// must not be accepted even when its kernel device number is correct.
	must(unix.Chown(lease.path, 1000, 1000))
	if d, err := (linuxInheritedMountOps{}).pinDeviceMetadata(lease.path); err == nil {
		d.file.Close()
		t.Fatal("inherited root accepted a non-root-owned device node")
	}
	must(unix.Chown(lease.path, 0, 0))
	sentinel := filepath.Join(target, "sentinel")
	must(os.WriteFile(sentinel, []byte("preserve me"), 0600))
	fileFD, err := unix.Open(sentinel, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	must(err)
	filePin := &pinnedTarget{file: os.NewFile(uintptr(fileFD), sentinel), path: sentinel}
	if err := (linuxInheritedMountOps{}).verifyTargetDevice(filePin, metadata); err == nil {
		t.Fatal("inherited root accepted a regular file on the correct ext4 device")
	}
	must(filePin.file.Close())
	if err := InitializeExt4(lease.path, other, "forbidden", testUUID, testBytes); err == nil {
		t.Fatal("initialized live disk elsewhere")
	}
	if err := InitializeExt4(lease.path, target, "forbidden", testUUID, testBytes); err == nil {
		t.Fatal("initialized mounted disk")
	}
	must(lease.unmountTarget(target))
	must(MountExistingExt4(lease.path, target))

	// Root copy-up is allowed to set arbitrary filesystem-root metadata. Each
	// call must be idempotent AND preserve uid/gid/mode/ctime and ACL bytes.
	for _, tc := range []struct {
		uid  int
		mode uint32
		acl  bool
	}{
		{1000, 0700, false}, {1000, 0, false}, {0, 0, false}, {0, 0777, false}, {1000, 0777, true},
	} {
		must(unix.Chown(target, tc.uid, 1000))
		must(unix.Chmod(target, tc.mode))
		if tc.acl {
			must(unix.Setxattr(target, "system.posix_acl_access", ownedRootACL(), 0))
		}
		var before, after unix.Stat_t
		must(unix.Stat(target, &before))
		var aclBefore []byte
		if tc.acl {
			aclBefore, err = ownedReadACL(target)
			must(err)
		}
		must(VerifyInheritedMountedExt4(lease.path, target))
		must(MountExistingExt4(lease.path, target))
		id, err := SyncExt4Identity(lease.path, target)
		must(err)
		if id.UUID != testUUID || id.Bytes != testBytes {
			t.Fatalf("identity changed: %+v", id)
		}
		must(unix.Stat(target, &after))
		if before.Uid != after.Uid || before.Gid != after.Gid || before.Mode != after.Mode || before.Ctim != after.Ctim {
			t.Fatal("idempotent mount changed root metadata")
		}
		if tc.acl {
			aclAfter, err := ownedReadACL(target)
			must(err)
			if !bytes.Equal(aclBefore, aclAfter) {
				t.Fatal("root ACL changed")
			}
		}
	}
	// Persistence across a normal sync/unmount/remount with non-root + ACL root.
	_, err = SyncExt4Identity(lease.path, target)
	must(err)
	must(lease.unmountTarget(target))
	must(MountExistingExt4(lease.path, target))
	must(MountExistingExt4(lease.path, target))
	id, err := InspectExt4Identity(lease.path, target)
	must(err)
	if id.UUID != testUUID || id.Bytes != testBytes {
		t.Fatalf("persisted identity changed: %+v", id)
	}
	acl, err := ownedReadACL(target)
	must(err)
	if !bytes.Equal(acl, ownedRootACL()) {
		t.Fatal("persisted root ACL changed")
	}
	contents, err := os.ReadFile(sentinel)
	must(err)
	if string(contents) != "preserve me" {
		t.Fatal("sentinel lost")
	}

	// Dormant read-only/no-replay probe controls: strict preflight, exact ro
	// mount, no replay/format/fsck/sync, byte preservation on rejection.
	must(lease.unmountTarget(target))
	probe, err := ProbeExt4ReadOnly(lease.path, target, testUUID, testBytes)
	must(err)
	if probe.Identity() != (Ext4Identity{UUID: testUUID, Bytes: testBytes}) || probe.Destination() != target || probe.Device() != lease.path {
		t.Fatalf("probe identity mismatch: %s %s %+v", probe.Device(), probe.Destination(), probe.Identity())
	}
	probeRoot, err := probe.Root()
	must(err)
	var probeRootStat unix.Stat_t
	must(unix.Fstat(int(probeRoot.Fd()), &probeRootStat))
	if probeRootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatal("probe Root dup is not a directory")
	}
	must(probeRoot.Close())
	probePin, err := pinDestination(target)
	must(err)
	probeSnap, err := (linuxExt4Ops{}).snapshot(&pinnedTarget{file: probePin, path: target}, true)
	must(err)
	must(probePin.Close())
	probeMounted, err := probeDestinationState(probeSnap, &pinnedDevice{major: 7, minor: lease.minor}, target)
	if err != nil || !probeMounted {
		t.Fatalf("probe mount not the visible read-only root: mounted=%v err=%v", probeMounted, err)
	}
	if f, err := os.OpenFile(filepath.Join(target, "forbidden"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err == nil {
		f.Close()
		t.Fatal("read-only probe accepted a write")
	}
	// The lease closes its pins and unmounts only its own verified mount.
	must(probe.Close())
	if _, err := probe.Root(); err == nil {
		t.Fatal("Root accepted after lease Close")
	}
	// Promotion requires all external RO root FDs closed. EBUSY consumes the
	// attempt but keeps the original mount owned for cleanup.
	busyProbe, err := ProbeExt4ReadOnly(lease.path, target, testUUID, testBytes)
	must(err)
	busyRoot, err := busyProbe.Root()
	must(err)
	if err := busyProbe.Promote(func(*os.File) error { return nil }); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("open RO root did not block promotion: %v", err)
	}
	must(busyRoot.Close())
	must(busyProbe.Close())

	journaled, err := ProbeExt4ReadOnly(lease.path, target, testUUID, testBytes)
	must(err)
	oldMountID, blockFD := journaled.lease.mountID, journaled.lease.device.file.Fd()
	competitor, err := os.Open(lease.path)
	must(err)
	defer competitor.Close()
	assertLocked := func() {
		t.Helper()
		if err := unix.Flock(int(competitor.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
			t.Fatalf("promotion lost block flock: %v", err)
		}
	}
	var rootBefore, rootAfter unix.Stat_t
	must(unix.Stat(target, &rootBefore))
	aclBefore, err := ownedReadACL(target)
	must(err)
	must(journaled.Promote(func(root *os.File) error {
		assertLocked()
		snap, err := (linuxExt4Ops{}).snapshot(&pinnedTarget{file: root, path: target}, true)
		if err != nil {
			return err
		}
		mounted, err := probeDestinationState(snap, journaled.lease.device, target)
		if err != nil {
			return err
		}
		if !mounted {
			return fmt.Errorf("admission root not RO mounted")
		}
		return nil // fixture admission only; production callback verifies signed authority
	}))
	assertLocked()
	if journaled.lease.device.file.Fd() != blockFD || journaled.lease.mountID == 0 {
		t.Fatal("promotion replaced device FD or lacks mount identity")
	}
	t.Logf("promotion mount IDs: RO=%d RW=%d (numeric reuse is valid after proven unmount)", oldMountID, journaled.lease.mountID)
	newRoot, err := journaled.Root()
	must(err)
	must(unix.Fstat(int(newRoot.Fd()), &rootAfter))
	if rootBefore.Dev != rootAfter.Dev || rootBefore.Ino != rootAfter.Ino || rootBefore.Uid != rootAfter.Uid || rootBefore.Gid != rootAfter.Gid || rootBefore.Mode != rootAfter.Mode {
		t.Fatal("promotion changed disk root identity/metadata")
	}
	aclAfter, err := ownedReadACL(target)
	must(err)
	if !bytes.Equal(aclBefore, aclAfter) {
		t.Fatal("promotion changed root ACL")
	}
	must(newRoot.Close())
	must(os.WriteFile(filepath.Join(target, "journaled-write"), []byte("persist journaled"), 0600))
	must(journaled.Close())
	must(unix.Flock(int(competitor.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	must(unix.Flock(int(competitor.Fd()), unix.LOCK_UN))
	check, err := ProbeExt4ReadOnly(lease.path, target, testUUID, testBytes)
	must(err)
	written, err := os.ReadFile(filepath.Join(target, "journaled-write"))
	must(err)
	if string(written) != "persist journaled" {
		t.Fatal("journaled write did not persist")
	}
	must(check.Close())

	for _, bad := range []struct {
		uuid  string
		bytes uint64
	}{
		{"abcdefab-1234-5678-9abc-123456789abc", testBytes},
		{testUUID, testBytes + 4096},
	} {
		if _, err := ProbeExt4ReadOnly(lease.path, target, bad.uuid, bad.bytes); err == nil {
			t.Fatal("probe accepted mismatched identity")
		}
	}
	// Full-image proof: a rejection must leave every backing byte untouched,
	// not only the superblock range (ro,noload ext4 can still run orphan
	// cleanup writes, so a non-empty orphan list must be rejected pre-mount).
	pristine := make([]byte, 2048)
	_, err = lease.backing.ReadAt(pristine, 1024)
	must(err)
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"missing VALID_FS", func(b []byte) { binary.LittleEndian.PutUint16(b[0x3a:], 0) }},
		{"ERROR_FS", func(b []byte) { binary.LittleEndian.PutUint16(b[0x3a:], ext4ErrorFS) }},
		{"journal recovery pending", func(b []byte) {
			binary.LittleEndian.PutUint32(b[0x60:], binary.LittleEndian.Uint32(b[0x60:])|ext4FeatureIncompatRecover)
		}},
		{"orphan inode list present", func(b []byte) { binary.LittleEndian.PutUint32(b[0xe8:], 9) }},
		{"orphan-present feature", func(b []byte) {
			binary.LittleEndian.PutUint32(b[0x64:], binary.LittleEndian.Uint32(b[0x64:])|ext4FeatureROOrphanPresent)
		}},
	} {
		mutated := make([]byte, len(pristine))
		copy(mutated, pristine)
		tc.mutate(mutated)
		_, err = lease.backing.WriteAt(mutated, 1024)
		must(err)
		must(lease.backing.Sync())
		// Include this case's deliberate corruption in the baseline; only the
		// probe must leave the entire image unchanged.
		imageBefore := make([]byte, testBytes)
		_, err = lease.backing.ReadAt(imageBefore, 0)
		must(err)
		if _, err := ProbeExt4ReadOnly(lease.path, target, testUUID, testBytes); err == nil {
			t.Fatalf("probe accepted %s superblock", tc.name)
		}
		imageAfter := make([]byte, testBytes)
		_, err = lease.backing.ReadAt(imageAfter, 0)
		must(err)
		if !bytes.Equal(imageAfter, imageBefore) {
			t.Fatalf("probe mutated the image after %s rejection", tc.name)
		}
		data, err := os.ReadFile("/proc/self/mountinfo")
		must(err)
		records, err := parseMountinfo(string(data))
		must(err)
		for _, r := range records {
			if r.major == 7 && r.minor == lease.minor {
				t.Fatalf("probe mounted the %s disk at %s", tc.name, r.point)
			}
		}
	}
	_, err = lease.backing.WriteAt(pristine, 1024)
	must(err)
	must(lease.backing.Sync())
	must(unix.Mount("tmpfs", other, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, ""))
	foreign, err := pinDestination(other)
	must(err)
	foreignID, err = fdMountID(foreign)
	must(err)
	var foreignStat unix.Stat_t
	must(unix.Fstat(int(foreign.Fd()), &foreignStat))
	matchingForeignDevice := &pinnedDevice{major: unix.Major(uint64(foreignStat.Dev)), minor: unix.Minor(uint64(foreignStat.Dev))}
	if err := (linuxInheritedMountOps{}).verifyTargetDevice(&pinnedTarget{file: foreign, path: other}, matchingForeignDevice); err == nil {
		t.Fatal("inherited root accepted tmpfs despite matching device metadata")
	}
	must(foreign.Close())
	if err := MountExistingExt4(lease.path, other); err == nil {
		t.Fatal("foreign visible mount accepted")
	}
	t.Run("fresh shutdown lease", func(t *testing.T) {
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		// A separate new blank image: never reinitialize the existing control
		// disk, and keep this sibling artifact directory on any failure.
		freshDir, err := os.MkdirTemp("/run", "cengine-ext4-owned-fresh-")
		must(err)
		t.Logf("fresh shutdown artifacts: %s (preserved on failure)", freshDir)
		freshLoop, err := newOwnedLoop(freshDir)
		defer func() { runtime.KeepAlive(freshLoop) }()
		must(err)
		freshTarget := filepath.Join(freshDir, "mnt")
		must(os.Mkdir(freshTarget, 0700))
		defer func() {
			if t.Failed() {
				t.Logf("preserving fresh shutdown evidence and owned loop: %s", freshDir)
				return
			}
			if err := freshLoop.cleanup(freshTarget, "", 0); err != nil {
				t.Errorf("preserving %s and lease on uncertain cleanup: %v", freshDir, err)
			}
		}()

		// Uses the real formatter and mount operations, retaining the original
		// device pin for synchronization and plain-unmount shutdown.
		fresh, err := InitializeExt4ForShutdown(freshLoop.path, freshTarget, "owned-fresh", testUUID, testBytes)
		defer func() { runtime.KeepAlive(fresh) }()
		must(err)
		root, err := fresh.Root()
		defer func() { runtime.KeepAlive(root) }()
		must(err)
		rootDup, err := fresh.Root()
		defer func() { runtime.KeepAlive(rootDup) }()
		must(err)
		var rootStat, dupStat unix.Stat_t
		must(unix.Fstat(int(root.Fd()), &rootStat))
		must(unix.Fstat(int(rootDup.Fd()), &dupStat))
		if root.Fd() == rootDup.Fd() || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Dev != dupStat.Dev || rootStat.Ino != dupStat.Ino || uint64(rootStat.Dev) != unix.Mkdev(7, freshLoop.minor) {
			t.Fatal("fresh roots are not independent duplicates of the owned ext4 root")
		}
		freshSentinel := filepath.Join(freshTarget, "fresh-sentinel")
		must(os.WriteFile(freshSentinel, []byte("preserve fresh shutdown"), 0600))
		identity, err := fresh.SyncIdentity()
		must(err)
		if identity != (Ext4Identity{UUID: testUUID, Bytes: testBytes}) {
			t.Fatalf("fresh synchronized identity mismatch: %+v", identity)
		}
		must(root.Close())
		if err := fresh.Close(); !errors.Is(err, unix.EBUSY) {
			t.Fatalf("open fresh root did not block plain-unmount shutdown: %v", err)
		}
		// Failure retains the original device lock, not permission to format
		// again. Closing the final external root permits cleanup-only retry.
		contender, err := os.Open(freshLoop.path)
		must(err)
		defer contender.Close()
		if err := unix.Flock(int(contender.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
			t.Fatalf("busy fresh shutdown lost device lock: %v", err)
		}
		must(rootDup.Close())
		must(fresh.Close())
		must(fresh.Close()) // terminal Close is idempotent
		must(unix.Flock(int(contender.Fd()), unix.LOCK_EX|unix.LOCK_NB))
		must(unix.Flock(int(contender.Fd()), unix.LOCK_UN))
		must(contender.Close())
		if root, err := fresh.Root(); err == nil {
			root.Close()
			t.Fatal("fresh shutdown granted a root after Close")
		}
		data, err := os.ReadFile("/proc/self/mountinfo")
		must(err)
		records, err := parseMountinfo(string(data))
		must(err)
		for _, r := range records {
			if r.major == 7 && r.minor == freshLoop.minor {
				t.Fatalf("fresh shutdown left mount %d at %s", r.id, r.point)
			}
		}

		// Successful strict no-replay probing proves the normal shutdown left
		// a clean superblock. The entire post-shutdown image must remain intact.
		imageBefore := make([]byte, testBytes)
		_, err = freshLoop.backing.ReadAt(imageBefore, 0)
		must(err)
		freshProbe, err := ProbeExt4ReadOnly(freshLoop.path, freshTarget, testUUID, testBytes)
		defer func() { runtime.KeepAlive(freshProbe) }()
		must(err)
		if freshProbe.Identity() != identity {
			t.Fatalf("fresh shutdown probe identity changed: %+v", freshProbe.Identity())
		}
		contents, err := os.ReadFile(freshSentinel)
		must(err)
		if string(contents) != "preserve fresh shutdown" {
			t.Fatal("fresh shutdown lost sentinel")
		}
		must(freshProbe.Close())
		imageAfter := make([]byte, testBytes)
		_, err = freshLoop.backing.ReadAt(imageAfter, 0)
		must(err)
		if !bytes.Equal(imageBefore, imageAfter) {
			t.Fatal("read-only probe mutated the clean fresh-shutdown image")
		}
		t.Log("fresh shutdown passed: root duplicates, EBUSY retry, clean unmount, same UUID and full image preserved")
	})
	t.Log("owned ext4 runtime controls passed: UUID/data/root metadata/ACL preserved")
}

// Only fresh private nodes are created. Never chmod/mknod/replace global /dev.
func ownedNode(path string, kind uint32, major, minor uint32) (*os.File, error) {
	if err := unix.Mknod(path, kind|0600, int(unix.Mkdev(major, minor))); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != kind || uint64(st.Rdev) != unix.Mkdev(major, minor) {
		f.Close()
		return nil, fmt.Errorf("private node identity mismatch")
	}
	return f, nil
}

type ownedLoop struct {
	dir, path     string
	file, backing *os.File // held AUTOCLEAR lease until validated teardown
	minor         uint32
	dev, inode    uint64
}

func newOwnedLoop(dir string) (*ownedLoop, error) {
	backing, err := os.OpenFile(filepath.Join(dir, "new.img"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	// On failure only close this new backing FD; preserve all artifacts.
	ok := false
	defer func() {
		if !ok {
			backing.Close()
		}
	}()
	if err := backing.Truncate(int64(testBytes)); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(backing.Fd()), &st); err != nil {
		return nil, err
	}
	control, err := ownedNode(filepath.Join(dir, "loop-control"), unix.S_IFCHR, 10, 237)
	if err != nil {
		return nil, err
	}
	defer control.Close()
	seen := map[int]bool{}
	for attempt := 0; attempt < 8; attempt++ {
		number, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return nil, fmt.Errorf("LOOP_CTL_GET_FREE (CONFIG_BLK_DEV_LOOP=y required): %w", err)
		}
		if number < 0 || number > (1<<20)-1 {
			return nil, fmt.Errorf("invalid loop number %d", number)
		}
		if seen[number] {
			continue
		} // never configure the same candidate twice
		seen[number] = true
		path := filepath.Join(dir, fmt.Sprintf("loop%d", number))
		file, err := ownedNode(path, unix.S_IFBLK, 7, uint32(number))
		if err != nil {
			return nil, err
		}
		config := unix.LoopConfig{Fd: uint32(backing.Fd()), Info: unix.LoopInfo64{Flags: unix.LO_FLAGS_AUTOCLEAR, Sizelimit: testBytes}}
		if err := unix.IoctlLoopConfigure(int(file.Fd()), &config); err != nil {
			file.Close() // failed configure is NEVER ownership; no detach/status adoption
			if errors.Is(err, unix.EBUSY) {
				continue
			}
			return nil, fmt.Errorf("LOOP_CONFIGURE: %w", err)
		}
		lease := &ownedLoop{dir, path, file, backing, uint32(number), uint64(st.Dev), st.Ino}
		// If proof fails, no explicit detach and no removal. Keep the FD alive
		// until child exit instead of guessing at a potentially changed binding.
		if err := lease.validate(); err != nil {
			ok = true
			return lease, err
		}
		ok = true
		return lease, nil
	}
	return nil, fmt.Errorf("no newly owned loop after 8 bounded free-device queries")
}
func (l *ownedLoop) validate() error {
	var st unix.Stat_t
	if err := unix.Fstat(int(l.backing.Fd()), &st); err != nil {
		return err
	}
	if uint64(st.Dev) != l.dev || st.Ino != l.inode || st.Size != int64(testBytes) || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("backing identity/size changed")
	}
	info, err := unix.IoctlLoopGetStatus64(int(l.file.Fd()))
	if err != nil {
		return err
	}
	if !ownedLoopMatches(info, l.dev, l.inode, l.minor) {
		return fmt.Errorf("owned loop binding changed: %+v", info)
	}
	size, err := (linuxExt4Ops{}).capacity(&pinnedDevice{file: l.file})
	if err != nil {
		return err
	}
	if size != testBytes {
		return fmt.Errorf("owned loop capacity changed: %d", size)
	}
	return nil
}
func ownedLoopMatches(info *unix.LoopInfo64, dev, inode uint64, minor uint32) bool {
	return info.Device == dev && info.Inode == inode && info.Rdevice == 0 && info.Number == minor && info.Offset == 0 && info.Sizelimit == testBytes && info.Flags == unix.LO_FLAGS_AUTOCLEAR && info.Encrypt_type == 0 && info.Encrypt_key_size == 0
}
func (l *ownedLoop) unmountTarget(target string) error {
	if err := l.validate(); err != nil {
		return err
	}
	ops := linuxExt4Ops{}
	pin, err := ops.pinTarget(target)
	if err != nil {
		return err
	}
	s, err := ops.snapshot(pin, true)
	closeErr := pin.file.Close() // an O_PATH mount reference would make umount EBUSY
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	mounted, err := destinationState(s, &pinnedDevice{major: 7, minor: l.minor}, target)
	if err != nil {
		return err
	}
	if !mounted {
		return nil
	}
	return unix.Unmount(target, 0) // never lazy/force unmount
}
func (l *ownedLoop) cleanup(target, other string, foreignID uint64) error {
	if err := l.validate(); err != nil {
		return err
	}
	if foreignID != 0 {
		ops := linuxExt4Ops{}
		pin, err := ops.pinTarget(other)
		if err != nil {
			return err
		}
		s, err := ops.snapshot(pin, true)
		pin.file.Close()
		if err != nil {
			return err
		}
		found := false
		for _, r := range s.records {
			if r.point == other || strings.HasPrefix(r.point, other+"/") {
				if found || r.id != foreignID || s.visible != foreignID || r.point != other || r.fs != "tmpfs" || r.root != "/" {
					return fmt.Errorf("foreign control mount changed")
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("foreign control mount disappeared")
		}
		if err := unix.Unmount(other, 0); err != nil {
			return err
		}
	}
	if err := l.unmountTarget(target); err != nil {
		return err
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	records, err := parseMountinfo(string(data))
	if err != nil {
		return err
	}
	for _, r := range records {
		if (r.major == 7 && r.minor == l.minor) || r.point == l.dir || strings.HasPrefix(r.point, l.dir+"/") {
			return fmt.Errorf("remaining mount %d at %s; refuse detach/removal", r.id, r.point)
		}
	}
	if err := l.validate(); err != nil {
		return err
	}
	// Only the exact newly configured, still-validated lease may be detached.
	if err := unix.IoctlSetInt(int(l.file.Fd()), unix.LOOP_CLR_FD, 0); err != nil {
		return err
	}
	if err := l.file.Close(); err != nil {
		return err
	}
	if err := l.backing.Close(); err != nil {
		return err
	}
	return os.RemoveAll(l.dir) // proved no mount beneath the private artifact root
}
func ownedRootACL() []byte {
	// Linux POSIX ACL xattr v2: user_obj,user(1234),group_obj,mask,other.
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 7, ^uint32(0)}, {2, 7, 1234}, {4, 7, ^uint32(0)}, {16, 7, ^uint32(0)}, {32, 7, ^uint32(0)}} {
		p := acl[4+i*8:]
		binary.LittleEndian.PutUint16(p, e.tag)
		binary.LittleEndian.PutUint16(p[2:], e.perm)
		binary.LittleEndian.PutUint32(p[4:], e.id)
	}
	return acl
}
func ownedReadACL(path string) ([]byte, error) {
	buf := make([]byte, 128)
	n, err := unix.Getxattr(path, "system.posix_acl_access", buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
