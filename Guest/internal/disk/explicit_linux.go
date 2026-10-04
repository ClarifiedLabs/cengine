//go:build linux

package disk

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var explicitTransitionMu sync.Mutex

// MountExistingExt4 mounts only an existing ext4 filesystem, preserving its UUID
// and label. It never formats, repairs, or runs fsck, regardless of mount errno.
// Destination ancestors must be root-owned and not writable by others. An
// already verified filesystem root retains its own owner, mode and ACLs.
// See EXPLICIT-EXT4.md for the exclusive namespace/device ownership contract.
func MountExistingExt4(device, destination string) error {
	return (ext4Transition{&explicitTransitionMu, linuxExt4Ops{}}).run(device, destination, "", "", 0, false)
}

// InitializeExt4 is an explicit destructive capability, NOT a freshness test.
// The caller MUST already hold durable, consumed, one-shot host authorization
// bound to this exact exclusively owned block disk and VM launch, UUID and size.
// Any failure consumes that authorization: never retry initialization. The sole
// production caller is the authenticated, one-shot PID1 disk bootstrap gate.
func InitializeExt4(device, destination, label, expectedUUID string, expectedBytes uint64) error {
	return (ext4Transition{&explicitTransitionMu, linuxExt4Ops{}}).run(device, destination, label, expectedUUID, expectedBytes, true)
}

// InitializeExt4ForShutdown is storage PID1's fresh-only initialization. The
// returned opaque lease MUST be retained even when err is nonnil. It carries
// cleanup ownership, not another permission to initialize.
func InitializeExt4ForShutdown(device, destination, label, expectedUUID string, expectedBytes uint64) (Ext4ShutdownLease, error) {
	var lease Ext4ShutdownLease
	err := (ext4Transition{&explicitTransitionMu, linuxExt4Ops{}}).runRetained(device, destination, label, expectedUUID, expectedBytes, true, &lease)
	return lease, err
}

func (linuxExt4Ops) syncBlock(d *pinnedDevice) error { return d.file.Sync() }

// ProbeExt4ReadOnly is a strictly read-only mount of an existing ext4
// filesystem for future fresh-init resume. The pinned device is opened
// O_RDONLY; the expected UUID/byte capacity must match the on-disk superblock,
// which must be cleanly unmounted (VALID_FS, no ERROR_FS) with no pending
// journal recovery, no non-empty orphan inode list and only supported
// features — all strictly before mount. The mount is
// MS_RDONLY|MS_NODEV|MS_NOSUID with noload from the pinned device descriptor,
// so the journal is never replayed; the visible mount identity is reverified
// afterwards. It never formats, fscks, syncs, replays or remounts read-write,
// and diskbootstrap retains the lease without granting a writable storage root.
// Caller exclusivity applies.
func ProbeExt4ReadOnly(device, destination, expectedUUID string, expectedBytes uint64) (Ext4ReadOnlyLease, error) {
	return (ext4Transition{&explicitTransitionMu, linuxExt4Ops{}}).probeReadOnly(device, destination, expectedUUID, expectedBytes)
}

// InspectExt4Identity observes a pinned disk only while its exact ext4 root is
// verified visible at destination with the required policy. It does not mount,
// format, repair, sync, or authorize initialization. Caller exclusivity applies.
func InspectExt4Identity(device, destination string) (Ext4Identity, error) {
	return (ext4Transition{&explicitTransitionMu, linuxExt4Ops{}}).inspect(device, destination)
}

// SyncExt4Identity verifies the visible ext4 root, synchronizes its real mount FD
// and the pinned block FD, then reverifies the mount and observes UUID/capacity.
// A failed sync or verification returns no identity acknowledgement.
func SyncExt4Identity(device, destination string) (Ext4Identity, error) {
	return (ext4Transition{&explicitTransitionMu, linuxExt4Ops{}}).observe(device, destination, true)
}

type linuxExt4Ops struct{}

func (ops linuxExt4Ops) sync(d *pinnedDevice, target *pinnedTarget) error {
	// O_PATH is sufficient for pinning, but syncfs requires a real descriptor.
	// Open relative to the held root, not a potentially replaced pathname.
	fd, err := unix.Openat(int(target.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), target.path)
	defer file.Close()
	realTarget := &pinnedTarget{file: file, path: target.path}
	verify := func() error {
		s, err := ops.snapshot(realTarget, true)
		if err != nil {
			return err
		}
		mounted, err := destinationState(s, d, target.path)
		if err != nil {
			return err
		}
		if !mounted {
			return fmt.Errorf("sync requires visible exact ext4 root")
		}
		return nil
	}
	return checkedDiskSync(func() error { return unix.Syncfs(fd) }, d.file.Sync, verify)
}

// Walk each component relative to held directories: no symlinks, no writable
// parents, no implicit mkdir. Privileged namespace/device mutation must be
// excluded by the caller; no pathname API can defend against hostile CAP_SYS_ADMIN.
func secureDirectory(path string) (*os.File, error) {
	return walkDirectory(path, false)
}

// pinDestination permits arbitrary metadata ONLY on the final O_PATH directory.
// This is a pin, not acceptance: destinationState must prove the visible exact
// mount before using that exception; unmounted leaves need trustedTarget.
func pinDestination(path string) (*os.File, error) {
	return walkDirectory(path, true)
}
func trustedDirectory(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	return directoryMetadataPolicy(st.Uid, st.Mode)
}
func walkDirectory(path string, allowLeafMetadata bool) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err = trustedDirectory(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if path != "/" {
		components := strings.Split(strings.TrimPrefix(path, "/"), "/")
		for i, component := range components {
			next, err := unix.Openat(fd, component, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			unix.Close(fd)
			if err != nil {
				return nil, err
			}
			fd = next
			if !allowLeafMetadata || i != len(components)-1 {
				if err = trustedDirectory(fd); err != nil {
					unix.Close(fd)
					return nil, err
				}
			}
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func (linuxExt4Ops) pinDevice(path string, write bool) (*pinnedDevice, error) {
	parent, err := secureDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	flags := unix.O_RDONLY
	if write {
		flags = unix.O_RDWR
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		file.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Uid != 0 {
		file.Close()
		return nil, fmt.Errorf("not a root-owned block device")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("block device lock: %w", err)
	}
	return &pinnedDevice{file, unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))}, nil
}
func (linuxExt4Ops) pinTarget(path string) (*pinnedTarget, error) {
	file, err := pinDestination(path)
	if err != nil {
		return nil, err
	}
	return &pinnedTarget{file, path}, nil
}
func (linuxExt4Ops) trustedTarget(target *pinnedTarget) error {
	return trustedDirectory(int(target.file.Fd()))
}

// dupDirectory opens a new real O_RDONLY descriptor for the directory held by
// target, relative to the pin (never a re-resolved pathname). O_PATH pins the
// mount but cannot serve directory reads, so consumers of Root need this
// readable descriptor, which inherits the pin's exact mount.
func (linuxExt4Ops) dupDirectory(target *pinnedTarget) (*os.File, error) {
	fd, err := unix.Openat(int(target.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), target.path), nil
}
func fdMountID(file *os.File) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", file.Fd()))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			id, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || id == 0 {
				return 0, fmt.Errorf("invalid fd mount ID")
			}
			return id, nil
		}
	}
	return 0, fmt.Errorf("fdinfo lacks mount ID")
}
func (linuxExt4Ops) snapshot(target *pinnedTarget, requireSame bool) (mountSnapshot, error) {
	fresh, err := pinDestination(target.path)
	if err != nil {
		return mountSnapshot{}, err
	}
	defer fresh.Close()
	visible, err := fdMountID(fresh)
	if err != nil {
		return mountSnapshot{}, err
	}
	if requireSame {
		old, err := fdMountID(target.file)
		if err != nil {
			return mountSnapshot{}, err
		}
		a, err := target.file.Stat()
		if err != nil {
			return mountSnapshot{}, err
		}
		b, err := fresh.Stat()
		if err != nil {
			return mountSnapshot{}, err
		}
		if old != visible || !os.SameFile(a, b) {
			return mountSnapshot{}, fmt.Errorf("destination replaced since pin")
		}
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return mountSnapshot{}, err
	}
	records, err := parseMountinfo(string(data))
	if err != nil {
		return mountSnapshot{}, err
	}
	// Reopen once more to reject path/mount replacement during the snapshot.
	again, err := pinDestination(target.path)
	if err != nil {
		return mountSnapshot{}, err
	}
	defer again.Close()
	after, err := fdMountID(again)
	if err != nil {
		return mountSnapshot{}, err
	}
	a, err := fresh.Stat()
	if err != nil {
		return mountSnapshot{}, err
	}
	b, err := again.Stat()
	if err != nil {
		return mountSnapshot{}, err
	}
	if after != visible || !os.SameFile(a, b) {
		return mountSnapshot{}, fmt.Errorf("destination changed during mount snapshot")
	}
	return mountSnapshot{visible, records}, nil
}
func (linuxExt4Ops) capacity(d *pinnedDevice) (uint64, error) {
	// BLKGETSIZE64 writes __u64, NOT an int (including on 32-bit Linux).
	var size uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, d.file.Fd(), uintptr(unix.BLKGETSIZE64), uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0, errno
	}
	return size, nil
}
func formatCommand(d *pinnedDevice, label, uuid string) *exec.Cmd {
	cmd := exec.Command("/sbin/mke2fs", "-F", "-t", "ext4", "-L", label, "-U", uuid,
		"-O", "metadata_csum,64bit,dir_index,extent", "-E", "lazy_itable_init=0,lazy_journal_init=0", "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{d.file}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return cmd
}
func (linuxExt4Ops) format(d *pinnedDevice, label, uuid string) error {
	output, err := formatCommand(d, label, uuid).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mke2fs: %w: %s", err, output)
	}
	return d.file.Sync()
}
func (linuxExt4Ops) uuid(d *pinnedDevice) (string, error) {
	// Identity only. This is NOT filesystem validity, freshness or repair logic.
	var super [120]byte
	if _, err := d.file.ReadAt(super[:], 1024); err != nil {
		return "", err
	}
	if binary.LittleEndian.Uint16(super[0x38:0x3a]) != 0xef53 {
		return "", fmt.Errorf("missing ext superblock identity")
	}
	raw := hex.EncodeToString(super[0x68:0x78])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:], nil
}
func (linuxExt4Ops) superblock(d *pinnedDevice) (ext4SuperSummary, error) {
	// Preflight observation only: magic, state, orphan list, feature bits and
	// UUID. It is never identity authorization for formatting, replay or repair.
	// The 2048-byte read starts at offset 0; parseExt4Superblock decodes the
	// superblock at data[1024:]. Reading at offset 1024 here would double-skip.
	var data [2048]byte
	if _, err := d.file.ReadAt(data[:], 0); err != nil {
		return ext4SuperSummary{}, err
	}
	return parseExt4Superblock(data[:])
}

// pinnedMountSource names the pinned node by its own path for ORDINARY mounts
// only: the kernel records that string verbatim as the mount's device name,
// and per-device consumers (cAdvisor under kubelet, for example) need /dev/vdX,
// not one shared /proc/self/fd/N spelling. The held descriptor still fixes the
// identity: the path must currently name the same root-owned block special
// (the destination state checks then require the visible mount's major/minor
// to match). The read-only probe does not use this: it mounts by the pinned
// device descriptor directly, never re-resolving a pathname.
func pinnedMountSource(d *pinnedDevice) (string, error) {
	source := d.file.Name()
	var st unix.Stat_t
	if err := unix.Lstat(source, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Uid != 0 ||
		unix.Major(uint64(st.Rdev)) != d.major || unix.Minor(uint64(st.Rdev)) != d.minor {
		return "", fmt.Errorf("block device path no longer names the pinned device")
	}
	return source, nil
}

// probeMountFlags and probeMountData pin the exact read-only/no-replay mount
// contract asserted by the Linux unit tests.
const probeMountFlags = unix.MS_RDONLY | unix.MS_NODEV | unix.MS_NOSUID

func (linuxExt4Ops) mountReadOnly(d *pinnedDevice, target *pinnedTarget) error {
	// noload mounts without journal recovery. Only the lease's separately
	// authorized Promote boundary can later replace it with a journaled RW mount.
	// The source is the pinned device descriptor itself, never a re-resolved
	// pathname: the kernel resolves /proc/self/fd/N to the exact pinned block
	// device for the mount. The probe feeds no per-device consumers, so
	// the verbatim /dev/vdX source string ordinary mounts preserve is not needed.
	return unix.Mount(fmt.Sprintf("/proc/self/fd/%d", d.file.Fd()), fmt.Sprintf("/proc/self/fd/%d", target.file.Fd()), "ext4", probeMountFlags, probeMountData)
}

// unmountReadOnly detaches the mount at destination with a plain, non-lazy
// umount(2). The caller must have proved from a fresh mountinfo snapshot that
// the visible mount is still the exact owned probe mount, and must hold no
// open descriptor into it — an O_PATH mount reference makes umount(2) EBUSY.
// A changed or foreign mount is never passed here; PID1 exclusive namespace
// ownership excludes a racing stacked replacement between proof and detach.
func (linuxExt4Ops) unmountReadOnly(_ *pinnedDevice, destination string) error {
	return unix.Unmount(destination, 0)
}

func (ops linuxExt4Ops) mount(d *pinnedDevice, target *pinnedTarget) error {
	source, err := pinnedMountSource(d)
	if err != nil {
		return err
	}
	return unix.Mount(source, fmt.Sprintf("/proc/self/fd/%d", target.file.Fd()), "ext4", unix.MS_NODEV|unix.MS_NOSUID, "errors=remount-ro")
}
