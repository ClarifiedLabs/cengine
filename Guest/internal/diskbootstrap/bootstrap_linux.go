//go:build linux

package diskbootstrap

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"dev.cengine/guest/internal/disk"
	"dev.cengine/guest/internal/vsock"
	"golang.org/x/sys/unix"
)

var bootMu sync.Mutex
var bootAttempted bool

// Keep a failed cleanup lease reachable until contained PID1 exit: GC must not
// finalize its locked block FD while an owned/uncertain mount remains. Boot is
// one-shot, so this is bounded to one lease (including after ownership transfer).
var bootProbe *disk.Ext4ReadOnlyLease

// Kept independently of verified evidence and its one-shot fresh permission:
// initialization can fail after writing/mounting but before RunVerified returns.
var bootFresh *disk.Ext4ShutdownLease

// An ordinary existing mount has no fresh/resume shutdown lease. Track its
// attempt before the syscall, so a failed ordinary mount cannot masquerade as
// a pre-mutation boot failure when cleanup sees no lease.
var bootStorageUnleasedMount bool

// CloseStorageShutdownLeases is cleanup only. PID1 must first close admission,
// positively reap every owned worker, and close every duplicated storage root.
// An error requires keeping PID1 alive and retaining these leases for host hard
// fallback. Call only after private-owner EOF or terminal pre-Ready boot
// failure, never on daemon loss or a recoverable service command failure.
func CloseStorageShutdownLeases() error {
	bootMu.Lock()
	fresh, probe, unleasedMount := bootFresh, bootProbe, bootStorageUnleasedMount
	bootMu.Unlock()
	if unleasedMount {
		return errors.New("storage shutdown lease unavailable for ordinary mount")
	}
	// With no attempted mount and no lease, boot failed before any disk
	// mutation: there is nothing to unmount and a fatal boot may power off.
	var err error
	if fresh != nil {
		err = errors.Join(err, fresh.Close())
	}
	if probe != nil {
		err = errors.Join(err, probe.Close())
	}
	return err
}

// Run is PID1's mandatory gate. There is no mixed-version or mount-only bypass.
// Even a failed attempt permanently consumes the in-process session opportunity.
func Run(kind string) error {
	result, err := RunVerified(kind)
	if err == nil {
		result.Close()
	}
	return err
}

// RunVerified returns unforgeable evidence only after the whole batch and host commit.
func RunVerified(kind string) (VerifiedBootResult, error) {
	bootMu.Lock()
	if bootAttempted {
		bootMu.Unlock()
		return VerifiedBootResult{}, failure("commit", nil)
	}
	bootAttempted = true
	bootMu.Unlock()
	if os.Getpid() != 1 || !validKind(kind) {
		return VerifiedBootResult{}, failure("invalid-manifest", nil)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return VerifiedBootResult{}, failure("invalid-frame", nil)
	}
	nonce[6] = nonce[6]&0x0f | 0x40
	nonce[8] = nonce[8]&0x3f | 0x80
	s := hex.EncodeToString(nonce[:])
	bootNonce := s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
	inventory, err := inventoryDisks(kind)
	if err != nil {
		return VerifiedBootResult{}, failure("disk-mismatch", nil)
	}
	listener, err := vsock.Listen(Port)
	if err != nil {
		return VerifiedBootResult{}, failure("invalid-peer", nil)
	}
	ops := &linuxOperations{kind: kind, inventory: inventory}
	transferred := false
	defer func() {
		if !transferred {
			// A failed detach retains the pin until this contained PID1 exits.
			_ = ops.probe.Close()
		}
	}()
	ack, err := acceptEvidence(listener, Hello{Version: Version, Type: "hello", Kind: kind, GuestBootNonce: bootNonce, Disks: inventory}, ops)
	if err != nil {
		return VerifiedBootResult{}, err
	}
	if kind == "container" {
		return VerifiedBootResult{state: &verifiedState{container: &ContainerBinding{ack.ShimLaunchUUID, ack.GuestBootNonce}}}, nil
	}
	if ack.Sync == "read-only-no-replay" {
		// Do not call pinStorageRoot: its sync is a write-side operation.
		root, err := ops.probe.Root()
		if err != nil {
			return VerifiedBootResult{}, failure("disk-mismatch", nil)
		}
		// Retain only the opaque lease's own root pin. Promotion must be able
		// to detach this RO mount; no ordinary root descriptor may escape.
		if err := root.Close(); err != nil {
			return VerifiedBootResult{}, failure("disk-mismatch", nil)
		}
		transferred = true
		return VerifiedBootResult{state: &verifiedState{probe: &ops.probe, binding: StorageBinding{ack.ShimLaunchUUID, ack.GuestBootNonce, ack.Disks[0].Ext4UUID, ack.Disks[0].Bytes}}}, nil
	}
	var root *os.File
	if ops.fresh != nil {
		// Sync was performed through this same lease during 4105. Never
		// reopen/flock the device while retaining our own exclusive pin.
		root, err = ops.fresh.Root()
	} else {
		root, err = pinStorageRoot(ack.Disks[0])
	}
	if err != nil {
		return VerifiedBootResult{}, failure("disk-mismatch", nil)
	}
	return VerifiedBootResult{state: &verifiedState{root: root, fresh: ack.Disks[0].OperationUUID != nil, binding: StorageBinding{ack.ShimLaunchUUID, ack.GuestBootNonce, ack.Disks[0].Ext4UUID, ack.Disks[0].Bytes}}}, nil
}
func authenticatedPeer(connection net.Conn) bool {
	peer, ok := connection.RemoteAddr().(vsock.Addr)
	return ok && peer.CID == RemoteCID
}
func acceptSession(listener net.Listener, hello Hello, ops diskOperations) error {
	_, err := acceptEvidence(listener, hello, ops)
	return err
}
func acceptEvidence(listener net.Listener, hello Hello, ops diskOperations) (*Synced, error) {
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return nil, failure("invalid-peer", nil)
		}
		if !authenticatedPeer(connection) {
			_ = connection.Close()
			continue
		}
		// Close before hello or any authorization; this listener is never reopened.
		if err := listener.Close(); err != nil {
			_ = connection.Close()
			return nil, failure("invalid-peer", nil)
		}
		defer connection.Close()
		return sessionEvidence(connection, hello, ops)
	}
}

// Inventory every attached virtio block disk, not a manifest-selected subset.
// Partitions, aliases, noncontiguous names, wrong serials and capacity changes
// fail before any mutation. Inert virtual loop/ram devices are not attachments.
func inventoryDisks(kind string) ([]HelloDisk, error) {
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return nil, err
	}
	var result []HelloDisk
	seen := map[uint64]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			resolved, err := filepath.EvalSymlinks(filepath.Join("/sys/class/block", name))
			if err != nil || !strings.HasPrefix(resolved, "/sys/devices/virtual/block/") {
				return nil, failure("disk-mismatch", nil)
			}
			// Configured loop devices could overlap an attachment and are forbidden.
			if _, err := os.Stat(filepath.Join(resolved, "loop")); err == nil || !errors.Is(err, os.ErrNotExist) {
				return nil, failure("disk-mismatch", nil)
			}
			continue
		}
		i := len(result)
		if i >= MaximumDisks || name != fmt.Sprintf("vd%c", 'a'+i) {
			return nil, failure("disk-mismatch", nil)
		}
		base := filepath.Join("/sys/class/block", name)
		if _, err := os.Stat(filepath.Join(base, "partition")); err == nil || !errors.Is(err, os.ErrNotExist) {
			return nil, failure("disk-mismatch", nil)
		}
		serial, err := os.ReadFile(filepath.Join(base, "serial"))
		if err != nil || strings.TrimSuffix(string(serial), "\n") != blockIdentifier(i) {
			return nil, failure("disk-mismatch", nil)
		}
		size, err := os.ReadFile(filepath.Join(base, "size"))
		if err != nil {
			return nil, err
		}
		sectors, err := strconv.ParseUint(strings.TrimSpace(string(size)), 10, 64)
		if err != nil || sectors == 0 || sectors > (1<<63-1)/512 {
			return nil, failure("disk-mismatch", nil)
		}
		dev, err := os.ReadFile(filepath.Join(base, "dev"))
		if err != nil {
			return nil, err
		}
		parts := strings.Split(strings.TrimSpace(string(dev)), ":")
		if len(parts) != 2 {
			return nil, failure("disk-mismatch", nil)
		}
		major, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return nil, err
		}
		minor, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, err
		}
		rdev := unix.Mkdev(uint32(major), uint32(minor))
		if seen[rdev] {
			return nil, failure("disk-mismatch", nil)
		}
		seen[rdev] = true
		if err := verifyInventoryDevice("/dev/"+name, rdev, sectors*512); err != nil {
			return nil, err
		}
		result = append(result, HelloDisk{Ordinal: uint32(i), BlockIdentifier: blockIdentifier(i), Bytes: sectors * 512})
	}
	if !validCount(len(result)) || (kind == "storage" && len(result) != 1) {
		return nil, failure("disk-mismatch", nil)
	}
	return result, nil
}
func verifyInventoryDevice(path string, rdev, expectedBytes uint64) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Uid != 0 || uint64(st.Rdev) != rdev {
		return failure("disk-mismatch", nil)
	}
	var capacity uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BLKGETSIZE64), uintptr(unsafe.Pointer(&capacity)))
	if errno != 0 {
		return errno
	}
	if capacity != expectedBytes {
		return failure("disk-mismatch", nil)
	}
	return nil
}

type linuxOperations struct {
	fresh     *disk.Ext4ShutdownLease
	probe     disk.Ext4ReadOnlyLease
	kind      string
	inventory []HelloDisk
}

func (ops linuxOperations) prepare(targets []target) error {
	current, err := inventoryDisks(ops.kind)
	if err != nil || len(current) != len(ops.inventory) {
		return failure("disk-mismatch", nil)
	}
	for i := range current {
		if current[i] != ops.inventory[i] {
			return failure("disk-mismatch", nil)
		}
	}
	// PID1 owns this fresh namespace. Create only derived mountpoints, never
	// chmod/chown a leaf (which could already be an arbitrary-metadata ext4 root).
	for _, target := range targets {
		if err := os.MkdirAll(target.destination, 0755); err != nil {
			return err
		}
	}
	return nil
}
func (ops *linuxOperations) probeReadOnly(t target, uuid string, size uint64) (identity, error) {
	var err error
	ops.probe, err = disk.ProbeExt4ReadOnly(t.device, t.destination, uuid, size)
	bootMu.Lock()
	bootProbe = &ops.probe
	bootMu.Unlock()
	observed := ops.probe.Identity()
	return identity{uuid: observed.UUID, bytes: observed.Bytes}, err
}

func (ops *linuxOperations) initialize(t target, uuid string, size uint64) error {
	if ops.kind != "storage" {
		return disk.InitializeExt4(t.device, t.destination, t.label, uuid, size)
	}
	lease, err := disk.InitializeExt4ForShutdown(t.device, t.destination, t.label, uuid, size)
	ops.fresh = &lease
	bootMu.Lock()
	bootFresh = ops.fresh // retain cleanup-only failures, not just successful boots
	bootMu.Unlock()
	return err
}
func (ops *linuxOperations) mount(t target) error {
	if ops.kind == "storage" {
		bootMu.Lock()
		bootStorageUnleasedMount = true
		bootMu.Unlock()
	}
	return disk.MountExistingExt4(t.device, t.destination)
}
func (ops *linuxOperations) sync(t target) (identity, error) {
	var observed disk.Ext4Identity
	var err error
	if ops.fresh != nil {
		observed, err = ops.fresh.SyncIdentity()
	} else {
		observed, err = disk.SyncExt4Identity(t.device, t.destination)
	}
	return identity{uuid: observed.UUID, bytes: observed.Bytes}, err
}

// PID1 alone owns the mount namespace. Hold the actual /data root across
// construction, and reverify the exact visible ext4 after acquiring that FD.
func pinStorageRoot(want SyncedDisk) (*os.File, error) {
	fd, err := unix.Open("/data", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), "verified-storage-root")
	fail := func() (*os.File, error) { root.Close(); return nil, failure("disk-mismatch", nil) }
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || st.Ino != 2 {
		return fail()
	}
	before, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return fail()
	}
	observed, err := disk.SyncExt4Identity("/dev/vda", "/data")
	if err != nil || observed.UUID != want.Ext4UUID || observed.Bytes != want.Bytes {
		return fail()
	}
	visible, err := os.Open("/data")
	if err != nil {
		return fail()
	}
	defer visible.Close()
	info, err := visible.Stat()
	held, heldErr := root.Stat()
	after, readErr := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", visible.Fd()))
	mountID := func(data []byte) string {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "mnt_id:") {
				return line
			}
		}
		return ""
	}
	var device unix.Stat_t
	if err != nil || heldErr != nil || readErr != nil || !os.SameFile(info, held) || mountID(before) == "" || mountID(before) != mountID(after) || unix.Stat("/dev/vda", &device) != nil || uint64(st.Dev) != uint64(device.Rdev) {
		return fail()
	}
	return root, nil
}
