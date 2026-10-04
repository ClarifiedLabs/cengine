//go:build linux

package disk

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// No mount or formatter is executed by these tests.
func TestFormatterUsesInheritedPinAfterPathReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original")
	original, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	super := make([]byte, 2048)
	super[1024+0x38] = 0x53
	super[1024+0x39] = 0xef
	raw, _ := hex.DecodeString(strings.ReplaceAll(testUUID, "-", ""))
	copy(super[1024+0x68:], raw)
	if _, err := original.Write(super); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".held"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("foreign replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	d := &pinnedDevice{file: original, major: 8, minor: 16}
	cmd := formatCommand(d, "data", testUUID)
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != original || cmd.Args[len(cmd.Args)-1] != "/proc/self/fd/3" {
		t.Fatalf("not pinned: %+v", cmd)
	}
	if strings.Contains(strings.Join(cmd.Args, " "), path) {
		t.Fatal("formatter reopens original pathname")
	}
	if !strings.Contains(strings.Join(cmd.Args, " "), "-U "+testUUID) {
		t.Fatal("UUID absent")
	}
	actual, err := (linuxExt4Ops{}).uuid(d)
	if err != nil || actual != testUUID {
		t.Fatalf("UUID from wrong inode: %s %v", actual, err)
	}
}

// No mount or formatter is executed: this is the file-backed native adapter
// regression for the read-only probe's superblock preflight. The superblock
// lives at byte offset 1024; the adapter must read from offset 0 exactly once
// (a ReadAt at 1024 plus the parser's own data[1024:] skip double-offsets).
func TestNativeSuperblockAdapterReadsFileBackedImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	img := make([]byte, 2048)
	super := img[1024:]
	binary.LittleEndian.PutUint16(super[0x38:0x3a], 0xef53)
	binary.LittleEndian.PutUint16(super[0x3a:0x3c], ext4ValidFS)
	binary.LittleEndian.PutUint32(super[0x5c:0x60], ext4FeatureCompatHasJournal)
	binary.LittleEndian.PutUint32(super[0x60:0x64], ext4FeatureIncompatExtents|ext4FeatureIncompat64bit)
	binary.LittleEndian.PutUint32(super[0x64:0x68], ext4FeatureROMetadataCsum)
	raw, _ := hex.DecodeString(strings.ReplaceAll(testUUID, "-", ""))
	copy(super[0x68:0x78], raw)
	if err := os.WriteFile(path, img, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := (linuxExt4Ops{}).superblock(&pinnedDevice{file: f})
	if err != nil {
		t.Fatalf("file-backed superblock rejected (double offset?): %v", err)
	}
	if s.UUID != testUUID || s.State != ext4ValidFS || s.LastOrphan != 0 ||
		s.Compat != ext4FeatureCompatHasJournal || s.Incompat != ext4FeatureIncompatExtents|ext4FeatureIncompat64bit ||
		s.ROCompat != ext4FeatureROMetadataCsum {
		t.Fatalf("file-backed superblock mismatch: %+v", s)
	}
	if err := requireCleanSuperblock(s, testUUID); err != nil {
		t.Fatal(err)
	}
	// A non-empty s_last_orphan at superblock offset 0xe8 must surface.
	binary.LittleEndian.PutUint32(super[0xe8:0xec], 11)
	if err := os.WriteFile(path, img, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = (linuxExt4Ops{}).superblock(&pinnedDevice{file: f})
	if err != nil {
		t.Fatal(err)
	}
	if s.LastOrphan != 11 {
		t.Fatalf("orphan list not parsed: %+v", s)
	}
	if err := requireCleanSuperblock(s, testUUID); err == nil {
		t.Fatal("non-empty orphan list accepted")
	}
	// Short images fail closed.
	short, err := os.Create(filepath.Join(t.TempDir(), "short.img"))
	if err != nil {
		t.Fatal(err)
	}
	defer short.Close()
	if err := short.Truncate(1500); err != nil {
		t.Fatal(err)
	}
	if _, err := (linuxExt4Ops{}).superblock(&pinnedDevice{file: short}); err == nil {
		t.Fatal("short image accepted")
	}
}

func TestIdentityRejectsShortOrNonExtSuperblock(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "identity")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := &pinnedDevice{file: f}
	if _, err := (linuxExt4Ops{}).uuid(d); err == nil {
		t.Fatal("short read accepted")
	}
	if err := f.Truncate(2048); err != nil {
		t.Fatal(err)
	}
	if _, err := (linuxExt4Ops{}).uuid(d); err == nil {
		t.Fatal("zero header accepted")
	}
	if _, err := (linuxExt4Ops{}).capacity(d); err == nil {
		t.Fatal("regular file accepted by block ioctl")
	}
}
func TestNativeSnapshotUsesHeldDirectoryMountID(t *testing.T) {
	ops := linuxExt4Ops{}
	target, err := ops.pinTarget("/")
	if err != nil {
		t.Fatal(err)
	}
	defer target.file.Close()
	s, err := ops.snapshot(target, true)
	if err != nil {
		t.Fatal(err)
	}
	id, err := fdMountID(target.file)
	if err != nil || s.visible != id {
		t.Fatalf("mount ID %d != %d: %v", s.visible, id, err)
	}
}
func TestNativeDestinationLeafAndAncestors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned /run fixture required")
	}
	dir, err := os.MkdirTemp("/run", "cengine-ext4-pin-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	parent := filepath.Join(dir, "parent")
	leaf := filepath.Join(parent, "leaf")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []int{0, 1000} {
		for _, mode := range []uint32{0, 0700, 0777} {
			if err := unix.Chown(leaf, uid, 1000); err != nil {
				t.Fatal(err)
			}
			if err := unix.Chmod(leaf, mode); err != nil {
				t.Fatal(err)
			}
			pin, err := (linuxExt4Ops{}).pinTarget(leaf)
			if err != nil {
				t.Fatalf("leaf pin uid=%d mode=%o: %v", uid, mode, err)
			}
			err = (linuxExt4Ops{}).trustedTarget(pin)
			pin.file.Close()
			if (err != nil) != (uid != 0 || mode&0022 != 0) {
				t.Fatalf("unmounted leaf accepted: %v", err)
			}
		}
	}
	for _, change := range []func() error{
		func() error { return unix.Chmod(parent, 0777) },
		func() error {
			if err := unix.Chmod(parent, 0700); err != nil {
				return err
			}
			return unix.Chown(parent, 1000, 1000)
		},
	} {
		if err := change(); err != nil {
			t.Fatal(err)
		}
		if pin, err := (linuxExt4Ops{}).pinTarget(leaf); err == nil {
			pin.file.Close()
			t.Fatal("untrusted intermediate accepted")
		}
	}
	if err := unix.Chown(parent, 0, 0); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{alias, filepath.Join(alias, "leaf")} {
		if pin, err := (linuxExt4Ops{}).pinTarget(path); err == nil {
			pin.file.Close()
			t.Fatal("symlink accepted")
		}
	}
}

// No mount or formatter is executed: this pins the exact read-only/no-replay
// syscall contract the native runtime test exercises.
func TestPromotionMountContractPinned(t *testing.T) {
	const wantFlags = unix.MS_NODEV | unix.MS_NOSUID
	if promotionMountFlags != wantFlags || promotionMountData != "errors=remount-ro,data=ordered" {
		t.Fatal("promotion must create a journaled writable mount without remount/noload")
	}
}

func TestProbeMountContractPinned(t *testing.T) {
	const wantFlags = unix.MS_RDONLY | unix.MS_NODEV | unix.MS_NOSUID
	if probeMountFlags != wantFlags {
		t.Fatalf("probe mount flags = %#x, want MS_RDONLY|MS_NODEV|MS_NOSUID %#x", probeMountFlags, wantFlags)
	}
	if probeMountData != "noload" {
		t.Fatalf("probe mount data = %q, want noload", probeMountData)
	}
}

func TestOwnedLoopIdentityProof(t *testing.T) {
	good := unix.LoopInfo64{Device: 123, Inode: 456, Number: 7, Sizelimit: testBytes, Flags: unix.LO_FLAGS_AUTOCLEAR}
	if !ownedLoopMatches(&good, 123, 456, 7) {
		t.Fatal("valid owned identity rejected")
	}
	for _, mutate := range []func(*unix.LoopInfo64){
		func(i *unix.LoopInfo64) { i.Device++ }, func(i *unix.LoopInfo64) { i.Inode++ },
		func(i *unix.LoopInfo64) { i.Number++ }, func(i *unix.LoopInfo64) { i.Offset++ },
		func(i *unix.LoopInfo64) { i.Sizelimit++ }, func(i *unix.LoopInfo64) { i.Flags = 0 },
		func(i *unix.LoopInfo64) { i.Flags |= unix.LO_FLAGS_READ_ONLY },
		func(i *unix.LoopInfo64) { i.Rdevice++ }, func(i *unix.LoopInfo64) { i.Encrypt_type++ },
		func(i *unix.LoopInfo64) { i.Encrypt_key_size++ },
	} {
		bad := good
		mutate(&bad)
		if ownedLoopMatches(&bad, 123, 456, 7) {
			t.Fatalf("wrong backing accepted: %+v", bad)
		}
	}
}

func TestNativePinRejectsUnsafeParentsAndNonBlocks(t *testing.T) {
	if f, err := secureDirectory("/tmp"); err == nil {
		f.Close()
		t.Fatal("world-writable parent accepted")
	}
	if d, err := (linuxExt4Ops{}).pinDevice("/dev/null", false); err == nil {
		d.file.Close()
		t.Fatal("character device accepted")
	}
	if d, err := (linuxInheritedMountOps{}).pinDeviceMetadata("/dev/null"); err == nil {
		d.file.Close()
		t.Fatal("inherited character device accepted")
	}
	if d, err := (linuxInheritedMountOps{}).pinDeviceMetadata("/tmp/foreign"); err == nil {
		d.file.Close()
		t.Fatal("inherited device under unsafe parent accepted")
	}
}
