//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// This test requires the explicitly selected real-ext4 test filesystem. It does
// not create a VM, mount, format, or silently substitute stat-only identity.
func TestPrepareExt4IdentityRealFilesystem(t *testing.T) {
	root := t.TempDir()
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Skip("requires real ext4 TMPDIR")
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	uuid, err := backingUUID(fd)
	if err != nil {
		t.Fatal(err)
	}
	if uuid == ([16]byte{}) {
		t.Fatal("missing real filesystem UUID")
	}
	rootBefore, err := ext4Identity(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	before, err := copyIdentityAt(fd, "a")
	if err != nil {
		t.Fatal(err)
	}
	hardlink, err := copyIdentityAt(fd, "b")
	if err != nil || hardlink != before {
		t.Fatalf("hardlinks changed identity: %+v %+v %v", before, hardlink, err)
	}
	if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "renamed")); err != nil {
		t.Fatal(err)
	}
	renamed, err := copyIdentityAt(fd, "renamed")
	if err != nil || renamed != before {
		t.Fatalf("rename changed identity: %+v %v", renamed, err)
	}
	if err := os.Symlink("renamed", filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	symlink, err := copyIdentityAt(fd, "symlink")
	if err != nil || symlink.FileType != unix.S_IFLNK || symlink == before {
		t.Fatalf("symlink followed or unsupported: %+v %v", symlink, err)
	}
	pin, err := copyPinAt(fd, "renamed", unix.O_PATH)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pin)
	if err := os.Remove(filepath.Join(root, "renamed")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	retained, err := ext4Identity(pin)
	if err != nil || retained != before {
		t.Fatalf("retained unlinked identity changed: %+v %v", retained, err)
	}
	if err := os.WriteFile(filepath.Join(root, "renamed"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	replacement, err := copyIdentityAt(fd, "renamed")
	if err != nil || replacement == before {
		t.Fatalf("replacement adopted old identity: %+v %v", replacement, err)
	}
	// A separately opened root models a fresh attachment, not retained node IDs.
	fresh, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fresh)
	rootAfter, err := ext4Identity(fresh)
	if err != nil || rootAfter != rootBefore {
		t.Fatalf("fresh root identity differs: %+v %+v %v", rootBefore, rootAfter, err)
	}
	got, err := copyIdentityAt(fresh, "renamed")
	if err != nil || got != replacement {
		t.Fatalf("fresh attachment changed identity: %+v %v", got, err)
	}
}

func TestPrepareIdentityAtRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "inside"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inside", "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("inside", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if pin, err := copyPinAt(fd, "alias/file", unix.O_PATH); err == nil {
		unix.Close(pin)
		t.Fatal("traversed intermediate symlink")
	}
}
