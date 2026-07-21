//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNormalizedDeviceRelativeRejectsEscapesAndNonCanonicalPaths(t *testing.T) {
	for _, path := range []string{"relative", "/dev/", "/dev/../etc/passwd", "/dev//data", "/dev/data/.."} {
		if relative, err := normalizedDeviceRelative(path); err == nil {
			t.Fatalf("normalizedDeviceRelative(%q) = %q, want error", path, relative)
		}
	}
	if relative, err := normalizedDeviceRelative("/dev/nested/data"); err != nil || relative != "nested/data" {
		t.Fatalf("normalizedDeviceRelative valid path = %q, %v", relative, err)
	}
}

func TestOpenDeviceParentRefusesSymlinkTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	descriptor, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(descriptor)
	if parent, _, err := openDeviceParent(descriptor, "linked/device"); err == nil {
		unix.Close(parent)
		t.Fatal("device parent traversal followed a symlink")
	}
}

func TestChmodDeviceAtRefusesLastComponentSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "device")); err != nil {
		t.Fatal(err)
	}
	descriptor, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(descriptor)
	if err := chmodDeviceAt(descriptor, "device", 0o666); err == nil {
		t.Fatal("device chmod followed a last-component symlink")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("outside target mode = %#o, want 0600", info.Mode().Perm())
	}
}
