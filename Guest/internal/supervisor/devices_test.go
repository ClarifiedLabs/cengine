//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateStandardDeviceSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dev"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := createStandardDeviceSymlinks(root); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1",
		"stderr": "/proc/self/fd/2",
	}
	for name, target := range want {
		value, err := os.Readlink(filepath.Join(root, "dev", name))
		if err != nil {
			t.Fatalf("read %s symlink: %v", name, err)
		}
		if value != target {
			t.Fatalf("%s symlink = %q, want %q", name, value, target)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "dev", "console")); !os.IsNotExist(err) {
		t.Fatalf("console created with standard symlinks: %v", err)
	}
}
