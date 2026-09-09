//go:build linux

package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	nfs "github.com/willscott/go-nfs"
	"golang.org/x/sys/unix"
)

func TestNFSRejectsSpecialNodeDataAndRootDeviceCreation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root")
	}
	root := t.TempDir()
	h := newVolumeNFSHandler(root)
	if h.filesystem.rootErr != nil {
		t.Fatal(h.filesystem.rootErr)
	}
	defer h.filesystem.confined.Close()
	defer h.filesystem.rootFile.Close()
	f := h.filesystem
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	// Simulate an existing device populated outside NFS. Opening /dev/ptmx
	// would allocate a terminal, even if a post-open stat then rejected it.
	if err := unix.Mknod(filepath.Join(root, "device"), unix.S_IFCHR|0600, int(unix.Mkdev(5, 2))); err != nil {
		t.Fatal(err)
	}
	if err := f.Symlink("device", "device-link"); err != nil {
		t.Fatal(err)
	}
	err := h.WithIdentity(context.Background(), nfs.Identity{UID: 0, GID: 0}, func() error {
		for _, mode := range []uint32{unix.S_IFCHR, unix.S_IFBLK} {
			if err := f.Mknod("new-device", mode|0600, 1, 3); !errors.Is(err, unix.EPERM) {
				return errors.New("root NFS device creation was not rejected")
			}
		}
		for _, name := range []string{"fifo", "device", "device-link"} {
			for _, flags := range []int{os.O_RDONLY, os.O_WRONLY, os.O_WRONLY | os.O_TRUNC, os.O_CREATE | os.O_WRONLY} {
				file, err := f.OpenFile(name, flags, 0600)
				if file != nil {
					file.Close()
				}
				if !errors.Is(err, unix.EPERM) {
					return errors.New("special node data open was not rejected before open")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "new-device")); !os.IsNotExist(err) {
		t.Fatalf("device created: %v", err)
	}
}
