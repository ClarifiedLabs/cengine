//go:build linux

package storageboot

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHeldWorkerRootRejectsNilAndHostTmpfs(t *testing.T) {
	if identity, err := heldWorkerRoot(nil); err == nil || identity != (workerRootIdentity{}) {
		t.Fatal("accepted nil held root", identity, err)
	}
	// Inspect an existing host tmpfs; never mount, elevate or create VM assets.
	// Cross-compilation on Darwin does not execute this Linux check.
	for _, path := range []string{"/dev/shm", "/run", "/dev"} {
		root, err := os.Open(path)
		if err != nil {
			continue
		}
		var fs unix.Statfs_t
		err = unix.Fstatfs(int(root.Fd()), &fs)
		if err != nil || uint64(fs.Type) != uint64(unix.TMPFS_MAGIC) {
			root.Close()
			continue
		}
		identity, err := heldWorkerRoot(root)
		root.Close()
		if err == nil || identity != (workerRootIdentity{}) {
			t.Fatal("accepted actual non-ext4 tmpfs root", path, identity, err)
		}
		return
	}
	t.Skip("no existing readable host tmpfs root; no privileged mount attempted")
}
