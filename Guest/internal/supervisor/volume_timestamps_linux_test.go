//go:build linux

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestInitializeVolumeCopiesRootTimesAfterCleanup(t *testing.T) {
	for _, populated := range []bool{false, true} {
		for _, mode := range []uint32{0750, 0000} {
			t.Run(fmt.Sprintf("populated=%v/mode=%o", populated, mode), func(t *testing.T) {
				if mode == 0 && os.Geteuid() != 0 {
					t.Skip("requires root for restrictive source permissions")
				}
				rootfs, volume := t.TempDir(), t.TempDir()
				source := filepath.Join(rootfs, "data")
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
				if populated {
					if err := os.WriteFile(filepath.Join(source, "seed"), []byte("seed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
				if os.Geteuid() == 0 {
					uid, gid = 10001, 10002
					if err := os.Chown(source, int(uid), int(gid)); err != nil {
						t.Fatal(err)
					}
				}
				if err := unix.Chmod(source, mode); err != nil {
					t.Fatal(err)
				}
				atime, mtime := time.Unix(1_600_000_000, 321_000_000), time.Unix(1_700_000_000, 123_000_000)
				if err := os.Chtimes(source, atime, mtime); err != nil {
					t.Fatal(err)
				}
				if err := initializeVolumeAt(rootfs, volume, protocol.Mount{Destination: "/data"}); err != nil {
					t.Fatal(err)
				}
				assertCopyupRootTimes(t, volume, atime, mtime)
				assertVolumeRootMetadata(t, volume, uid, gid, mode)
				if _, err := os.Lstat(filepath.Join(volume, confinedCopyTransactionName)); !os.IsNotExist(err) {
					t.Fatalf("transaction remains: %v", err)
				}
				if populated {
					if seed, err := os.ReadFile(filepath.Join(volume, "seed")); err != nil || string(seed) != "seed" {
						t.Fatalf("seed = %q, %v", seed, err)
					}
				}
			})
		}
	}
}

func TestCopyupRootTimesUsePinnedPreEnumerationSnapshot(t *testing.T) {
	sourcePath, parent := t.TempDir(), t.TempDir()
	destinationPath, movedPath := filepath.Join(parent, "volume"), filepath.Join(parent, "moved")
	outside := t.TempDir()
	if err := os.Mkdir(destinationPath, 0700); err != nil {
		t.Fatal(err)
	}
	atime, mtime := time.Unix(1_600_000_000, 321_000_000), time.Unix(1_700_000_000, 123_000_000)
	if err := os.Chtimes(sourcePath, atime, mtime); err != nil {
		t.Fatal(err)
	}
	outsideTime := time.Unix(1_500_000_000, 987_000_000)
	if err := os.Chtimes(outside, outsideTime, outsideTime); err != nil {
		t.Fatal(err)
	}
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	operations := confinedXattrSyscalls()
	replaced := false
	operations.list = func(fd int, value []byte) (int, error) {
		if !replaced {
			replaced = true
			// This runs after the initial source stat, before enumeration. Change
			// the live source timestamps and replace the destination pathname;
			// finalization must use neither the late source stat nor this symlink.
			later := time.Unix(1_800_000_000, 0)
			if err := os.Chtimes(sourcePath, later, later); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(destinationPath, movedPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, destinationPath); err != nil {
				t.Fatal(err)
			}
		}
		return unix.Flistxattr(fd, value)
	}
	if err := copyConfinedDirectoryWithRootXattrs(source, destination, operations); err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("snapshot boundary did not run")
	}
	assertCopyupRootTimes(t, movedPath, atime, mtime)
	assertCopyupRootTimes(t, outside, outsideTime, outsideTime)
	if _, err := os.Lstat(filepath.Join(movedPath, confinedCopyTransactionName)); !os.IsNotExist(err) {
		t.Fatalf("transaction remains: %v", err)
	}
}

func assertCopyupRootTimes(t *testing.T, path string, atime, mtime time.Time) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Atim != unix.NsecToTimespec(atime.UnixNano()) || stat.Mtim != unix.NsecToTimespec(mtime.UnixNano()) {
		t.Fatalf("root times after cleanup = %v/%v, want %v/%v", stat.Atim, stat.Mtim, atime, mtime)
	}
}
