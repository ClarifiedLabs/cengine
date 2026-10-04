//go:build linux

package supervisor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/storageidentity"
	"dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func pinSymlinkForTest(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func symlinkXattrsForTest(t *testing.T, path string) *confinedXattrSnapshot {
	t.Helper()
	// Independent no-follow syscall control; do not verify procfd copying
	// solely with the same procfd implementation under test.
	operations := confinedXattrOperations{
		list: func(_ int, b []byte) (int, error) { return unix.Llistxattr(path, b) },
		get:  func(_ int, name string, b []byte) (int, error) { return unix.Lgetxattr(path, name, b) },
	}
	snapshot, err := snapshotConfinedXattrsWith(-1, operations)
	if err != nil || snapshot.State != "supported" {
		t.Fatalf("DIRECT-EXT4 symlink snapshot: %#v, %v", snapshot, err)
	}
	return snapshot
}

func TestDirectExt4SymlinkXattrsRetainPinnedIdentity(t *testing.T) {
	for _, mutation := range []string{"rename", "unlink"} {
		t.Run(mutation, func(t *testing.T) {
			root := directExt4XattrRoot(t)
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
			setRequiredXattr(t, target, "user.outside", []byte("unchanged"))
			setRequiredXattr(t, target, "security.capability", directExt4Capability())
			wantTarget := fileXattrsForTest(t, target)
			var targetStat unix.Stat_t
			if err := unix.Stat(target, &targetStat); err != nil {
				t.Fatal(err)
			}
			paths := []string{filepath.Join(root, "source"), filepath.Join(root, "destination")}
			var fds [2]int
			for i, path := range paths {
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				fds[i] = pinSymlinkForTest(t, path)
			}
			if err := os.Lchown(paths[0], 10001, 10002); err != nil {
				t.Fatal(err)
			}
			if err := unix.Lsetxattr(paths[0], "security.capability", directExt4Capability(), 0); err != nil {
				t.Fatal(err)
			}
			want := symlinkXattrsForTest(t, paths[0])
			var sourceStat unix.Stat_t
			if err := unix.Fstat(fds[0], &sourceStat); err != nil {
				t.Fatal(err)
			}
			// Deterministically place replacement names after both no-follow
			// pins: metadata and literal reads must retain the original inodes.
			for _, path := range paths {
				var err error
				if mutation == "rename" {
					err = os.Rename(path, path+"-retained")
				} else {
					err = os.Remove(path)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := readlinkat(fds[0], ""); err != nil || got != target {
				t.Fatalf("pinned literal = %q, %v", got, err)
			}
			if err := copyConfinedSymlinkMetadata(fds[0], fds[1], sourceStat); err != nil {
				t.Fatal(err)
			}
			operations := confinedSymlinkXattrSyscalls()
			got, err := snapshotConfinedXattrsWith(fds[1], operations)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("pinned destination attrs = %#v, want %#v, %v", got, want, err)
			}
			var destinationStat unix.Stat_t
			if err := unix.Fstat(fds[1], &destinationStat); err != nil {
				t.Fatal(err)
			}
			if destinationStat.Uid != sourceStat.Uid || destinationStat.Gid != sourceStat.Gid || destinationStat.Atim != sourceStat.Atim || destinationStat.Mtim != sourceStat.Mtim {
				t.Fatal("pinned symlink metadata changed identity")
			}
			// Exercise exact-inode removal too, without touching either name.
			if err := restoreConfinedXattrsWith(fds[1], &confinedXattrSnapshot{State: "supported", Entries: []confinedXattr{}}, operations); err != nil {
				t.Fatal(err)
			}
			if _, err := operations.get(fds[1], "security.capability", make([]byte, 64)); !errors.Is(err, unix.ENODATA) {
				t.Fatalf("pinned remove: %v", err)
			}
			for _, path := range paths {
				if got := symlinkXattrsForTest(t, path); len(got.Entries) != 0 {
					t.Fatalf("replacement symlink touched: %#v", got)
				}
			}
			var after unix.Stat_t
			if err := unix.Stat(target, &after); err != nil || !reflect.DeepEqual(after, targetStat) {
				t.Fatalf("target metadata changed: %#v, %v", after, err)
			}
			if got := fileXattrsForTest(t, target); !reflect.DeepEqual(got, wantTarget) {
				t.Fatal("target xattrs changed")
			}
		})
	}
}

func TestDirectExt4SymlinkXattrFailureRollsBack(t *testing.T) {
	sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
	link := filepath.Join(sourcePath, "capable-link")
	if err := os.Symlink("missing", link); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lsetxattr(link, "security.capability", directExt4Capability(), 0); err != nil {
		t.Fatalf("DIRECT-EXT4 CAP_SETFCAP setup: %v", err)
	}
	setRequiredXattr(t, destinationPath, "user.original", []byte("keep"))
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	original, err := confinedRootMetadata(destination.fd)
	if err != nil {
		t.Fatal(err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var words [2]unix.CapUserData
	if err := unix.Capget(&header, &words[0]); err != nil {
		t.Fatal(err)
	}
	caps := uint64(words[0].Effective) | uint64(words[1].Effective)<<32
	if caps&(1<<unix.CAP_SETFCAP) == 0 {
		t.Fatal("DIRECT-EXT4 requires CAP_SETFCAP")
	}
	worker := new(storageidentity.Worker)
	var copyErr error
	err = worker.Do(storagewire.Caller{FSUID: 0, FSGID: 0, Groups: []uint32{}, EffectiveCaps: caps &^ (1 << unix.CAP_SETFCAP)}, 0, func() error {
		copyErr = copyConfinedDirectory(source, destination)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(copyErr, unix.EPERM) || !strings.Contains(copyErr.Error(), "security.capability") || !strings.Contains(copyErr.Error(), "capable-link") {
		t.Fatalf("symlink capability failure was not propagated: %v", copyErr)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := recoverConfinedCopyTransaction(destination); err != nil {
			t.Fatal(err)
		}
		after, err := confinedRootMetadata(destination.fd)
		if err != nil || !reflect.DeepEqual(after, original) {
			t.Fatalf("failed copy changed root: %#v, %v", after, err)
		}
		entries, err := os.ReadDir(destinationPath)
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed copy left entries: %v, %v", entries, err)
		}
	}
	buffer := make([]byte, 64)
	n, err := unix.Lgetxattr(link, "security.capability", buffer)
	if err != nil || !bytes.Equal(buffer[:n], directExt4Capability()) {
		t.Fatalf("failed copy changed source capability: %x, %v", buffer, err)
	}
}

// No injected metadata success, mutable syscall hook, or production debug path:
// deny the actual Linux syscall by withholding its required effective capability.
func TestDirectExt4EmptySymlinkMetadataFailureRollsBack(t *testing.T) {
	for _, fault := range []struct {
		name       string
		capability uint
		operation  string
	}{
		{"ownership", unix.CAP_CHOWN, "chown copy-up symlink"},
		{"timestamps", unix.CAP_FOWNER, "set copy-up symlink times"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
			link := filepath.Join(sourcePath, "empty-link")
			if err := os.Symlink("missing", link); err != nil {
				t.Fatal(err)
			}
			if err := os.Lchown(link, 10001, 10002); err != nil {
				t.Fatal(err)
			}
			if err := unix.UtimesNanoAt(unix.AT_FDCWD, link, []unix.Timespec{{Sec: 1700000000}, {Sec: 1700000001}}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				t.Fatal(err)
			}
			if attrs := symlinkXattrsForTest(t, link); len(attrs.Entries) != 0 {
				t.Fatal("fixture must have no xattrs")
			}
			setRequiredXattr(t, destinationPath, "user.original", []byte("keep"))
			setRequiredXattr(t, destinationPath, "security.capability", directExt4Capability())
			source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
			original, err := confinedRootMetadata(destination.fd)
			if err != nil {
				t.Fatal(err)
			}
			header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
			var words [2]unix.CapUserData
			if err := unix.Capget(&header, &words[0]); err != nil {
				t.Fatal(err)
			}
			caps := uint64(words[0].Effective) | uint64(words[1].Effective)<<32
			if caps&(1<<unix.CAP_CHOWN) == 0 || caps&(1<<unix.CAP_FOWNER) == 0 {
				t.Fatal("DIRECT-EXT4 requires CHOWN and FOWNER setup capabilities")
			}
			var copyErr error
			worker := new(storageidentity.Worker)
			err = worker.Do(storagewire.Caller{FSUID: 0, FSGID: 0, Groups: []uint32{}, EffectiveCaps: caps &^ (1 << fault.capability)}, 0, func() error {
				copyErr = copyConfinedDirectory(source, destination)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(copyErr, unix.EPERM) || !strings.Contains(copyErr.Error(), fault.operation) || !strings.Contains(copyErr.Error(), "empty-link") {
				t.Fatalf("required %s failure did not reach transaction caller: %v", fault.name, copyErr)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := recoverConfinedCopyTransaction(destination); err != nil {
					t.Fatal(err)
				}
				after, err := confinedRootMetadata(destination.fd)
				if err != nil || !reflect.DeepEqual(after, original) {
					t.Fatalf("failed metadata copy changed root: %#v, %v", after, err)
				}
				entries, err := os.ReadDir(destinationPath)
				if err != nil || len(entries) != 0 {
					t.Fatalf("failed metadata copy left entries: %v, %v", entries, err)
				}
			}
			var st unix.Stat_t
			if err := unix.Lstat(link, &st); err != nil {
				t.Fatal(err)
			}
			if st.Uid != 10001 || st.Gid != 10002 || st.Mtim.Sec != 1700000001 {
				t.Fatalf("source metadata changed: %#v", st)
			}
		})
	}
}
