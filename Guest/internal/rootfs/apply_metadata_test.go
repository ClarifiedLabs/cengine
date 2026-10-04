//go:build linux

package rootfs

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func metadataArchive(t *testing.T, headers ...*tar.Header) *bytes.Buffer {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, header := range headers {
		header.Uid, header.Gid = os.Getuid(), os.Getgid()
		header.Format = tar.FormatPAX
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &archive
}

const outsideMetadataTimestamp = 1_700_000_000_000_000_123

func outsideMetadataTarget(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(path, "user.guard", []byte("unchanged"), 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 12345, 12345); err != nil {
			t.Fatal(err)
		}
	}
	stamp := unix.NsecToTimespec(outsideMetadataTimestamp)
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{stamp, stamp}, 0); err != nil {
		t.Fatal(err)
	}
	return path
}

func expectOutsideMetadataUnchanged(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("outside mode = %o; want 600", info.Mode().Perm())
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if os.Geteuid() == 0 {
		uid, gid = 12345, 12345
	}
	if stat.Uid != uid || stat.Gid != gid {
		t.Errorf("outside owner = %d:%d; want %d:%d", stat.Uid, stat.Gid, uid, gid)
	}
	if stat.Atim.Nano() != outsideMetadataTimestamp || stat.Mtim.Nano() != outsideMetadataTimestamp {
		t.Errorf("outside timestamps changed: atime %v, mtime %v", stat.Atim, stat.Mtim)
	}
	buffer := make([]byte, 128)
	n, err := unix.Getxattr(path, "user.guard", buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "unchanged" {
		t.Errorf("outside xattr = %q; want unchanged", buffer[:n])
	}
}

func TestApplyLayerHardlinkToSymlinkDoesNotFollowMetadata(t *testing.T) {
	for _, withXattr := range []bool{false, true} {
		name := "without-xattr"
		if withXattr {
			name = "with-xattr"
		}
		t.Run(name, func(t *testing.T) {
			root, outside := t.TempDir(), outsideMetadataTarget(t)
			link := &tar.Header{Name: "hardlink", Linkname: "symlink", Typeflag: tar.TypeLink, Mode: 0777}
			if withXattr {
				link.PAXRecords = map[string]string{"SCHILY.xattr.user.guard": "changed"}
			}
			err := applyLayer(root, metadataArchive(t,
				&tar.Header{Name: "symlink", Linkname: outside, Typeflag: tar.TypeSymlink, Mode: 0777}, link))
			if withXattr {
				if !errors.Is(err, unix.EPERM) {
					t.Errorf("symlink user xattr error = %v; want EPERM", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			expectOutsideMetadataUnchanged(t, outside)
			info, err := os.Lstat(filepath.Join(root, "hardlink"))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("hardlink is not a symlink inode")
			}
		})
	}
}

func TestApplyLayerRejectsReplacedDeferredDirectoryMetadata(t *testing.T) {
	root, outside := t.TempDir(), outsideMetadataTarget(t)
	err := applyLayer(root, metadataArchive(t,
		&tar.Header{Name: "directory", Typeflag: tar.TypeDir, Mode: 0777,
			PAXRecords: map[string]string{"SCHILY.xattr.user.guard": "changed"}},
		&tar.Header{Name: "directory", Linkname: outside, Typeflag: tar.TypeSymlink, Mode: 0777}))
	if err == nil || !strings.Contains(err.Error(), "inode type changed") {
		t.Errorf("replaced directory error = %v; want inode type changed", err)
	}
	expectOutsideMetadataUnchanged(t, outside)
}

func TestApplyLayerRejectsReplacedHardlinkParents(t *testing.T) {
	for _, replaceSource := range []bool{false, true} {
		name := "target-parent"
		if replaceSource {
			name = "source-parent"
		}
		t.Run(name, func(t *testing.T) {
			root, outside := t.TempDir(), outsideMetadataTarget(t)
			source, target := "source", "parent/new-link"
			if replaceSource {
				source, target = "parent/target", "new-link"
			}
			err := applyLayer(root, metadataArchive(t,
				&tar.Header{Name: "source", Typeflag: tar.TypeReg, Mode: 0600},
				&tar.Header{Name: target, Linkname: source, Typeflag: tar.TypeLink, Mode: 0777,
					PAXRecords: map[string]string{"SCHILY.xattr.user.guard": "changed"}},
				&tar.Header{Name: "parent", Linkname: filepath.Dir(outside), Typeflag: tar.TypeSymlink, Mode: 0777}))
			if err == nil {
				t.Error("replaced hardlink parent accepted")
			}
			expectOutsideMetadataUnchanged(t, outside)
			if _, err := os.Lstat(filepath.Join(filepath.Dir(outside), "new-link")); !os.IsNotExist(err) {
				t.Errorf("hardlink escaped root: %v", err)
			}
		})
	}
}

func TestApplyLayerSymlinkUserXattrsFailClosed(t *testing.T) {
	for _, value := range []string{"", "nonempty"} {
		name := "empty"
		if value != "" {
			name = "nonempty"
		}
		t.Run(name, func(t *testing.T) {
			root, outside := t.TempDir(), outsideMetadataTarget(t)
			err := applyLayer(root, metadataArchive(t, &tar.Header{
				Name: "symlink", Linkname: outside, Typeflag: tar.TypeSymlink, Mode: 0777,
				PAXRecords: map[string]string{"SCHILY.xattr.user.guard": value},
			}))
			if !errors.Is(err, unix.EPERM) {
				t.Errorf("symlink user xattr error = %v; want EPERM", err)
			}
			expectOutsideMetadataUnchanged(t, outside)
		})
	}
}

func TestMetadataPinsInodeAcrossPathReplacement(t *testing.T) {
	for _, replaceParent := range []bool{false, true} {
		name := "final-component"
		if replaceParent {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			root, outside := t.TempDir(), outsideMetadataTarget(t)
			parent := filepath.Join(root, "parent")
			if err := os.Mkdir(parent, 0755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(parent, "target")
			if err := os.WriteFile(target, nil, 0600); err != nil {
				t.Fatal(err)
			}
			rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(rootFD)
			fd, err := openMetadata(rootFD, "parent/target")
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			moved := filepath.Join(root, "moved")
			if replaceParent {
				if err := os.Rename(parent, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), parent); err != nil {
					t.Fatal(err)
				}
				moved = filepath.Join(moved, "target")
			} else {
				if err := os.Rename(target, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, target); err != nil {
					t.Fatal(err)
				}
			}
			header := &tar.Header{Typeflag: tar.TypeReg, Mode: 0644, Uid: os.Getuid(), Gid: os.Getgid(),
				Xattrs: map[string]string{"user.guard": "changed"}}
			// Deterministically place replacement between descriptor resolution and
			// metadata writes, rather than relying on probabilistic race timing.
			if err := metadataFD(fd, header); err != nil {
				t.Fatal(err)
			}
			if err := metadata(rootFD, "parent/target", header); err == nil {
				t.Error("replacement path accepted")
			}
			expectOutsideMetadataUnchanged(t, outside)
			info, err := os.Stat(moved)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0644 {
				t.Errorf("pinned mode = %o; want 644", info.Mode().Perm())
			}
			buffer := make([]byte, 128)
			n, err := unix.Getxattr(moved, "user.guard", buffer)
			if err != nil {
				t.Fatal(err)
			}
			if string(buffer[:n]) != "changed" {
				t.Errorf("pinned xattr = %q; want changed", buffer[:n])
			}
		})
	}
}
