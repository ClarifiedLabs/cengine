//go:build linux

package rootfs

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyLayerPreservesEmptyAndBinaryPAXXattrs(t *testing.T) {
	root := t.TempDir()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, header := range []*tar.Header{
		{Name: "directory", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "directory/file", Typeflag: tar.TypeReg, Mode: 0644},
		{Name: "hardlink", Linkname: "directory/file", Typeflag: tar.TypeLink, Mode: 0644},
	} {
		header.Uid, header.Gid = os.Getuid(), os.Getgid()
		header.Format = tar.FormatPAX
		header.PAXRecords = map[string]string{
			"SCHILY.xattr.user.empty":  "",
			"SCHILY.xattr.user.binary": "value\x00\xff",
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := applyLayer(root, &archive); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"directory", "directory/file", "hardlink"} {
		for name, want := range map[string]string{"user.empty": "", "user.binary": "value\x00\xff"} {
			buffer := make([]byte, 128)
			n, err := unix.Lgetxattr(filepath.Join(root, path), name, buffer)
			if err != nil {
				t.Fatalf("%s %s: %v", path, name, err)
			}
			if string(buffer[:n]) != want {
				t.Fatalf("%s %s = %q; want %q", path, name, buffer[:n], want)
			}
		}
	}
}

func TestMetadataKeepsExplicitHeaderXattrPrecedence(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	header := &tar.Header{
		Typeflag: tar.TypeReg, Mode: 0600, Uid: os.Getuid(), Gid: os.Getgid(),
		Xattrs: map[string]string{"user.value": "explicit"},
		PAXRecords: map[string]string{
			"SCHILY.xattr.user.value": "pax", "SCHILY.xattr.user.empty": "",
			"unrelated.field": "not-an-xattr",
		},
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if err := metadata(rootFD, "file", header); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"user.value": "explicit", "user.empty": ""} {
		buffer := make([]byte, 128)
		n, err := unix.Lgetxattr(path, name, buffer)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(buffer[:n]) != want {
			t.Fatalf("%s = %q; want %q", name, buffer[:n], want)
		}
	}
}
