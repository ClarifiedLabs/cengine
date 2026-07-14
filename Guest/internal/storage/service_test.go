//go:build linux

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestRemoveDirectoryContentsDoesNotFollowSymlinks(t *testing.T) {
	root:=t.TempDir();outside:=t.TempDir();if err:=os.WriteFile(filepath.Join(outside,"keep"),[]byte("safe"),0644);err!=nil{t.Fatal(err)};if err:=os.Mkdir(filepath.Join(root,"nested"),0755);err!=nil{t.Fatal(err)};if err:=os.WriteFile(filepath.Join(root,"nested/file"),[]byte("remove"),0644);err!=nil{t.Fatal(err)};if err:=os.Symlink(outside,filepath.Join(root,"link"));err!=nil{t.Fatal(err)}
	fd,err:=unix.Open(root,unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,0);if err!=nil{t.Fatal(err)};defer unix.Close(fd);if err:=removeDirectoryContents(fd);err!=nil{t.Fatal(err)};entries,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)};if len(entries)!=0{t.Fatalf("directory is not empty: %v",entries)};if data,err:=os.ReadFile(filepath.Join(outside,"keep"));err!=nil||string(data)!="safe"{t.Fatalf("symlink target changed: %q %v",data,err)}
}

func TestSetattrSizeOpensFileWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	if err := os.WriteFile(path, make([]byte, 16_384), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, setattrOpenFlags(&protocol.FSRequestBody{Flags: 8}), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, 32_768); err != nil {
		t.Fatalf("truncate through setattr descriptor: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 32_768 {
		t.Fatalf("resized file is %d bytes, want 32768", info.Size())
	}
}

func TestFsyncNodeSupportsPathOnlyDirectoryDescriptors(t *testing.T) {
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil { t.Fatal(err) }
	defer unix.Close(fd)
	if err := fsyncNode(fd, 0); err != nil {
		t.Fatalf("fsync directory through O_PATH node: %v", err)
	}
}

func TestSymlinkXattrReadsMatchEmptyLinuxSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("missing-target", path); err != nil { t.Fatal(err) }
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil { t.Fatal(err) }
	defer unix.Close(fd)
	attr, err := statFD(fd)
	if err != nil { t.Fatal(err) }
	session := &session{nodes: map[uint64]nodeRef{1: {fd: fd, attr: attr}}}
	listed, err := session.listxattr(&protocol.FSRequestBody{Node: 1})
	if err != nil { t.Fatalf("list symlink xattrs: %v", err) }
	if len(listed.Names) != 0 { t.Fatalf("symlink xattrs = %v, want none", listed.Names) }
	_, err = session.getxattr(&protocol.FSRequestBody{Node: 1, Xattr: "user.missing"})
	if !errors.Is(err, unix.ENODATA) { t.Fatalf("get missing symlink xattr = %v, want ENODATA", err) }
}
