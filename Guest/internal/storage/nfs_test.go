//go:build linux

package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNFSHandlesFollowDirectoryRenameAndSupportHardLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "before"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "before", "file"), []byte("payload"), 0644); err != nil {
		t.Fatal(err)
	}
	handler := newVolumeNFSHandler(root)
	handle := handler.ToHandle(handler.filesystem, []string{"before", "file"})
	if err := handler.filesystem.Rename("before", "after"); err != nil {
		t.Fatal(err)
	}
	_, path, err := handler.FromHandle(handle)
	if err != nil || filepath.Join(path...) != filepath.Join("after", "file") {
		t.Fatalf("renamed handle resolved to %v, %v", path, err)
	}
	if err := handler.filesystem.Link(filepath.Join("after", "file"), filepath.Join("after", "link")); err != nil {
		t.Fatal(err)
	}
	file, err := os.Stat(filepath.Join(root, "after", "file"))
	if err != nil {
		t.Fatal(err)
	}
	link, err := os.Stat(filepath.Join(root, "after", "link"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(file, link) {
		t.Fatal("NFS hard link did not preserve inode identity")
	}
}
