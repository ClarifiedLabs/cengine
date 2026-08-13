//go:build linux

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNFSExclusiveCopyupRenameDoesNotReplaceBackingContent(t *testing.T) {
	root := t.TempDir()
	transaction := filepath.Join(root, "volume", ".cengine-copyup-transaction")
	staging := filepath.Join(transaction, "staging")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "entry"), []byte("copy-up"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := newVolumeNFSHandler(root)
	from := filepath.Join("volume", ".cengine-copyup-transaction", "staging", "entry")
	to := filepath.Join("volume", "entry")
	if err := handler.filesystem.Rename(from, to); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, to)); err != nil || string(got) != "copy-up" {
		t.Fatalf("exclusive copy-up rename = %q, %v", got, err)
	}

	if err := os.WriteFile(filepath.Join(staging, "entry"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := handler.filesystem.Rename(from, to); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive copy-up collision error = %v, want EEXIST", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, to)); err != nil || string(got) != "copy-up" {
		t.Fatalf("exclusive copy-up collision replaced destination = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, from)); err != nil || string(got) != "replacement" {
		t.Fatalf("exclusive copy-up collision removed source = %q, %v", got, err)
	}
}

func TestNFSExclusiveCopyupRenameClassification(t *testing.T) {
	for _, test := range []struct {
		from string
		to   string
		want bool
	}{
		{"volume/.cengine-copyup-transaction/manifest.tmp", "volume/.cengine-copyup-transaction/manifest.json", true},
		{"/volume/.cengine-copyup-transaction/staging/etc", "/volume/etc", true},
		{"volume/.cengine-copyup-transaction/staging/a/b", "volume/a/b", false},
		{"volume/staging/etc", "volume/etc", false},
		{"other/.cengine-copyup-transaction/staging/etc", "volume/etc", false},
	} {
		if got := isExclusiveCopyupRename(test.from, test.to); got != test.want {
			t.Errorf("isExclusiveCopyupRename(%q, %q) = %t, want %t", test.from, test.to, got, test.want)
		}
	}
}

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
