package storagefuse

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Construct only the descriptor plumbing under the unprivileged test tempdir;
// production pinMountParent/create retain the mandatory root trust checks.
func testPinnedLeaf(t *testing.T) *pinnedMountPath {
	t.Helper()
	parent := t.TempDir()
	pin, err := openDirectoryAt(unix.AT_FDCWD, parent)
	if err != nil {
		t.Fatal(err)
	}
	p := &pinnedMountPath{path: filepath.Join(parent, "private"), name: "private", chain: []directoryPin{pin}}
	t.Cleanup(p.close)
	return p
}
func testCreateLeaf(t *testing.T, p *pinnedMountPath) {
	t.Helper()
	if err := unix.Mkdirat(p.parentFD(), p.name, 0700); err != nil {
		t.Fatal(err)
	}
	leaf, err := openDirectoryAt(p.parentFD(), p.name)
	if err != nil {
		t.Fatal(err)
	}
	p.created, p.leaf = true, &leaf
}
func TestCleanupOnlyRemovesOwnedEmptyLeaf(t *testing.T) {
	p := testPinnedLeaf(t)
	testCreateLeaf(t, p)
	if err := os.WriteFile(filepath.Join(p.path, "keep"), []byte("user work"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err == nil {
		t.Fatal("nonempty leaf removed")
	}
	if err := os.Rename(p.path, p.path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err != ErrProfile {
		t.Fatal("replacement not detected", err)
	}
	if _, err := os.Lstat(p.path); err != nil {
		t.Fatal("replacement removed", err)
	}
	if err := os.Remove(p.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p.path+"-old", p.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p.path, "keep")); err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err != nil {
		t.Fatal(err)
	}
}
func TestPinnedParentRenameNeverRedirectsCreationOrCleanup(t *testing.T) {
	p := testPinnedLeaf(t)
	parent := filepath.Dir(p.path)
	moved := parent + "-moved"
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.path, 0700); err != nil {
		t.Fatal(err)
	}
	testCreateLeaf(t, p) // pinned mkdirat affects the moved original, not replacement
	if _, err := os.Stat(filepath.Join(moved, p.name)); err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.path); err != nil {
		t.Fatal("replacement removed", err)
	}
	if _, err := os.Stat(filepath.Join(moved, p.name)); !os.IsNotExist(err) {
		t.Fatal("original not removed", err)
	}
}
func TestCleanupWithoutCapturedLeafNeverRemovesAnything(t *testing.T) {
	p := testPinnedLeaf(t)
	if err := os.Mkdir(p.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err != nil {
		t.Fatal(err)
	}
	p.created = true
	if err := p.remove(); err != ErrProfile {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.path); err != nil {
		t.Fatal(err)
	}
}
func TestEveryAncestorMustBeTrusted(t *testing.T) {
	root := unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0755}
	private := unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0700}
	user := unix.Stat_t{Uid: 501, Mode: unix.S_IFDIR | 0700}
	writable := unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0775}
	for _, tc := range []struct {
		name  string
		chain []unix.Stat_t
		ok    bool
	}{
		{"trusted", []unix.Stat_t{root, root, private}, true},
		{"user-grandparent", []unix.Stat_t{root, user, private}, false},
		{"writable-grandparent", []unix.Stat_t{root, writable, private}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok := true
			for _, st := range tc.chain {
				ok = ok && trustedDirectory(st)
			}
			if ok != tc.ok {
				t.Fatal("ancestor trust mismatch")
			}
		})
	}
	// Exercise the real descriptor walk: a user/writable temp ancestor cannot be
	// rescued by a private descendant, and symlink components are never followed.
	p := testPinnedLeaf(t)
	if err := os.Mkdir(p.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(p.path), 0777); err != nil {
		t.Fatal(err)
	}
	if got, err := pinMountParent(filepath.Join(p.path, "mount")); err == nil {
		got.close()
		t.Fatal("untrusted ancestor accepted")
	}
	link := filepath.Join(filepath.Dir(p.path), "link")
	if err := os.Symlink(p.path, link); err != nil {
		t.Fatal(err)
	}
	if pin, err := openDirectoryAt(p.parentFD(), "link"); err == nil {
		pin.file.Close()
		t.Fatal("symlink followed")
	}
}
func TestMountPathClaimSerializesGenerations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount")
	release, err := claimMountPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := claimMountPath(path); err == nil {
				r()
				t.Error("concurrent generation admitted")
			}
		}()
	}
	wg.Wait()
	release()
	next, err := claimMountPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer next()
	release() // stale generation must not release its successor
	if r, err := claimMountPath(path); err == nil {
		r()
		t.Fatal("old release removed successor")
	}
}
