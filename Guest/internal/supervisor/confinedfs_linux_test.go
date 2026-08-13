//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestValidateConfinedRelativePathRejectsAmbiguousAndOversizedPaths(t *testing.T) {
	tooDeep := strings.Repeat("a/", maxConfinedPathDepth) + "a"
	tests := []string{
		"",
		"/absolute",
		".",
		"..",
		"a/./b",
		"a/../b",
		"a//b",
		"a/",
		"a\x00b",
		strings.Repeat("a", unix.NAME_MAX+1),
		strings.Repeat("a", unix.PathMax),
		tooDeep,
	}
	for _, path := range tests {
		if _, err := validateConfinedRelativePath(path); err == nil {
			t.Errorf("validateConfinedRelativePath(%q) unexpectedly succeeded", path)
		}
	}
	components, err := validateConfinedRelativePath("directory/file")
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 2 || components[0] != "directory" || components[1] != "file" {
		t.Fatalf("components = %#v", components)
	}
}

func TestOpenConfinedAtENOSYSFallbackRejectsSymlinks(t *testing.T) {
	rootPath := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "nested", "file"), []byte("inside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "file"), []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootPath, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "file"), filepath.Join(rootPath, "final")); err != nil {
		t.Fatal(err)
	}
	root, err := openConfinedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()

	calls := 0
	unsupported := func(_ int, _ string, how *unix.OpenHow) (int, error) {
		calls++
		wantResolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS)
		if how.Resolve != wantResolve {
			t.Fatalf("openat2 resolve flags = %#x, want %#x", how.Resolve, wantResolve)
		}
		return -1, unix.ENOSYS
	}
	fd, err := openConfinedAtWith(root.fd, "nested/file", unix.O_RDONLY, 0, unsupported)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "fallback-file")
	data, readErr := os.ReadFile(procFDPath(fd))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read/close fallback descriptor: %v / %v", readErr, closeErr)
	}
	if string(data) != "inside" {
		t.Fatalf("fallback data = %q", data)
	}
	for _, path := range []string{"escape/file", "final"} {
		if fd, err := openConfinedAtWith(root.fd, path, unix.O_PATH|unix.O_NOFOLLOW, 0, unsupported); err == nil {
			_ = unix.Close(fd)
			t.Errorf("fallback opened symlink path %q", path)
		}
	}
	if calls != 3 {
		t.Fatalf("openat2 attempts = %d, want 3", calls)
	}
}

func TestConfinedRootRemainsPinnedWhenPathIsReplaced(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "root")
	movedPath := filepath.Join(parent, "moved")
	outside := t.TempDir()
	if err := os.Mkdir(rootPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "value"), []byte("inside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "value"), []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	root, err := openConfinedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if err := os.Rename(rootPath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, rootPath); err != nil {
		t.Fatal(err)
	}

	fd, err := openConfinedAt(root.fd, "value", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(procFDPath(fd))
	_ = unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "inside" {
		t.Fatalf("pinned root read %q, want inside", data)
	}
}

func TestCopyConfinedDirectoryPreservesEntriesLinksAndMetadata(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(sourcePath, "directory"), 0710); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(sourcePath, "directory", "file")
	if err := os.WriteFile(filePath, []byte("contents"), 0641); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_700_000_000, 123_000_000)
	if err := os.Chtimes(filePath, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filePath, filepath.Join(sourcePath, "hardlink")); err != nil {
		t.Fatal(err)
	}
	literalTarget := "../../outside"
	if err := os.Symlink(literalTarget, filepath.Join(sourcePath, "literal")); err != nil {
		t.Fatal(err)
	}
	xattrCopied := unix.Setxattr(filePath, "user.cengine-test", []byte("metadata"), 0) == nil

	source, err := openConfinedRoot(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	destination, err := openConfinedRoot(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.close()
	if err := copyConfinedDirectory(source, destination); err != nil {
		t.Fatal(err)
	}

	copiedPath := filepath.Join(destinationPath, "directory", "file")
	data, err := os.ReadFile(copiedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "contents" {
		t.Fatalf("copied contents = %q", data)
	}
	info, err := os.Stat(copiedPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0641 {
		t.Fatalf("copied mode = %#o, want 0641", info.Mode().Perm())
	}
	if !info.ModTime().Equal(mtime) {
		t.Fatalf("copied mtime = %v, want %v", info.ModTime(), mtime)
	}
	var regularStat, hardlinkStat unix.Stat_t
	if err := unix.Stat(copiedPath, &regularStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(destinationPath, "hardlink"), &hardlinkStat); err != nil {
		t.Fatal(err)
	}
	if regularStat.Dev != hardlinkStat.Dev || regularStat.Ino != hardlinkStat.Ino {
		t.Fatal("hard-linked source files were copied as distinct inodes")
	}
	target, err := os.Readlink(filepath.Join(destinationPath, "literal"))
	if err != nil {
		t.Fatal(err)
	}
	if target != literalTarget {
		t.Fatalf("copied symlink target = %q, want %q", target, literalTarget)
	}
	if xattrCopied {
		buffer := make([]byte, 32)
		length, err := unix.Getxattr(copiedPath, "user.cengine-test", buffer)
		if err != nil {
			t.Fatal(err)
		}
		if string(buffer[:length]) != "metadata" {
			t.Fatalf("copied xattr = %q", buffer[:length])
		}
	}
}

func TestCopyConfinedDirectoryRejectsSpecialNodes(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "before"), []byte("rollback"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(sourcePath, "zz-pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := openConfinedRoot(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	destination, err := openConfinedRoot(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.close()
	err = copyConfinedDirectory(source, destination)
	if err == nil || !strings.Contains(err.Error(), "special file") {
		t.Fatalf("copy special node error = %v", err)
	}
	entries, readErr := os.ReadDir(destinationPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed copy-up left transaction entries: %#v", entries)
	}
}

func TestRecoverConfinedCopyTransactionRollsBackMatchingEntriesAndPreservesReplacements(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "matching"), []byte("matching"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "replaced"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sourcePath, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "nested", "child"), []byte("child"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := openConfinedRoot(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	destination, err := openConfinedRoot(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.close()
	publishStaleConfinedCopyTransaction(t, source, destination)

	if err := os.Remove(filepath.Join(destinationPath, "replaced")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destinationPath, "replaced"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverConfinedCopyTransaction(destination); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"matching", "nested"} {
		if _, err := os.Lstat(filepath.Join(destinationPath, relative)); !os.IsNotExist(err) {
			t.Fatalf("matching transaction entry %q survived recovery: %v", relative, err)
		}
	}
	replacement, err := os.ReadFile(filepath.Join(destinationPath, "replaced"))
	if err != nil {
		t.Fatal(err)
	}
	if string(replacement) != "replacement" {
		t.Fatalf("replacement contents = %q", replacement)
	}
	if _, err := os.Lstat(filepath.Join(destinationPath, confinedCopyTransactionName)); !os.IsNotExist(err) {
		t.Fatalf("copy-up transaction survived recovery: %v", err)
	}

	if err := os.Remove(filepath.Join(destinationPath, "replaced")); err != nil {
		t.Fatal(err)
	}
	if err := copyConfinedDirectory(source, destination); err != nil {
		t.Fatal(err)
	}
	for relative, want := range map[string]string{
		"matching":     "matching",
		"replaced":     "original",
		"nested/child": "child",
	} {
		got, err := os.ReadFile(filepath.Join(destinationPath, relative))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("retried copy %q = %q, want %q", relative, got, want)
		}
	}
}

func TestRecoverConfinedCopyTransactionRemovesUncommittedStaging(t *testing.T) {
	destinationPath := t.TempDir()
	transactionPath := filepath.Join(destinationPath, confinedCopyTransactionName)
	if err := os.MkdirAll(filepath.Join(transactionPath, confinedCopyStagingName), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(transactionPath, confinedCopyStagingName, "partial"),
		[]byte("partial"),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	destination, err := openConfinedRoot(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.close()
	if err := recoverConfinedCopyTransaction(destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("uncommitted transaction survived recovery: %v", err)
	}
}

func publishStaleConfinedCopyTransaction(
	t *testing.T,
	source *confinedRoot,
	destination *confinedRoot,
) {
	t.Helper()
	if err := unix.Mkdirat(destination.fd, confinedCopyTransactionName, 0700); err != nil {
		t.Fatal(err)
	}
	transactionFD, err := unix.Openat(
		destination.fd,
		confinedCopyTransactionName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(transactionFD)
	if err := unix.Mkdirat(transactionFD, confinedCopyStagingName, 0700); err != nil {
		t.Fatal(err)
	}
	stagingFD, err := unix.Openat(
		transactionFD,
		confinedCopyStagingName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stagingFD)
	state := &confinedCopyState{hardlinks: make(map[confinedInode]confinedHardlink)}
	defer state.close()
	if err := state.copyDirectoryContents(source.fd, stagingFD, ""); err != nil {
		t.Fatal(err)
	}
	if err := writeConfinedCopyManifest(transactionFD, state.created); err != nil {
		t.Fatal(err)
	}
	entries, err := readConfinedDirectory(stagingFD)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := unix.Renameat2(
			stagingFD, entry.Name(), destination.fd, entry.Name(), unix.RENAME_NOREPLACE,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := syncConfinedDirectory(destination.fd); err != nil {
		t.Fatal(err)
	}
}

func TestConfinedDirectoryEmptinessUsesPinnedDescriptor(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "volume")
	movedPath := filepath.Join(parent, "original")
	outside := t.TempDir()
	if err := os.Mkdir(rootPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, "lost+found"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "attacker"), []byte("present"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := openConfinedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if err := os.Rename(rootPath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, rootPath); err != nil {
		t.Fatal(err)
	}
	empty, err := confinedDirectoryIsEmpty(root, "lost+found")
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Fatal("replacement path affected descriptor-relative emptiness check")
	}
}
