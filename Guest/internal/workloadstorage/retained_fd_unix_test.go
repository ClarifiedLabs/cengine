//go:build linux || darwin

package workloadstorage

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func retainedTestRoot(t *testing.T) (string, *os.File, context.Context) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return dir, root, ctx
}
func retainedTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestRetainedFDActualWriteSyncSameDescriptor(t *testing.T) {
	dir, root, ctx := retainedTestRoot(t)
	path := filepath.Join(dir, retainedFDName)
	retainedTestFile(t, path, []byte("original"))
	r, err := openRetainedFD(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	fd, identity := r.file.Fd(), r.identity
	flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR {
		t.Fatalf("not writable: %x %v", flags, err)
	}
	cloexec, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
	if err != nil || cloexec&unix.FD_CLOEXEC == 0 {
		t.Fatal("missing CLOEXEC")
	}
	if _, err := r.attemptWrite(ctx); err == nil {
		t.Fatal("attempt before positive")
	}
	result, err := r.positiveWrite(ctx)
	if err != nil || !result.completed || result.written != 1 || result.writeErr != nil || result.syncErr != nil {
		t.Fatalf("positive: %+v %v", result, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "\xa5riginal" {
		t.Fatalf("positive bytes %x %v", data, err)
	}
	if _, err := r.positiveWrite(ctx); err == nil {
		t.Fatal("duplicate positive")
	}
	// Replace the pathname, not the retained inode. The next real operation must
	// still mutate the original file, and success must never be called a denial.
	old := filepath.Join(dir, "original-renamed")
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	retainedTestFile(t, path, []byte("replacement"))
	result, err = r.attemptWrite(ctx)
	if err != nil || !result.completed || result.written != 1 || result.writeErr != nil || result.syncErr != nil {
		t.Fatalf("attempt: %+v %v", result, err)
	}
	if r.file.Fd() != fd || r.identity != identity {
		t.Fatal("descriptor changed")
	}
	data, err = os.ReadFile(old)
	if err != nil || string(data) != "\x5ariginal" {
		t.Fatalf("original bytes %x %v", data, err)
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("reopened replacement")
	}
	if _, err := r.attemptWrite(ctx); err == nil {
		t.Fatal("duplicate attempt")
	}
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.attemptWrite(ctx); err == nil {
		t.Fatal("closed FD accepted")
	}
}
func TestRetainedFDPinnedRootSurvivesBorrowedClose(t *testing.T) {
	dir, root, ctx := retainedTestRoot(t)
	retainedTestFile(t, filepath.Join(dir, retainedFDName), []byte("original"))
	pinned, err := retainedFDPinRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := retainedFDPinRoot(root); err == nil {
		duplicate.Close()
		t.Fatal("closed borrowed root was duplicated")
	}
	other, otherRoot, _ := retainedTestRoot(t)
	defer otherRoot.Close()
	retainedTestFile(t, filepath.Join(other, retainedFDName), []byte("unrelated"))
	r, err := openRetainedFD(ctx, pinned)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	result, err := r.positiveWrite(ctx)
	if err != nil || !result.completed || result.writeErr != nil || result.syncErr != nil {
		t.Fatal("pinned original not writable", result, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, retainedFDName))
	if err != nil || string(data) != "\xa5riginal" {
		t.Fatal("lost original root", data, err)
	}
	data, err = os.ReadFile(filepath.Join(other, retainedFDName))
	if err != nil || string(data) != "unrelated" {
		t.Fatal("wrote recycled root", data, err)
	}
}

func TestRetainedFDRejectUnsafeFixtures(t *testing.T) {
	for _, name := range []string{"missing", "symlink", "directory", "fifo", "empty", "oversize", "hardlink", "readonly"} {
		t.Run(name, func(t *testing.T) {
			dir, root, ctx := retainedTestRoot(t)
			path := filepath.Join(dir, retainedFDName)
			var err error
			switch name {
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside")
				retainedTestFile(t, outside, []byte("untouched"))
				err = os.Symlink(outside, path)
				defer func() {
					data, err := os.ReadFile(outside)
					if err != nil || string(data) != "untouched" {
						t.Fatal("escaped")
					}
				}()
			case "directory":
				err = os.Mkdir(path, 0700)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "empty":
				retainedTestFile(t, path, nil)
			case "oversize":
				retainedTestFile(t, path, make([]byte, 4097))
			case "hardlink":
				retainedTestFile(t, path, []byte("x"))
				err = os.Link(path, filepath.Join(dir, "alias"))
			case "readonly":
				retainedTestFile(t, path, []byte("x"))
				err = os.Chmod(path, 0400)
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := openRetainedFD(ctx, root)
			if err == nil {
				_ = r.close()
				t.Fatal("unsafe fixture accepted")
			}
			if name == "missing" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("created fixture")
				}
			}
		})
	}
}
func TestRetainedFDCancellationAndBusyAreNotCompletion(t *testing.T) {
	dir, root, ctx := retainedTestRoot(t)
	path := filepath.Join(dir, retainedFDName)
	retainedTestFile(t, path, []byte("original"))
	if r, err := openRetainedFD(context.Background(), root); err == nil {
		_ = r.close()
		t.Fatal("unbounded context accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if r, err := openRetainedFD(canceled, root); err == nil {
		_ = r.close()
		t.Fatal("canceled open accepted")
	}
	r, err := openRetainedFD(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	result, err := r.positiveWrite(canceled)
	if !errors.Is(err, context.Canceled) || result.completed {
		t.Fatal("cancellation became evidence")
	}
	r.mu.Lock()
	result, err = r.positiveWrite(ctx)
	closeErr := r.close()
	r.mu.Unlock()
	if !errors.Is(err, errRetainedFDBusy) || result.completed || !errors.Is(closeErr, errRetainedFDBusy) {
		t.Fatal("busy became completion/release")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatal("canceled/busy operation wrote")
	}
	if _, err := r.positiveWrite(ctx); err != nil {
		t.Fatal(err)
	}
	result, err = r.attemptWrite(canceled)
	if !errors.Is(err, context.Canceled) || result.completed {
		t.Fatal("cancellation became negative")
	}
}
