//go:build linux || darwin

package workloadstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOriginalRootReadOwnersRetainTwoReadOnlyDescriptions(t *testing.T) {
	_, _, ctx := retainedTestRoot(t)
	var owners [2]*retainedFDOwner
	var paths [2]string
	for i := range owners {
		dir := t.TempDir()
		paths[i] = filepath.Join(dir, retainedReadName)
		retainedTestFile(t, paths[i], bytes.Repeat([]byte{byte('A' + i)}, 32))
		owners[i] = newRetainedFDOwner(func() (*os.File, error) { return os.Open(dir) }, func() { t.Error("unexpected abort") }, make(chan struct{}))
		t.Cleanup(func() { owners[i].execute(ctx, "close") })
		if _, err := owners[i].execute(ctx, "read-open"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(paths[i], paths[i]+"-retained"); err != nil {
			t.Fatal(err)
		}
		retainedTestFile(t, paths[i], bytes.Repeat([]byte{'X'}, 32))
	}
	var identities [2]retainedFDIdentity
	for i, owner := range owners {
		out, err := owner.execute(ctx, "read")
		sum := sha256.Sum256(bytes.Repeat([]byte{byte('A' + i)}, 32))
		if err != nil || !out.completed || out.readBytes != 32 || out.readErr != nil || out.readSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("not retained description", out, err)
		}
		identities[i] = out.identity
		if _, err := owner.execute(ctx, "close"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-owner.done:
		default:
			t.Fatal("close unjoined")
		}
		for _, suffix := range []string{"", "-retained"} {
			data, err := os.ReadFile(paths[i] + suffix)
			want := byte('X')
			if suffix != "" {
				want = byte('A' + i)
			}
			if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{want}, 32)) {
				t.Fatal("read mutated backing", data, err)
			}
		}
	}
	if identities[0] == identities[1] {
		t.Fatal("same object")
	}
}
func TestOriginalRootReadFDModeAndShape(t *testing.T) {
	for _, name := range []string{"valid", "read-only-mode", "short", "large", "symlink", "hardlink", "directory", "fifo", "canceled"} {
		t.Run(name, func(t *testing.T) {
			dir, root, ctx := retainedTestRoot(t)
			path := filepath.Join(dir, retainedReadName)
			data := bytes.Repeat([]byte{'A'}, 32)
			switch name {
			case "short":
				data = data[:31]
			case "large":
				data = append(data, 'A')
			}
			switch name {
			case "symlink":
				target := filepath.Join(dir, "target")
				retainedTestFile(t, target, data)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			default:
				retainedTestFile(t, path, data)
			}
			if name == "read-only-mode" {
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				_, statErr := retainedFDStat(file, false)
				file.Close()
				if statErr == nil {
					t.Fatal("writable probe accepted read-only mode")
				}
			}
			if name == "hardlink" {
				if err := os.Link(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
			}
			if name == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			r, err := openRetainedReadFD(ctx, root)
			if name != "valid" && name != "read-only-mode" {
				if err == nil {
					r.close()
					t.Fatal("invalid object opened")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.close()
			flags, err := unix.FcntlInt(r.file.Fd(), unix.F_GETFL, 0)
			if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
				t.Fatal("not read-only", flags, err)
			}
			if _, err := r.file.WriteAt([]byte{1}, 0); err == nil {
				t.Fatal("reader writable")
			}
			out, err := r.positive(ctx)
			if err != nil || out.readErr != nil || out.readBytes != 32 || !out.completed {
				t.Fatal(out, err)
			}
			if _, err = r.positive(ctx); err == nil {
				t.Fatal("read twice")
			}
		})
	}
}
func TestOriginalRootReadPairFailedAcquisitionPreservesBothOwners(t *testing.T) {
	dir, _, ctx := retainedTestRoot(t)
	retainedTestFile(t, filepath.Join(dir, retainedReadName), bytes.Repeat([]byte{'A'}, 32))
	entered, unblock := make(chan struct{}), make(chan struct{})
	doneA, doneB := make(chan struct{}), make(chan struct{})
	var abortA, abortB atomic.Int32
	a := newRetainedFDOwner(func() (*os.File, error) { return os.Open(dir) }, func() { abortA.Add(1) }, doneA)
	b := newRetainedFDOwner(func() (*os.File, error) { close(entered); <-unblock; return os.Open(dir) }, func() { abortB.Add(1) }, doneB)
	if _, err := a.execute(ctx, "read-open"); err != nil {
		t.Fatal(err)
	}
	current, cancel := context.WithCancel(ctx)
	defer cancel()
	o := &originalConsumer{roots: &originalRootPair{owners: [2]*retainedFDOwner{a, b}}, cancel: cancel}
	o.operations.Lock()
	result := make(chan error, 1)
	go func() { _, err := b.execute(current, "read-open"); result <- err }()
	<-entered
	if err := o.stop(); !errors.Is(err, errRetainedFDBusy) || o.roots == nil || abortA.Load() != 1 || abortB.Load() != 1 {
		t.Fatal("lost unjoined ownership", err)
	}
	o.operations.Unlock()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(unblock)
	for _, owner := range []*retainedFDOwner{a, b} {
		select {
		case <-owner.done:
		case <-ctx.Done():
			t.Fatal("syscall not joined")
		}
	}
	short, stop := context.WithTimeout(ctx, time.Millisecond)
	defer stop()
	if err := b.joinFailure(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("mount join skipped", err)
	}
	close(doneA)
	close(doneB)
	for _, owner := range []*retainedFDOwner{a, b} {
		if err := owner.joinFailure(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("cause lost", err)
		}
	}
	if o.roots == nil {
		t.Fatal("failed stop claimed release")
	}
}
func TestOriginalRootReadPairCleanReleaseClosesBoth(t *testing.T) {
	_, _, ctx := retainedTestRoot(t)
	pair := &originalRootPair{}
	for i := range pair.owners {
		dir := t.TempDir()
		retainedTestFile(t, filepath.Join(dir, retainedReadName), bytes.Repeat([]byte{byte('A' + i)}, 32))
		pair.owners[i] = newRetainedFDOwner(func() (*os.File, error) { return os.Open(dir) }, func() { t.Error("abort clean reader") }, make(chan struct{}))
		if _, err := pair.owners[i].execute(ctx, "read-open"); err != nil {
			t.Fatal(err)
		}
	}
	o := &originalConsumer{roots: pair}
	if err := o.stop(); err != nil || o.roots != nil {
		t.Fatal("no release", err)
	}
	for _, owner := range pair.owners {
		select {
		case <-owner.done:
		default:
			t.Fatal("unjoined")
		}
	}
}
