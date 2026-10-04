//go:build linux || darwin

package workloadstorage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestRetainedCloseDistinguishesDisconnectedFlushFromFailedRelease(t *testing.T) {
	for _, cause := range []error{nil, syscall.ENOTCONN, syscall.EIO, syscall.EBADF, syscall.EINTR, context.Canceled, context.DeadlineExceeded, errRetainedFDBusy, errors.Join(syscall.ENOTCONN, syscall.EBADF)} {
		for _, joined := range []bool{false, true} {
			for _, linux := range []bool{false, true} {
				err := cause
				if cause != nil {
					err = &os.PathError{Op: "close", Path: "private", Err: cause}
				}
				want := err
				if joined && linux && cause == syscall.ENOTCONN {
					want = nil
				}
				if got := retainedCloseResult(err, joined, linux); got != want {
					t.Fatal("unexpected close disposition", got, want)
				}
			}
		}
	}
}

func TestRetainedFDOwnerOriginalWritableDescription(t *testing.T) {
	dir, _, ctx := retainedTestRoot(t)
	path := filepath.Join(dir, retainedFDName)
	retainedTestFile(t, path, []byte("original"))
	o := newRetainedFDOwner(func() (*os.File, error) { return os.Open(dir) }, func() { t.Error("unexpected abort") }, make(chan struct{}))
	for _, op := range []string{"open", "positive"} {
		if _, err := o.execute(ctx, op); err != nil {
			t.Fatal(op, err)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil || string(before) != "\xa5riginal" {
		t.Fatal("positive missing", before, err)
	}
	old := filepath.Join(dir, "old")
	if err = os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	retainedTestFile(t, path, []byte("replacement"))
	out, err := o.execute(ctx, "attempt")
	if err != nil || !out.completed || out.written != 1 || out.writeErr != nil || out.syncErr != nil {
		t.Fatal("actual attempt", out, err)
	}
	if _, err = o.execute(ctx, "close"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-o.done:
	default:
		t.Fatal("close not joined")
	}
	data, err := os.ReadFile(old)
	if err != nil || string(data) != "\x5ariginal" {
		t.Fatal("reopened pathname", data, err)
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("changed replacement", data, err)
	}
	if _, err = o.execute(ctx, "attempt"); err == nil {
		t.Fatal("released owner reused")
	}
}

// Closing a FUSE directory queues RELEASEDIR; keep the acquisition root alive
// until the file observation is over rather than racing it into the wire trace.
func TestRetainedFDOwnerKeepsRootUntilJoinedClose(t *testing.T) {
	for _, operation := range []string{"open", "read-open"} {
		t.Run(operation, func(t *testing.T) {
			dir, _, ctx := retainedTestRoot(t)
			retainedTestFile(t, filepath.Join(dir, retainedFDName), []byte("original"))
			retainedTestFile(t, filepath.Join(dir, retainedReadName), make([]byte, 32))
			root, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			o := newRetainedFDOwner(func() (*os.File, error) { return root, nil }, func() { t.Error("unexpected abort") }, make(chan struct{}))
			if _, err := o.execute(ctx, operation); err != nil {
				t.Fatal(err)
			}
			if _, err := root.Stat(); err != nil {
				t.Fatal("acquisition released root before observation", err)
			}
			if _, err := o.execute(ctx, "close"); err != nil {
				t.Fatal(err)
			}
			if _, err := root.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("joined close retained root", err)
			}
		})
	}
}

func TestRetainedFDOwnerCanceledAcquisitionKeepsBothJoins(t *testing.T) {
	dir, _, ctx := retainedTestRoot(t)
	retainedTestFile(t, filepath.Join(dir, retainedFDName), []byte("original"))
	entered, unblock, mountDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var aborted atomic.Int32
	o := newRetainedFDOwner(func() (*os.File, error) { close(entered); <-unblock; return os.Open(dir) }, func() { aborted.Add(1) }, mountDone)
	canceled, cancel := context.WithCancel(ctx)
	reply := make(chan error, 1)
	go func() {
		out, err := o.execute(canceled, "open")
		if out.completed {
			t.Error("timeout is evidence")
		}
		reply <- err
	}()
	<-entered
	if _, err := o.execute(ctx, "positive"); err == nil {
		t.Fatal("concurrent operation queued")
	}
	cancel()
	if err := <-reply; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if aborted.Load() != 1 {
		t.Fatal("missing exact abort")
	}
	select {
	case <-o.done:
		t.Fatal("claimed blocked syscall join")
	default:
	}
	short, stop := context.WithTimeout(ctx, time.Millisecond)
	defer stop()
	if err := o.joinFailure(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unjoined accepted", err)
	}
	close(unblock)
	select {
	case <-o.done:
	case <-ctx.Done():
		t.Fatal("worker not joined")
	}
	short2, stop2 := context.WithTimeout(ctx, time.Millisecond)
	defer stop2()
	if err := o.joinFailure(short2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("mount join skipped", err)
	}
	close(mountDone)
	if err := o.joinFailure(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("lost failed open", err)
	}
	if _, err := o.execute(ctx, "open"); err == nil {
		t.Fatal("failed owner reused")
	}
	data, err := os.ReadFile(filepath.Join(dir, retainedFDName))
	if err != nil || string(data) != "original" {
		t.Fatal("canceled acquisition wrote", data, err)
	}
}

// Even a successful write that races cancellation must remain a failed
// observation after both cleanup joins, never a successful denial or release.
func TestRetainedFDOwnerLateFailurePreservesCause(t *testing.T) {
	dir, _, ctx := retainedTestRoot(t)
	retainedTestFile(t, filepath.Join(dir, retainedFDName), []byte("original"))
	mountDone := make(chan struct{})
	close(mountDone)
	o := newRetainedFDOwner(func() (*os.File, error) { return os.Open(dir) }, func() {}, mountDone)
	for _, op := range []string{"open", "positive"} {
		if _, err := o.execute(ctx, op); err != nil {
			t.Fatal(err)
		}
	}
	o.fail(context.Canceled)
	if err := o.joinFailure(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("lost late cancellation", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, retainedFDName))
	if err != nil || string(data) != "\xa5riginal" {
		t.Fatal("successful operation was hidden", data, err)
	}
}

func TestRetainedFDOwnerRejectsUnboundedAndIdleAbortJoins(t *testing.T) {
	_, _, ctx := retainedTestRoot(t)
	var opens, aborts atomic.Int32
	mountDone := make(chan struct{})
	close(mountDone)
	o := newRetainedFDOwner(func() (*os.File, error) { opens.Add(1); return nil, ErrInvalidFrame }, func() { aborts.Add(1) }, mountDone)
	if _, err := o.execute(context.Background(), "open"); err == nil {
		t.Fatal("unbounded accepted")
	}
	if _, err := o.execute(ctx, "unknown"); err == nil {
		t.Fatal("unknown operation")
	}
	o.fail(ErrInvalidFrame)
	o.fail(ErrInvalidFrame)
	if err := o.joinFailure(ctx); !errors.Is(err, ErrInvalidFrame) {
		t.Fatal(err)
	}
	if opens.Load() != 0 || aborts.Load() != 1 {
		t.Fatal("invalid work or duplicate abort")
	}
	if newRetainedFDOwner(nil, func() {}, mountDone) != nil {
		t.Fatal("missing opener")
	}
}
