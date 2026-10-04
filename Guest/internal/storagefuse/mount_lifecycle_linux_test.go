//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"testing"
	"time"
)

func TestNativeReadOnlyMountFlags(t *testing.T) {
	for _, ro := range []bool{false, true} {
		flags := nativeMountFlags(ro)
		if flags&(unix.MS_NOSUID|unix.MS_NODEV) != unix.MS_NOSUID|unix.MS_NODEV || (flags&unix.MS_RDONLY != 0) != ro {
			t.Fatal(flags)
		}
	}
}
func TestCleanupReleasesExactRawDescriptorOnce(t *testing.T) {
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	releases := 0
	m := &Mounted{fs: &rawFS{fd: fd}, pinned: &pinnedMountPath{}, releasePath: func() { releases++ }}
	m.life.clean.Store(true)
	m.cleanup()
	m.cleanup()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != unix.EBADF || releases != 1 || m.fs.fd != -1 {
		t.Fatalf("fd=%d release=%d err=%v", m.fs.fd, releases, err)
	}
}

func TestCancellationCannotAbortCommittedNativeCompletion(t *testing.T) {
	raw, client := fixture()
	m := &Mounted{fs: raw, done: make(chan struct{})}
	m.life.clean.Store(true)
	m.cancelGraceful(context.Canceled)
	if client.aborted != 0 || raw.stopped.Load() {
		t.Fatal("cancellation poisoned committed completion")
	}
}

func TestSecondaryNativeCloseWaiterDoesNotAbortOwner(t *testing.T) {
	raw, client := fixture()
	m := &Mounted{fs: raw, done: make(chan struct{}), timeout: time.Second}
	m.gracefulCall.Do(func() {}) // another caller already owns shutdown
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.CloseGracefully(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if client.aborted != 0 || raw.stopped.Load() || m.Err() != nil {
		t.Fatal("waiter changed owning attempt")
	}
	close(m.done) // the owner subsequently completed normally
	if err := m.CloseGracefully(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFailedAbortJoinReturnsDeadlineWithoutDone(t *testing.T) {
	raw, _ := fixture()
	m := &Mounted{fs: raw, done: make(chan struct{}), timeout: 10 * time.Millisecond}
	// Model an already-started shutdown whose exact kernel abort cannot finish.
	m.gracefulCall.Do(func() {})
	if err := m.CloseGracefully(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-m.Done():
		t.Fatal("claimed joined resources")
	default:
	}
	if err := m.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-m.Done():
		t.Fatal("abort claimed join")
	default:
	}
}
