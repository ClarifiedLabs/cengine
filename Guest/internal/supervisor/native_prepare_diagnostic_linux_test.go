//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type prepareDiagnosticFD struct {
	fd      int
	expired func() bool
}

func (p *prepareDiagnosticFD) live() bool { return !p.expired() }

func (p *prepareDiagnosticFD) close() { _ = unix.Close(p.fd) }
func (p *prepareDiagnosticFD) read(name string, maximum int64) ([]byte, error) {
	if !p.live() {
		return nil, errors.New("prepare observation expired")
	}
	fd, err := unix.Openat(p.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	raw := make([]byte, maximum+1)
	used := 0
	for used < len(raw) {
		if !p.live() {
			return nil, errors.New("prepare observation expired")
		}
		n, err := unix.Read(fd, raw[used:])
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		used += n
	}
	if int64(used) > maximum {
		return nil, errors.New("prepare proc read bound")
	}
	return raw[:used], nil
}
func (p *prepareDiagnosticFD) tasks() ([]string, error) {
	if !p.live() {
		return nil, errors.New("prepare observation expired")
	}
	fd, err := unix.Openat(p.fd, "task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "prepare-owned-tasks")
	defer dir.Close()
	if !p.live() {
		return nil, errors.New("prepare observation expired")
	}
	return dir.Readdirnames(33)
}
func (p *prepareDiagnosticFD) task(name string) (prepareDiagnosticProc, error) {
	if !p.live() {
		return nil, errors.New("prepare observation expired")
	}
	fd, err := unix.Openat(p.fd, "task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if !p.live() {
		return nil, errors.New("prepare observation expired")
	}
	task, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &prepareDiagnosticFD{task, p.expired}, nil
}

type prepareDiagnosticPin struct {
	proc  *prepareDiagnosticFD
	birth prepareDiagnosticBirth
}

type prepareDiagnosticOwner struct{ pid, pidfd int }

// The sole Start/Wait owner duplicates only its clone-returned pidfd. No proc
// open/read is on startup's publication or cleanup path. This duplicate remains
// owned by the observer even after the fixture closes its signaling pidfd.
func ownPrepareDiagnostic(pid, pidfd int) *prepareDiagnosticOwner {
	if pid <= 0 || pidfd < 0 {
		return nil
	}
	fd, err := unix.FcntlInt(uintptr(pidfd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	return &prepareDiagnosticOwner{pid, fd}
}

func (o *prepareDiagnosticOwner) pin(expired func() bool) *prepareDiagnosticPin {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if expired() {
		return nil
	}
	root, err := unix.Open("/proc", flags, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(root)
	var fs unix.Statfs_t
	if expired() || unix.Fstatfs(root, &fs) != nil {
		return nil
	}
	var self [32]byte
	if expired() {
		return nil
	}
	n, err := unix.Readlinkat(root, "self", self[:])
	if err != nil || n == len(self) || !prepareDiagnosticNamespace(int64(fs.Type), self[:n], os.Getpid()) {
		return nil
	}
	if expired() {
		return nil
	}
	own, err := unix.Openat(root, strconv.Itoa(os.Getpid()), flags, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(own)
	if expired() {
		return nil
	}
	info, err := unix.Openat(own, "fdinfo", flags, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(info)
	infoProc := &prepareDiagnosticFD{info, expired}
	matchesPID := func() bool {
		raw, err := infoProc.read(strconv.Itoa(o.pidfd), 4096)
		return err == nil && prepareDiagnosticPID(raw, o.pid)
	}
	// A reaped pidfd reports Pid:-1. Check both sides of acquiring the proc pin:
	// Wait may race freely, but a recycled numeric PID cannot pass this binding.
	if !matchesPID() || expired() {
		return nil
	}
	fd, err := unix.Openat(root, strconv.Itoa(o.pid), flags, 0)
	if err != nil {
		return nil
	}
	proc := &prepareDiagnosticFD{fd, expired}
	raw, err := proc.read("stat", 4096)
	birth, parseErr := prepareDiagnosticParse(raw)
	if err != nil || parseErr != nil || birth.pid != o.pid || birth.parent != os.Getpid() || !matchesPID() {
		proc.close()
		return nil
	}
	return &prepareDiagnosticPin{proc, birth}
}

func observePrepareDiagnostic(t *testing.T, owner *prepareDiagnosticOwner) (report, stop func()) {
	t.Helper()
	if owner == nil {
		t.Log("D prepare-child-pin-unavailable")
		return func() {}, func() {}
	}
	t.Logf("D prepare-owned-child pid=%d pidfd=owned", owner.pid)
	timer := time.NewTimer(30 * time.Second) // observation only, not a new operation deadline
	cancel := make(chan struct{})
	done := prepareDiagnosticObserver(timer.C, cancel, func() []byte {
		until := time.Now().Add(time.Second)
		expired := func() bool { return time.Now().After(until) }
		pin := owner.pin(expired)
		if pin == nil {
			return []byte("D prepare-child-pin-unavailable\n")
		}
		defer pin.proc.close()
		return prepareDiagnosticSnapshot(pin.proc, pin.birth, expired)
	}, func() { _ = unix.Close(owner.pidfd) })
	reported := false
	report = func() {
		if reported {
			return
		}
		select {
		case data := <-done:
			reported = true
			t.Logf("%s", data)
		default:
			t.Log("D prepare-child-observation-not-ready")
		}
	}
	return report, func() { timer.Stop(); close(cancel) }
}

func prepareDiagnosticKillResult(t *testing.T, reason string, err error) {
	t.Helper()
	errno := unix.Errno(0)
	if err != nil && !errors.As(err, &errno) {
		t.Logf("D prepare-kill reason=%s result=non-errno", reason)
		return
	}
	t.Logf("D prepare-kill reason=%s errno=%d", reason, errno)
}
