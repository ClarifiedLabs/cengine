//go:build linux

package storageworker

import (
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func waitReadable(t *testing.T, fd int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 && fds[0].Revents&unix.POLLIN != 0 {
			return
		}
	}
	t.Fatal("pidfd did not become readable")
}

func TestWaitGateRetainsZombieIdentity(t *testing.T) {
	requireRoot(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	gate := make(chan struct{})
	o, err := startWithGate(root, []string{"test-worker-echo", strconv.Itoa(os.Getpid())}, os.Getpid(), gate)
	if o != nil {
		defer func() { close(gate); _ = o.Kill(); awaitResult(t, o); _ = o.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Send([]byte("exit-zero")); err != nil {
		t.Fatal(err)
	}
	waitReadable(t, o.pidfd) // exit indication is NOT actual reaping
	if _, observed := o.Result(); observed {
		t.Fatal("gate bypassed actual wait")
	}
	select {
	case <-o.Done():
		t.Fatal("exit readiness closed Done before wait")
	default:
	}
	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PIDFD, o.pidfd, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil); err != nil {
		t.Fatalf("unreaped child's identity no longer owned: %v", err)
	}
}

func TestCloseInterruptsBlockedReceive(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		_ = unix.Close(fds[0])
		t.Fatal(err)
	}
	c, err := newChannel(os.NewFile(uintptr(fds[0]), "blocked-test"), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	wouldBlock := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { _, err := c.receive(wouldBlock); done <- err }()
	select {
	case <-wouldBlock: // actual recvmsg has returned EAGAIN, not merely started
	case <-time.After(2 * time.Second):
		go c.Close()
		t.Fatal("receive never reached read-wait path")
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("receive succeeded after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not interrupt receive")
	}
}

func TestChildDiesWithCreatingParent(t *testing.T) {
	requireRoot(t)
	// Own the orphan explicitly: this test is serial, and resets subreaper state.
	withSubreaper(t)
	o, err := startWorker(t, "test-worker-parent")
	if err != nil {
		t.Fatal(err)
	}
	_ = o.SetDeadline(time.Now().Add(5 * time.Second))
	packet, err := o.Receive()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(packet))
	if err != nil || pid <= 1 {
		t.Fatalf("child pid %q", packet)
	}
	pin, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pin)
	defer func() {
		_ = o.Kill()
		awaitResult(t, o)
		_ = unix.PidfdSendSignal(pin, unix.SIGKILL, nil, 0)
		waitReadable(t, pin)
		var status unix.WaitStatus
		deadline := time.Now().Add(5 * time.Second)
		for {
			got, err := unix.Wait4(pid, &status, unix.WNOHANG, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				t.Errorf("orphan reap: %v", err)
				return
			}
			if got == pid {
				if !status.Signaled() || status.Signal() != unix.SIGKILL {
					t.Errorf("orphan status: %v", status)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Error("orphan unreaped")
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	if err := o.Kill(); err != nil {
		t.Fatal(err)
	}
	awaitResult(t, o)
	// This must become readable BEFORE cleanup sends the grandchild a signal.
	waitReadable(t, pin)
}
