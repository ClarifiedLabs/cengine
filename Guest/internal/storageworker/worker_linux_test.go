//go:build linux

package storageworker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Helpers exist only in the test binary. Production has no argument or parent
// override. No VM, Docker, namespace creation or privileged helper is needed;
// actual Linux root and kernel pidfd support are requirements, never skips.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "test-worker-") {
		os.Exit(workerHelper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func workerHelper(args []string) int {
	if len(args) != 2 {
		return 80
	}
	parent, err := strconv.Atoi(args[1])
	if err != nil {
		return 81
	}
	if args[0] == "test-worker-before-ready" {
		return 19
	}
	if args[0] == "test-worker-reject-production" {
		c, err := Accept()
		if err == nil {
			_ = c.Close()
			return 82
		}
		return 0
	}
	if args[0] == "test-worker-reject-fds" {
		c, err := accept(parent)
		if err == nil {
			_ = c.Close()
			return 83
		}
		return 0
	}
	c, err := accept(parent)
	if err != nil {
		return 84
	}
	defer c.Close()
	if args[0] == "test-worker-parent" {
		o, err := start(c.Root, []string{"test-worker-echo", strconv.Itoa(os.Getpid())}, os.Getpid())
		if err != nil {
			return 91
		}
		if err := c.Send([]byte(strconv.Itoa(o.PID()))); err != nil {
			return 92
		}
		<-o.Done()
		return 93
	}
	for {
		packet, err := c.Receive()
		if err != nil {
			return 85
		}
		switch string(packet) {
		case "exit-zero":
			return 0
		case "exit-seven":
			return 7
		case "close-only":
			_ = c.Channel.Close()
			time.Sleep(30 * time.Second)
			return 86
		case "inspect":
			flags, err := unix.FcntlInt(c.Root.Fd(), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 || len(os.Environ()) != 0 {
				return 87
			}
			for fd := 0; fd < 3; fd++ {
				target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
				if err != nil || target != "/dev/null" {
					return 88
				}
			}
			if err := c.Send([]byte("inspected")); err != nil {
				return 89
			}
		default:
			if err := c.Send(packet); err != nil {
				return 90
			}
		}
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 || os.Getgid() != 0 {
		t.Fatal("actual Linux root uid/gid required; test is not skipped")
	}
}

func startWorker(t *testing.T, mode string) (*Owner, error) {
	t.Helper()
	requireRoot(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	o, err := start(root, []string{mode, strconv.Itoa(os.Getpid())}, os.Getpid())
	if o != nil {
		t.Cleanup(func() {
			_ = o.Kill()
			select {
			case <-o.Done():
			case <-time.After(5 * time.Second):
				t.Error("owned child was not reaped before cleanup deadline")
				return
			}
			r, ok := o.Result()
			if !ok || !r.Reaped {
				t.Errorf("cleanup not reaped: %+v", r)
				return
			}
			if err := o.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return o, err
}

func awaitResult(t *testing.T, o *Owner) WaitResult {
	t.Helper()
	select {
	case <-o.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not complete")
	}
	r, ok := o.Result()
	if !ok || !r.Reaped || r.State == nil {
		t.Fatalf("not actually reaped: %+v, %v", r, ok)
	}
	return r
}

func TestOwnedExitAndSignal(t *testing.T) {
	for _, mode := range []string{"exit-zero", "exit-seven", "signal"} {
		t.Run(mode, func(t *testing.T) {
			o, err := startWorker(t, "test-worker-echo")
			if err != nil {
				t.Fatal(err)
			}
			if o.PID() <= 1 {
				t.Fatalf("bad pid: %d", o.PID())
			}
			if _, ready := o.Result(); ready {
				t.Fatal("transport-ready invented a wait observation")
			}
			if err := o.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := o.Send([]byte("inspect")); err != nil {
				t.Fatal(err)
			}
			p, err := o.Receive()
			if err != nil || string(p) != "inspected" {
				t.Fatalf("inspect %q: %v", p, err)
			}
			if mode == "signal" {
				err = o.Kill()
			} else {
				err = o.Send([]byte(mode))
			}
			if err != nil {
				t.Fatal(err)
			}
			r := awaitResult(t, o)
			if mode == "signal" {
				status := r.State.Sys().(syscall.WaitStatus)
				if !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatalf("wrong status: %v", status)
				}
			} else {
				want := 0
				if mode == "exit-seven" {
					want = 7
				}
				if r.State.ExitCode() != want {
					t.Fatalf("exit=%d want=%d", r.State.ExitCode(), want)
				}
			}
			if err := o.Kill(); !errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("post-reap kill: %v", err)
			}
			if _, err := o.Receive(); err == nil {
				t.Fatal("channel usable after reaping")
			}
		})
	}
}

func TestCloseDeadlineAndEOFNeverReap(t *testing.T) {
	for _, action := range []string{"deadline", "close", "eof"} {
		t.Run(action, func(t *testing.T) {
			o, err := startWorker(t, "test-worker-echo")
			if err != nil {
				t.Fatal(err)
			}
			pin := o.pidfd
			switch action {
			case "deadline":
				_ = o.SetDeadline(time.Now().Add(20 * time.Millisecond))
				if _, err := o.Receive(); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("deadline=%v", err)
				}
			case "close":
				// Child exits on EOF; hold it in its close-only sleep first.
				if err := o.Send([]byte("close-only")); err != nil {
					t.Fatal(err)
				}
				if _, err := o.Receive(); err == nil {
					t.Fatal("expected EOF")
				}
				if err := o.Close(); !errors.Is(err, ErrUnreaped) {
					t.Fatalf("Close=%v", err)
				}
			case "eof":
				if err := o.Send([]byte("close-only")); err != nil {
					t.Fatal(err)
				}
				_ = o.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := o.Receive(); err == nil {
					t.Fatal("expected EOF")
				}
			}
			if _, observed := o.Result(); observed {
				t.Fatal("IPC failure invented a wait result")
			}
			if _, err := unix.FcntlInt(uintptr(pin), unix.F_GETFD, 0); err != nil {
				t.Fatalf("unreaped pidfd closed: %v", err)
			}
			if err := o.Kill(); err != nil {
				t.Fatal(err)
			}
			awaitResult(t, o)
		})
	}
}

func TestChildDiesBeforeReady(t *testing.T) {
	before := time.Now()
	o, err := startWorker(t, "test-worker-before-ready")
	if err == nil || o == nil {
		t.Fatalf("owner=%v err=%v", o, err)
	}
	if time.Since(before) >= startupTimeout {
		t.Fatal("parent retained child socket and hid EOF")
	}
	r := awaitResult(t, o)
	if r.State.ExitCode() != 19 {
		t.Fatalf("exit=%d", r.State.ExitCode())
	}
}

func TestProductionRequiresPID1(t *testing.T) {
	if os.Getpid() == 1 {
		t.Fatal("test runner must not be PID1")
	}
	if o, err := StartLifecycle(nil); err == nil || o != nil {
		t.Fatalf("StartLifecycle accepted non-PID1: %v %v", o, err)
	}
	o, err := startWorker(t, "test-worker-reject-production")
	if err == nil || o == nil {
		t.Fatalf("Accept accepted non-PID1 parent: %v", err)
	}
	r := awaitResult(t, o)
	status := r.State.Sys().(syscall.WaitStatus)
	// Accept closes FD3 on rejection. Startup may observe that EOF and send
	// its fail-closed SIGKILL before the rejecting helper reaches os.Exit(0).
	if r.State.ExitCode() != 0 && !(status.Signaled() && status.Signal() == syscall.SIGKILL) {
		t.Fatalf("helper exit: %v", r)
	}
}

func TestNoAmbientInheritance(t *testing.T) {
	requireRoot(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fd, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if o, err := start(root, nil, os.Getpid()); err == nil || o != nil {
		t.Fatalf("inheritable fd accepted: %v %v", o, err)
	}
}

func channelPair(t *testing.T, typ int, pass bool, peer int) (*Channel, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	if pass {
		for _, fd := range fds {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
				t.Fatal(err)
			}
		}
	}
	ch, err := newChannel(os.NewFile(uintptr(fds[0]), "test-channel"), peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	_ = ch.SetDeadline(time.Now().Add(2 * time.Second))
	return ch, fds[1]
}

func TestMessageBoundsAndIdentity(t *testing.T) {
	requireRoot(t)
	for _, size := range []int{1, MaxPayload, MaxPayload + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			c, fd := channelPair(t, unix.SOCK_SEQPACKET, true, os.Getpid())
			p := bytes.Repeat([]byte{'a'}, size)
			if err := unix.Sendmsg(fd, p, nil, nil, 0); err != nil {
				t.Fatal(err)
			}
			got, err := c.Receive()
			if size > MaxPayload {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("oversize: %v", err)
				}
				return
			}
			if err != nil || !bytes.Equal(got, p) {
				t.Fatalf("packet size=%d err=%v", len(got), err)
			}
			if err := c.Send(nil); !errors.Is(err, ErrProtocol) {
				t.Fatal("empty send accepted")
			}
			if err := c.Send(make([]byte, MaxPayload+1)); !errors.Is(err, ErrProtocol) {
				t.Fatal("oversize send accepted")
			}
		})
	}
	c, fd := channelPair(t, unix.SOCK_SEQPACKET, true, os.Getpid()+1)
	if err := unix.Sendmsg(fd, []byte("wrong sender"), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receive(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("wrong PID accepted: %v", err)
	}
}

func TestCredentialControlValidation(t *testing.T) {
	good := unix.UnixCredentials(&unix.Ucred{Pid: 17})
	for name, oob := range map[string][]byte{
		"missing":   nil,
		"duplicate": append(append([]byte{}, good...), good...),
		"wrong-pid": unix.UnixCredentials(&unix.Ucred{Pid: 18}),
		"wrong-uid": unix.UnixCredentials(&unix.Ucred{Pid: 17, Uid: 1}),
		"wrong-gid": unix.UnixCredentials(&unix.Ucred{Pid: 17, Gid: 1}),
		"malformed": {1, 2, 3},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateControl(oob, 17); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if err := validateControl(good, 17); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	oob := append(unix.UnixCredentials(&unix.Ucred{Pid: 999}), unix.UnixRights(fd)...)
	if err := validateControl(oob, 17); !errors.Is(err, ErrProtocol) {
		t.Fatal("rights accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
		_ = unix.Close(fd)
		t.Fatalf("rights leaked after wrong credential: %v", err)
	}
}

func TestActualRightsRejectedWithoutLeaks(t *testing.T) {
	requireRoot(t)
	c, fd := channelPair(t, unix.SOCK_SEQPACKET, true, os.Getpid())
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := unix.Sendmsg(fd, []byte("rights"), unix.UnixRights(int(f.Fd())), nil, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Receive(); !errors.Is(err, ErrProtocol) {
			t.Fatalf("rights accepted: %v", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("descriptor leak before=%d after=%d", len(before), len(after))
	}
}

func TestChannelRejectsUnpreparedDescriptors(t *testing.T) {
	for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET} {
		fds, err := unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		c, err := newChannel(os.NewFile(uintptr(fds[0]), "bad-channel"), 1)
		_ = unix.Close(fds[1])
		if err == nil {
			_ = c.Close()
			t.Fatalf("type %d without preparation accepted", typ)
		}
	}
}

func TestWaitClassificationDoesNotInventReaping(t *testing.T) {
	for _, err := range []error{nil, syscall.ECHILD, os.ErrDeadlineExceeded, &exec.ExitError{}} {
		if classifyWait(nil, err).Reaped {
			t.Fatalf("nil ProcessState reaped: %v", err)
		}
	}
	if classifyWait(&os.ProcessState{}, syscall.ECHILD).Reaped {
		t.Fatal("wait-system error reaped")
	}
	if !classifyWait(&os.ProcessState{}, &exec.ExitError{}).Reaped {
		t.Fatal("exit status was not accepted")
	}
}

func TestAcceptRejectsSwappedAndMalformedFDs(t *testing.T) {
	requireRoot(t)
	for _, mode := range []string{"swapped", "regular-root", "stream", "no-passcred", "extra-fd"} {
		t.Run(mode, func(t *testing.T) {
			root, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if mode == "regular-root" {
				_ = root.Close()
				root, err = os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
			}
			typ := unix.SOCK_SEQPACKET
			if mode == "stream" {
				typ = unix.SOCK_STREAM
			}
			fds, err := unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			parent := os.NewFile(uintptr(fds[0]), "parent")
			defer parent.Close()
			child := os.NewFile(uintptr(fds[1]), "child")
			defer child.Close()
			if mode != "no-passcred" {
				_ = unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
			}
			files := []*os.File{child, root}
			if mode == "extra-fd" {
				files = append(files, root)
			}
			if mode == "swapped" {
				files = []*os.File{root, child}
			}
			cmd := exec.Command("/proc/self/exe", "test-worker-reject-fds", strconv.Itoa(os.Getpid()))
			cmd.ExtraFiles = files
			cmd.Env = []string{}
			// These reject-before-ready helpers are bounded by an explicit
			// timer; no general child-reaper is installed.
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Fatal("reject helper hung")
			}
		})
	}
}
