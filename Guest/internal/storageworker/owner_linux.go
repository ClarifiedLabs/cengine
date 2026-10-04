//go:build linux

package storageworker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const startupTimeout = 5 * time.Second

var readyPacket = []byte("storageworker-ready-v1")

// Owner must not be copied. Close releases the pidfd only after actual reaping.
// The caller must retain any nonnil Owner returned by StartLifecycle, even with an error.
type Owner struct {
	commandMu     sync.Mutex // pins the zombie until an in-flight ACK is authenticated
	awaitingReply bool       // commandMu; only receive-only continuation may clear it
	channel       *Channel
	pid           int
	mu            sync.Mutex
	pidfd         int
	result        WaitResult
	observed      bool
	done          chan struct{}
}

// StartLifecycle is for the trusted root PID1 storageboot caller only. It borrows
// an already-verified directory descriptor and passes a duplicate as FD4, not a
// pathname. It starts only /proc/self/exe --managed-lifecycle-worker, with empty
// environment, /dev/null stdio, FD3 as a private Unix seqpacket socket, and
// Pdeathsig SIGKILL. Other caller descriptors must remain CLOEXEC; callers must
// not concurrently introduce non-CLOEXEC descriptors. Success authenticates
// transport readiness, not application-start authority. On a post-spawn error a
// nonnil Owner is killed via its pidfd but still requires Done/Result/Close
// cleanup. StartLifecycle never waits for reaping.
func StartLifecycle(root *os.File) (*Owner, error) {
	return start(root, []string{"--managed-lifecycle-worker"}, 1)
}

// start's arguments/parent seam is private, used only by same-package tests.
func start(root *os.File, args []string, parent int) (*Owner, error) {
	return startWithGate(root, args, parent, nil)
}

func startWithGate(root *os.File, args []string, parent int, reapGate <-chan struct{}) (*Owner, error) {
	if os.Getpid() != parent || os.Getuid() != 0 || os.Getgid() != 0 || os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("storageworker: trusted root parent required")
	}
	rootCopy, err := duplicateRoot(root)
	if err != nil {
		return nil, err
	}
	defer rootCopy.Close()
	if err := checkInheritedFDs(); err != nil {
		return nil, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parentFile := os.NewFile(uintptr(fds[0]), "storageworker-parent")
	childFile := os.NewFile(uintptr(fds[1]), "storageworker-child")
	defer childFile.Close()
	for _, fd := range fds {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			_ = parentFile.Close()
			return nil, err
		}
	}
	// Register the parent end before launch; an immediate child exit cannot
	// leave ownership stranded between spawn and channel setup.
	ch, err := newChannel(parentFile, 0)
	if err != nil {
		return nil, err
	}
	o := &Owner{channel: ch, pidfd: -1, done: make(chan struct{})}
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{childFile, rootCopy}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &o.pidfd}
	// nil stdio is /dev/null in os/exec. No pipes or copier goroutines.
	born := make(chan error, 1)
	waitGate := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			born <- err
			return
		}
		o.pid = cmd.Process.Pid
		born <- nil
		<-waitGate // no reap while the initial credential binding is in flight
		if reapGate != nil {
			<-reapGate
		} // private deterministic test seam
		var waitErr error
		if o.pidfd >= 0 {
			var info unix.Siginfo
			for {
				waitErr = unix.Waitid(unix.P_PIDFD, o.pidfd, &info, unix.WEXITED|unix.WNOWAIT, nil)
				if waitErr != unix.EINTR {
					break
				}
			}
		}
		o.commandMu.Lock()
		// Also fail the channel closed on an observation-system failure.
		_ = ch.Close()
		if waitErr == nil {
			// Do not permit a packet to authenticate a recycled numeric PID.
			// WNOWAIT pins the zombie until all credential checks have joined.
			waitErr = cmd.Wait() // the only reaping operation
		}
		o.commandMu.Unlock()
		r := classifyWait(cmd.ProcessState, waitErr)
		o.mu.Lock()
		o.result = r
		o.observed = true
		o.mu.Unlock()
		close(o.done)
		if !r.Reaped {
			// A wait-system failure is not permission to drop the ownership
			// thread (PDEATHSIG) or close/reuse the birth pidfd.
			select {}
		}
	}()
	if err := <-born; err != nil {
		_ = ch.Close()
		return nil, err
	}
	_ = childFile.Close() // otherwise early child death would not deliver EOF
	// Birth pin and locked wait gate exist before exposing the owner or using
	// the numeric PID to validate SCM_CREDENTIALS.
	ch.peer = int32(o.pid)
	startupErr := error(nil)
	if o.pidfd < 0 {
		startupErr = errors.New("storageworker: kernel birth pidfd unavailable")
	}
	if startupErr == nil {
		startupErr = ch.SetDeadline(time.Now().Add(startupTimeout))
		if startupErr == nil {
			var payload []byte
			payload, startupErr = ch.Receive()
			if startupErr == nil && !bytes.Equal(payload, readyPacket) {
				startupErr = ErrProtocol
			}
		}
	}
	if startupErr == nil {
		startupErr = ch.SetDeadline(time.Time{})
	}
	if startupErr != nil {
		_ = o.Kill()
		_ = ch.Close()
	}
	close(waitGate)
	return o, startupErr
}

func classifyWait(state *os.ProcessState, err error) WaitResult {
	var exitErr *exec.ExitError
	return WaitResult{Reaped: state != nil && (err == nil || errors.As(err, &exitErr)), State: state, Err: err}
}

func (o *Owner) PID() int                      { return o.pid }
func (o *Owner) Send(p []byte) error           { return o.channel.Send(p) }
func (o *Owner) Receive() ([]byte, error)      { return o.channel.Receive() }
func (o *Owner) SetDeadline(t time.Time) error { return o.channel.SetDeadline(t) }

// Done closes after a wait observation. Result.Reaped MUST still be checked.
func (o *Owner) Done() <-chan struct{} { return o.done }
func (o *Owner) Result() (WaitResult, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.result, o.observed
}

// Kill never resolves a numeric PID and never constitutes a wait observation.
func (o *Owner) Kill() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.result.Reaped {
		return os.ErrProcessDone
	}
	if o.pidfd < 0 {
		return ErrUnreaped
	}
	return unix.PidfdSendSignal(o.pidfd, unix.SIGKILL, nil, 0)
}

// Close interrupts IPC but does not kill or block waiting for process exit.
// ErrUnreaped requires retaining the owner; retry after Done and a reaped result.
func (o *Owner) Close() error {
	err := o.channel.Close()
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.result.Reaped {
		return ErrUnreaped
	}
	if o.pidfd >= 0 {
		closeErr := unix.Close(o.pidfd)
		o.pidfd = -1
		if err == nil {
			err = closeErr
		}
	}
	return err
}

func duplicateRoot(root *os.File) (*os.File, error) {
	if root == nil {
		return nil, errors.New("storageworker: missing root descriptor")
	}
	raw, err := root.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var callErr error
	if err := raw.Control(func(n uintptr) { fd, callErr = unix.FcntlInt(n, unix.F_DUPFD_CLOEXEC, 5) }); err != nil {
		return nil, err
	}
	if callErr != nil {
		return nil, callErr
	}
	f := os.NewFile(uintptr(fd), "storageworker-root")
	st, err := f.Stat()
	if err != nil || !st.IsDir() {
		_ = f.Close()
		return nil, errors.New("storageworker: root is not a directory")
	}
	return f, nil
}

func checkInheritedFDs() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < 3 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err == unix.EBADF {
			continue
		} // ReadDir's own descriptor
		if err != nil {
			return err
		}
		if flags&unix.FD_CLOEXEC == 0 {
			return fmt.Errorf("storageworker: ambient inheritable fd %d", fd)
		}
	}
	return nil
}
