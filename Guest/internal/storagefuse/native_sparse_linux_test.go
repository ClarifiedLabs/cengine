//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const sparseChildArgument = "--storagefuse-sparse-child-v1"

// A closed private exec entry, not another testing.Run/PASS stream. The child
// receives no path or authority material. Only an after-exec socket exchange can
// deliver the mount descriptor; an argv/environment flag alone cannot run work.
func init() {
	if len(os.Args) != 2 || os.Args[1] != sparseChildArgument {
		return
	}
	if err := sparseChild(); err != nil {
		fmt.Fprintf(os.Stderr, "D sparse-child-failed error=%s\n", nativeChildError(err))
		os.Exit(1)
	}
	os.Exit(0)
}

func TestNativeMountedManagedV3SparseMmapGraceful(t *testing.T) {
	nativeMountedManagedV3(t, "sparse-mmap")
}

func sparseChild() error {
	fmt.Fprintln(os.Stderr, "D sparse-child-enter")
	unix.Close(3) // pinned executable, never a mount or a storage/control credential
	file := os.NewFile(4, "private-sparse-socket")
	conn, err := sparseSocket(file)
	file.Close()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 || os.Getpagesize() != 4096 {
		return errors.New("sparse child profile")
	}
	if err = nativeChildStage(os.Stderr, "sparse-child-ready-send", func() error { return sparseSend(conn, "ready-v1", -1) }); err != nil {
		return err
	}
	root := -1
	if err = nativeChildStage(os.Stderr, "sparse-child-mount-receive", func() error {
		var err error
		root, err = sparseReceive(conn, "mount-v1", true)
		return err
	}); err != nil {
		return err
	}
	defer unix.Close(root)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err = unix.Fstat(root, &st); err != nil {
		return err
	}
	if err = unix.Fstatfs(root, &fs); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || fs.Type != unix.FUSE_SUPER_MAGIC {
		return errors.New("sparse child mount descriptor")
	}
	fmt.Fprintln(os.Stderr, "D sparse-child-mount-verified")
	nativePhase("sparse-open", 0, false)
	fd, err := unix.Openat(root, "sparse-prefix", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	nativePhase("sparse-open", 0, true)
	if err != nil {
		return err
	}
	defer func() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}()
	for i, op := range sparseOperations {
		model, _ := sparseModel(i + 1)
		nativePhase("sparse-truncate", i, false)
		err = unix.Ftruncate(fd, int64(len(model)))
		nativePhase("sparse-truncate", i, true)
		if err != nil {
			return err
		}
		pageOffset := op.offset & 4095
		nativePhase("sparse-mmap", i, false)
		mapped, err := unix.Mmap(fd, int64(op.offset-pageOffset), pageOffset+op.length, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		nativePhase("sparse-mmap", i, true)
		if err != nil {
			return err
		}
		nativePhase("sparse-copy", i, false)
		copy(mapped[pageOffset:], model[op.offset:op.offset+op.length])
		nativePhase("sparse-copy", i, true)
		// Preserve fsx's flags=0. No added FSYNC/MS_SYNC before the next operation.
		nativePhase("sparse-msync", i, false)
		err = unix.Msync(mapped, 0)
		nativePhase("sparse-msync", i, true)
		if err != nil {
			unix.Munmap(mapped)
			return err
		}
		nativePhase("sparse-munmap", i, false)
		err = unix.Munmap(mapped)
		nativePhase("sparse-munmap", i, true)
		if err != nil {
			return err
		}
		nativePhase("sparse-stat", i, false)
		err = unix.Fstat(fd, &st)
		nativePhase("sparse-stat", i, true)
		if err != nil {
			return err
		}
		nativePhase("sparse-seek", i, false)
		size, err := unix.Seek(fd, 0, unix.SEEK_END)
		nativePhase("sparse-seek", i, true)
		if err != nil {
			return err
		}
		if st.Size != int64(len(model)) || size != st.Size || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
			return errors.New("sparse child attributes")
		}
	}
	model, _ := sparseModel(2)
	actual := make([]byte, len(model)+1)
	nativePhase("sparse-read", 0, false)
	n, err := unix.Pread(fd, actual, 0)
	nativePhase("sparse-read", 0, true)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual[:n], model) {
		return errors.New("sparse mounted model")
	}
	nativePhase("sparse-close", 0, false)
	err = unix.Close(fd)
	fd = -1 // never retry close, even on error
	nativePhase("sparse-close", 0, true)
	if err != nil {
		return err
	}
	return nativeChildStage(os.Stderr, "sparse-child-complete-send", func() error { return sparseSend(conn, "complete-v1", -1) })
}

type sparseProcessPin struct {
	fd    int
	birth sparseBirth
}

func sparseProcRead(dir int, name string, maximum int64) ([]byte, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "owned-sparse-proc")
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if int64(len(raw)) > maximum {
		return nil, errors.New("sparse proc read bound")
	}
	return raw, err
}

func sparsePinProcess(pid int) (*sparseProcessPin, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/%d", pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	raw, err := sparseProcRead(fd, "stat", 4096)
	birth, parseErr := sparseParseBirth(raw)
	if err != nil || parseErr != nil || birth.pid != pid {
		unix.Close(fd)
		return nil, errors.New("sparse process birth")
	}
	return &sparseProcessPin{fd, birth}, nil
}

// Pinned before the sole Wait. Never resolve a numeric process/TID after reap;
// openat from proc directory pins cannot adopt a reused PID. Output stays private.
func (p *sparseProcessPin) diagnostic(role string) []byte {
	out := &sparseDiagnostic{}
	fmt.Fprintf(out, "D sparse-%s pid=%d birth=%d\n", role, p.birth.pid, p.birth.start)
	raw, err := sparseProcRead(p.fd, "stat", 4096)
	current, parseErr := sparseParseBirth(raw)
	if err != nil || parseErr != nil || current != p.birth {
		fmt.Fprintln(out, "D sparse-process-unavailable")
		return out.Bytes()
	}
	fd, err := unix.Openat(p.fd, "task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintln(out, "D sparse-tasks-unavailable")
		return out.Bytes()
	}
	dir := os.NewFile(uintptr(fd), "owned-sparse-tasks")
	defer dir.Close()
	names, _ := dir.Readdirnames(33)
	if len(names) > 32 {
		names = names[:32]
		fmt.Fprintln(out, "D sparse-task-bound")
	}
	for _, name := range names {
		tid, err := strconv.Atoi(name)
		if err != nil || tid <= 0 || strconv.Itoa(tid) != name {
			continue
		}
		fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		raw, err := sparseProcRead(fd, "stat", 4096)
		birth, parseErr := sparseParseBirth(raw)
		if err == nil && parseErr == nil && birth.pid == tid && birth.parent == p.birth.parent && birth.group == p.birth.group {
			fmt.Fprintf(out, "D sparse-tid=%d birth=%d\n", tid, birth.start)
			for _, field := range []string{"wchan", "syscall", "stack"} {
				raw, err := sparseProcRead(fd, field, 1024)
				if err != nil {
					raw = []byte("unavailable")
				}
				fmt.Fprintf(out, "D %s %s\n", field, raw)
			}
		}
		unix.Close(fd)
		if out.Len() > (16<<10)-4096 {
			break
		}
	}
	return out.Bytes()
}

func nativeSparseMmap(t *testing.T, mount *mounted, backing string, safeToRemove, childReaped, exchangeJoined *bool) {
	t.Helper()
	output := nativePhaseOutput // snapshot before an observation can outlive fixture cleanup
	executable, err := os.Open("/proc/self/exe")
	nativeMust(t, err)
	defer executable.Close()
	root, err := os.Open(mount.Mountpoint())
	nativeMust(t, err)
	defer func() {
		if *exchangeJoined {
			root.Close()
		}
	}()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	nativeMust(t, err)
	left, right := os.NewFile(uintptr(pair[0]), "sparse-parent"), os.NewFile(uintptr(pair[1]), "sparse-child")
	defer right.Close()
	conn, err := sparseSocket(left)
	left.Close()
	nativeMust(t, err)
	defer conn.Close()
	serverPin, err := sparsePinProcess(os.Getpid())
	nativeMust(t, err)
	closePins := true
	defer func() {
		if closePins {
			unix.Close(serverPin.fd)
		}
	}()
	pidFD := -1
	command := exec.Command("/proc/self/fd/3", sparseChildArgument)
	command.ExtraFiles = []*os.File{executable, right} // NO mount, root/backing or authority before exec
	command.Dir = "/"
	command.Env = []string{"TMPDIR=/scratch", "HOME=/tmp", "PATH=/", "GOTRACEBACK=single"}
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidFD}
	nativePhase("sparse-spawn", 0, false)
	owner, startErr := nativeStartChild(command)
	if startErr != nil {
		fmt.Fprintf(output, "D sparse-start-failed error=%s\n", nativeChildError(startErr))
	}
	nativeMust(t, startErr)
	*childReaped = false
	right.Close()
	childPin, pinErr := sparsePinProcess(command.Process.Pid)
	if pinErr == nil && (childPin.birth.parent != os.Getpid() || childPin.birth.group != command.Process.Pid) {
		pinErr = errors.New("sparse child lineage")
	}
	defer func() {
		if closePins && childPin != nil {
			unix.Close(childPin.fd)
		}
	}()
	defer func() {
		if *childReaped && pidFD >= 0 {
			unix.Close(pidFD)
		}
	}()
	owner.allowWait() // birth pin attempted before the creating thread's sole Wait
	done := owner.done
	var waitResult nativeChildResult
	waitReceived := false
	killAttempted := false
	var killErr error
	recordWait := func(result nativeChildResult, phase string) {
		waitResult, waitReceived = result, true
		*childReaped = result.reaped()
		done = nil
		fmt.Fprintf(output, "D sparse-wait phase=%s parent-kill-attempted=%t result=%s\n", phase, killAttempted, nativeChildWaitSummary(result, true))
	}
	nativePhase("sparse-spawn", 0, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	failure := errors.Join(pinErr, conn.SetDeadline(deadline))
	if pidFD < 0 {
		failure = errors.Join(failure, errors.New("sparse child pidfd unavailable"))
	}
	exchanged := make(chan error, 1)
	var exchangeErr error
	exchangeReceived := false
	recordExchange := func(err error, phase string) {
		exchangeErr, exchangeReceived = err, true
		*exchangeJoined = true
		exchanged = nil
		fmt.Fprintf(output, "D sparse-exchange phase=%s error=%s\n", phase, nativeChildError(err))
	}
	if failure == nil {
		*exchangeJoined = false
		go func() {
			err := nativeChildStage(output, "sparse-ready-receive", func() error {
				_, err := sparseReceive(conn, "ready-v1", false)
				return err
			})
			if err == nil {
				err = nativeChildStage(output, "sparse-mount-send", func() error { return sparseSend(conn, "mount-v1", int(root.Fd())) })
			}
			if err == nil {
				err = nativeChildStage(output, "sparse-complete-receive", func() error {
					_, err := sparseReceive(conn, "complete-v1", false)
					return err
				})
			}
			exchanged <- err
		}()
		select {
		case failure = <-exchanged:
			recordExchange(failure, "before-cleanup")
		case <-ctx.Done():
			failure = ctx.Err()
		}
	}
	if failure == nil {
		select {
		case result := <-done:
			recordWait(result, "before-cleanup")
			failure = result.err
			if failure == nil && !*childReaped {
				failure = errors.New("child Wait without reap")
			}
		case <-ctx.Done():
			failure = ctx.Err()
		}
	}
	if failure != nil {
		*safeToRemove = false
		// Snapshot already-delivered Wait before any parent cleanup action. A
		// later signal result is not evidence that it caused the original failure.
		select {
		case result := <-done:
			recordWait(result, "before-cleanup")
		default:
		}
		fmt.Fprintf(output, "D sparse-initiating-failure error=%s wait=%s\n", nativeChildError(failure), nativeChildWaitSummary(waitResult, waitReceived))
		// An independent server runtime observes both processes before abort/kill.
		diagnostic := make(chan struct{}, 1)
		go func() {
			raw := serverPin.diagnostic("server")
			if childPin != nil {
				raw = append(raw, childPin.diagnostic("child")...)
			}
			_, _ = output.Write(raw)
			diagnostic <- struct{}{}
		}()
		select {
		case <-diagnostic:
		case <-time.After(time.Second):
			closePins = false
		}
		conn.Close()
		if !*exchangeJoined {
			select {
			case err := <-exchanged:
				recordExchange(err, "cleanup")
			case <-time.After(time.Second):
			}
		}
		mount.fs.stop(failure) // abort only this fixture's exact mount
		if !*childReaped && pidFD >= 0 {
			killAttempted = true
			killErr = unix.PidfdSendSignal(pidFD, unix.SIGKILL, nil, 0)
		}
		if !*childReaped {
			select {
			case result := <-done:
				recordWait(result, "cleanup")
			case <-time.After(3 * time.Second):
			}
		}
		fmt.Fprintf(output, "D sparse-failure-results initiating=%s exchange-received=%t exchange=%s wait=%s parent-kill-attempted=%t kill-error=%s\n", nativeChildError(failure), exchangeReceived, nativeChildError(exchangeErr), nativeChildWaitSummary(waitResult, waitReceived), killAttempted, nativeChildError(killErr))
		fmt.Fprintf(output, "D sparse-child-failed reaped=%t exchange-joined=%t\n", *childReaped, *exchangeJoined)
		t.FailNow() // no verbose-printer write before cleanup
	}
	nativePhase("sparse-reaped", 0, true)
	model, _ := sparseModel(2)
	nativePhase("sparse-backing", 0, false)
	file, err := os.Open(filepath.Join(backing, "sparse-prefix"))
	nativeMust(t, err)
	defer file.Close()
	actual, err := io.ReadAll(io.LimitReader(file, int64(len(model)+1)))
	nativePhase("sparse-backing", 0, true)
	nativeMust(t, err)
	if !bytes.Equal(actual, model) {
		t.Fatal("sparse backing model including holes differs")
	}
}
