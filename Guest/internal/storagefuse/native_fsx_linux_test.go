//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeMountedManagedV3FsxGraceful(t *testing.T) {
	nativeMountedManagedV3(t, "fsx")
}

// Not testing.Run: neither environment nor arbitrary test patterns select work.
// This bootstrap is exec'd at / before any mount descriptor is delivered. See
// nativeSparseMmap: chdir/ExtraFiles on the self-served FUSE mount before exec can
// deadlock Go's fork child while the server runtime is stopped for fork.
func init() {
	if !fsxChildSelected(os.Args) {
		return
	}
	if err := fsxChild(); err != nil {
		fmt.Fprintf(os.Stderr, "D fsx-bootstrap-failed error=%s\n", nativeChildError(err))
		os.Exit(1)
	}
	os.Exit(1) // successful exec never returns
}

func fsxVerifyFile(file *os.File) error {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return err
	}
	if err := unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != fsxBinaryBytes || st.Uid != 0 || st.Gid != 0 ||
		st.Mode&0022 != 0 || st.Mode&0111 == 0 || st.Mode&07000 != 0 || st.Nlink != 1 || fs.Flags&unix.ST_RDONLY == 0 {
		return errors.New("fsx immutable file profile")
	}
	raw, err := io.ReadAll(io.NewSectionReader(file, 0, fsxBinaryBytes+1))
	if err != nil {
		return err
	}
	return fsxVerifyBytes(raw)
}

func fsxDropPrivileges() error {
	if err := unix.Setgroups(nil); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 64 << 20, Max: 64 << 20}); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	// Lock NOROOT: UID 0 must not regain capabilities when the static fsx execs.
	if err := unix.Prctl(unix.PR_SET_SECUREBITS, 1|2, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			return err
		}
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return err
	}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	if data != ([2]unix.CapUserData{}) {
		return errors.New("fsx capabilities survived")
	}
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		value, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0)
		if err != nil || value != 0 {
			return errors.New("fsx bounding capabilities survived")
		}
	}
	unix.Umask(0077)
	return nil
}

func fsxChild() error {
	runtime.LockOSThread() // capabilities/securebits and exec belong to one thread
	unix.Close(3)          // pinned test executable, no authority or mount descriptor
	socket := os.NewFile(4, "private-fsx-socket")
	conn, err := sparseSocket(socket)
	socket.Close()
	if err != nil {
		return err
	}
	defer conn.Close()
	if os.Geteuid() != 0 || os.Getegid() != 0 || runtime.GOARCH != "arm64" {
		return errors.New("fsx child profile")
	}
	if err = conn.SetDeadline(time.Now().Add(fsxChildLimit)); err != nil {
		return err
	}
	if err = sparseSend(conn, "ready-v1", -1); err != nil {
		return err
	}
	root, err := sparseReceive(conn, "mount-v1", true)
	if err != nil {
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
		return errors.New("fsx mount descriptor")
	}
	fd, err := sparseReceive(conn, "fsx-v1", true)
	if err != nil {
		return err
	}
	executable := os.NewFile(uintptr(fd), "pinned-fsx")
	defer executable.Close()
	if err = fsxVerifyFile(executable); err != nil {
		return err
	}
	if err = unix.Fchdir(root); err != nil {
		return err
	}
	if err = fsxDropPrivileges(); err != nil {
		return err
	}
	if err = sparseSend(conn, "exec-v1", -1); err != nil {
		return err
	}
	if err = conn.Close(); err != nil {
		return err
	}
	// Received rights have CLOEXEC; fsx inherits cwd and stdio, no socket, root,
	// executable handle, storage credential, transport, or Go server descriptor.
	return unix.Exec(fmt.Sprintf("/proc/self/fd/%d", fd), fsxArgv(), []string{"LC_ALL=C"})
}

func nativeFsx(t *testing.T, mount *mounted, base string, safeToRemove, childReaped, exchangeJoined *bool) {
	t.Helper()
	if runtime.GOARCH != "arm64" {
		t.Fatal("fsx requires the exact static arm64 corpus")
	}
	output := nativePhaseOutput
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	parentCaps := [2]unix.CapUserData{}
	nativeMust(t, unix.Capget(&header, &parentCaps[0]))
	if parentCaps[0].Effective&(1<<unix.CAP_SYS_PTRACE) == 0 {
		t.Fatal("fsx diagnostics require the fixture parent's existing ptrace privilege")
	}
	fd, err := unix.Open("/fsx", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	nativeMust(t, err)
	fsx := os.NewFile(uintptr(fd), "pinned-fsx")
	defer func() {
		if *exchangeJoined {
			fsx.Close()
		}
	}()
	nativeMust(t, fsxVerifyFile(fsx))
	fmt.Fprintf(output, "D fsx-pin sha256=%s bytes=%d seed=1 operations=1000 child-seconds=%d\n", fsxSHA256, fsxBinaryBytes, int(fsxChildLimit/time.Second))
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
	var rootID unix.Statx_t
	nativeMust(t, unix.Statx(int(root.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &rootID))
	if rootID.Mask&unix.STATX_MNT_ID == 0 || rootID.Mnt_id != uint64(mount.mountID) {
		t.Fatal("fsx exact mount descriptor")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	nativeMust(t, err)
	left, right := os.NewFile(uintptr(pair[0]), "fsx-parent"), os.NewFile(uintptr(pair[1]), "fsx-child")
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
	capture := &fsxCapture{}
	var diagnostic []byte
	// Full bounded output and native owned-process stacks remain in the private
	// ext4 fixture, never in the receipt. Parent cleanup preserves every failure,
	// including a later graceful-close/authority-retirement failure.
	t.Cleanup(func() {
		raw, overflow := capture.snapshot()
		for name, data := range map[string][]byte{"fsx-output": raw, "fsx-diagnostic": diagnostic} {
			if err := os.WriteFile(filepath.Join(base, name), data, 0600); err != nil {
				*safeToRemove = false
				fmt.Fprintln(output, "D fsx-evidence-write-failed")
				t.Fail()
			}
		}
		fmt.Fprintf(output, "D fsx-output bytes=%d overflow=%t sha256=%x\n", len(raw), overflow, sha256.Sum256(raw))
	})
	pidFD := -1
	command := exec.Command("/proc/self/fd/3", fsxChildArgument)
	command.Dir = "/"
	command.ExtraFiles = []*os.File{executable, right} // pinned bootstrap/socket ONLY
	command.Env = []string{"TMPDIR=/scratch", "GOTRACEBACK=single"}
	command.Stdout, command.Stderr = capture, capture
	command.WaitDelay = time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidFD}
	started := time.Now()
	nativePhase("fsx-spawn", 0, false)
	owner, startErr := nativeStartChild(command)
	if startErr != nil {
		fmt.Fprintf(output, "D fsx-start-failed error=%s\n", nativeChildError(startErr))
	}
	nativeMust(t, startErr)
	*childReaped = false
	right.Close()
	childPin, failure := sparsePinProcess(command.Process.Pid)
	if failure == nil && (childPin.birth.parent != os.Getpid() || childPin.birth.group != command.Process.Pid) {
		failure = errors.New("fsx child lineage")
	}
	if pidFD <= 0 {
		failure = errors.Join(failure, errors.New("fsx positive pidfd required"))
	}
	defer func() {
		if closePins && childPin != nil {
			unix.Close(childPin.fd)
		}
		if *childReaped && pidFD > 0 {
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
		fmt.Fprintf(output, "D fsx-wait phase=%s parent-kill-attempted=%t result=%s\n", phase, killAttempted, nativeChildWaitSummary(result, true))
	}
	nativePhase("fsx-spawn", 0, true)
	hard := time.NewTimer(time.Until(started.Add(fsxChildLimit)))
	defer hard.Stop()
	observe := time.NewTimer(time.Until(started.Add(fsxDiagnosticAfter)))
	defer observe.Stop()
	// No global proc scan, ptrace attach, SIGQUIT, numeric PID signal, or extra
	// workload capability. The already-privileged parent reads its two birth-pins.
	diagnosed := false
	diagnose := func() {
		if diagnosed {
			return
		}
		diagnosed = true
		result := make(chan []byte, 1)
		go func() {
			raw := serverPin.diagnostic("fsx-server")
			if childPin != nil {
				raw = append(raw, childPin.diagnostic("fsx-child")...)
			}
			result <- raw
		}()
		// Independent of the worker's runtime, socket exchange and capture. This
		// sub-budget cannot move the absolute fsxChildLimit kill deadline.
		budget := min(time.Second, time.Until(started.Add(fsxChildLimit)))
		if budget < 0 {
			budget = 0
		}
		select {
		case diagnostic = <-result:
			fmt.Fprintf(output, "D fsx-diagnostic bytes=%d sha256=%x\n", len(diagnostic), sha256.Sum256(diagnostic))
		case <-time.After(budget):
			closePins = false // observer may still use them; never recycle its FDs
			diagnostic = []byte("D fsx-diagnostic-budget-exceeded\n")
			fmt.Fprintln(output, "D fsx-diagnostic-budget-exceeded")
		}
	}
	exchanged := make(chan error, 1)
	var exchangeErr error
	exchangeReceived := false
	recordExchange := func(err error, phase string) {
		exchangeErr, exchangeReceived = err, true
		*exchangeJoined = true
		exchanged = nil
		fmt.Fprintf(output, "D fsx-exchange phase=%s error=%s\n", phase, nativeChildError(err))
	}
	if failure == nil {
		failure = conn.SetDeadline(started.Add(fsxChildLimit))
	}
	if failure == nil {
		*exchangeJoined = false
		go func() {
			err := nativeChildStage(output, "fsx-ready-receive", func() error {
				_, err := sparseReceive(conn, "ready-v1", false)
				return err
			})
			if err == nil {
				err = nativeChildStage(output, "fsx-mount-send", func() error { return sparseSend(conn, "mount-v1", int(root.Fd())) })
			}
			if err == nil {
				err = nativeChildStage(output, "fsx-binary-send", func() error { return sparseSend(conn, "fsx-v1", int(fsx.Fd())) })
			}
			if err == nil {
				err = nativeChildStage(output, "fsx-exec-receive", func() error {
					_, err := sparseReceive(conn, "exec-v1", false)
					return err
				})
			}
			exchanged <- err
		}()
	}
	for failure == nil && (!*childReaped || !*exchangeJoined) {
		select {
		case failure = <-exchanged:
			recordExchange(failure, "before-cleanup")
			nativePhase("fsx-exec", 0, true)
		case result := <-done:
			recordWait(result, "before-cleanup")
			failure = result.err
			if failure == nil && !*childReaped {
				failure = errors.New("child Wait without reap")
			}
		case <-observe.C:
			nativePhase("fsx-diagnostic", 0, false)
			diagnose()
			nativePhase("fsx-diagnostic", 0, true)
		case <-hard.C:
			failure = context.DeadlineExceeded
		}
	}
	if failure == nil && !closePins {
		failure = errors.New("fsx diagnostic observer unjoined")
	}
	if failure == nil {
		raw, overflow := capture.snapshot()
		failure = fsxOutputProof(raw, overflow, waitResult.err)
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
		fmt.Fprintf(output, "D fsx-initiating-failure error=%s wait=%s\n", nativeChildError(failure), nativeChildWaitSummary(waitResult, waitReceived))
		diagnose() // before abort, even for an early exec/exchange failure
		conn.Close()
		// Signal only the retained positive pidfd. Kill does not wait for a task
		// in D state, and abort is separately joined rather than delaying kill.
		if !*childReaped && pidFD > 0 {
			killAttempted = true
			killErr = unix.PidfdSendSignal(pidFD, unix.SIGKILL, nil, 0)
		}
		aborted := make(chan struct{}, 1)
		go func() { mount.fs.stop(failure); aborted <- struct{}{} }()
		join := time.NewTimer(3 * time.Second)
		defer join.Stop()
		joining := true
		for joining && (!*childReaped || !*exchangeJoined || aborted != nil) {
			select {
			case result := <-done:
				recordWait(result, "cleanup")
			case err := <-exchanged:
				recordExchange(err, "cleanup")
			case <-aborted:
				aborted = nil
			case <-join.C:
				joining = false
			}
		}
		fmt.Fprintf(output, "D fsx-failure-results initiating=%s exchange-received=%t exchange=%s wait=%s parent-kill-attempted=%t kill-error=%s\n", nativeChildError(failure), exchangeReceived, nativeChildError(exchangeErr), nativeChildWaitSummary(waitResult, waitReceived), killAttempted, nativeChildError(killErr))
		fmt.Fprintf(output, "D fsx-failed reaped=%t exchange-joined=%t abort-joined=%t\n", *childReaped, *exchangeJoined, aborted == nil)
		t.FailNow()
	}
	nativePhase("fsx-reaped", 0, true)
	fmt.Fprintln(output, "D fsx-complete exit=0 operations=1000 marker=verified")
}
