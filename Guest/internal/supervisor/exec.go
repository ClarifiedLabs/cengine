//go:build linux

package supervisor

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

const execStage1Argument = "cengine-exec-stage1"
const execStage2Argument = "cengine-exec-stage2"
const execStage3Argument = "cengine-exec-stage3"
const execStage1CgroupFD = 5
const execStage1TargetPIDFD = 6
const execStage2MountNamespaceFD = 5
const execStage2PIDNamespaceFD = 6
const execStage2CgroupFD = 7
const execStage2TargetPIDFD = 8

func IsExecStage1(arguments []string) bool {
	return len(arguments) == 3 && arguments[1] == execStage1Argument
}
func IsExecStage2(arguments []string) bool {
	return len(arguments) == 2 && arguments[1] == execStage2Argument
}
func IsExecStage3(arguments []string) bool {
	return len(arguments) == 2 && arguments[1] == execStage3Argument
}

func RunExecStage1(pid int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rootFD, err := unix.Open(fmt.Sprintf("/proc/%d/root", pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open workload root: %w", err)
	}
	root := os.NewFile(uintptr(rootFD), "workload-root")
	if root == nil {
		_ = unix.Close(rootFD)
		return errors.New("workload root is unavailable")
	}
	defer root.Close()
	mountNamespaceFD, err := unix.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open workload mount namespace: %w", err)
	}
	mountNamespace := os.NewFile(uintptr(mountNamespaceFD), "workload-mount-namespace")
	if mountNamespace == nil {
		_ = unix.Close(mountNamespaceFD)
		return errors.New("workload mount namespace is unavailable")
	}
	defer mountNamespace.Close()
	pidNamespaceFD, err := unix.Open(fmt.Sprintf("/proc/%d/ns/pid", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open workload PID namespace: %w", err)
	}
	pidNamespace := os.NewFile(uintptr(pidNamespaceFD), "workload-pid-namespace")
	if pidNamespace == nil {
		_ = unix.Close(pidNamespaceFD)
		return errors.New("workload PID namespace is unavailable")
	}
	defer pidNamespace.Close()
	cgroup := os.NewFile(execStage1CgroupFD, "exec-cgroup")
	if cgroup == nil {
		return errors.New("exec cgroup file descriptor is unavailable")
	}
	defer cgroup.Close()
	gate := os.NewFile(4, "exec-cgroup-ready")
	if gate == nil {
		return errors.New("exec cgroup readiness file descriptor is unavailable")
	}
	defer gate.Close()
	var ready [1]byte
	if _, err := io.ReadFull(gate, ready[:]); err != nil {
		return fmt.Errorf("wait for exec cgroup placement: %w", err)
	}
	if err := joinWorkloadNamespacesExceptMountAndPID(pid, namespaceOperations{unshare: unix.Unshare, open: unix.Open, setns: unix.Setns, close: unix.Close}); err != nil {
		return err
	}
	spec := os.NewFile(3, "exec-spec")
	if spec == nil {
		return errors.New("exec specification is unavailable")
	}
	targetPID := os.NewFile(execStage1TargetPIDFD, "exec-target-pid")
	if targetPID == nil {
		return errors.New("exec target PID descriptor is unavailable")
	}
	defer targetPID.Close()
	command := execStage2Command(spec, root, mountNamespace, pidNamespace, cgroup, targetPID)
	if err := runExecCommand(command, nil); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit
		}
		return fmt.Errorf("run exec stage 2: %w", err)
	}
	return nil
}

func execStage2Command(spec, root, mountNamespace, pidNamespace, cgroup, targetPID *os.File) *exec.Cmd {
	command := exec.Command("/proc/self/exe", execStage2Argument)
	command.ExtraFiles = []*os.File{spec, root, mountNamespace, pidNamespace, cgroup, targetPID}
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command
}

type namespaceOperations struct {
	unshare func(int) error
	open    func(string, int, uint32) (int, error)
	setns   func(int, int) error
	close   func(int) error
}

func joinWorkloadNamespacesExceptMountAndPID(pid int, operations namespaceOperations) error {
	if err := operations.unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare filesystem context: %w", err)
	}
	for _, namespace := range []struct {
		name string
		flag int
	}{{"uts", unix.CLONE_NEWUTS}, {"ipc", unix.CLONE_NEWIPC}, {"net", unix.CLONE_NEWNET}, {"cgroup", unix.CLONE_NEWCGROUP}} {
		fd, err := operations.open(fmt.Sprintf("/proc/%d/ns/%s", pid, namespace.name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		err = operations.setns(fd, namespace.flag)
		_ = operations.close(fd)
		if err != nil {
			return fmt.Errorf("join %s namespace: %w", namespace.name, err)
		}
	}
	return nil
}

func RunExecStage2() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// These descriptors must cross the stage boundary but must not leak into the
	// requested workload process after the final exec.
	for _, descriptor := range []int{
		3, 4, execStage2MountNamespaceFD, execStage2PIDNamespaceFD, execStage2CgroupFD,
		execStage2TargetPIDFD,
	} {
		unix.CloseOnExec(descriptor)
	}
	mountNamespace := os.NewFile(execStage2MountNamespaceFD, "workload-mount-namespace")
	if mountNamespace == nil {
		return errors.New("workload mount namespace is unavailable")
	}
	defer mountNamespace.Close()
	if err := enterExecMountNamespace(int(mountNamespace.Fd()), unix.Unshare, unix.Setns); err != nil {
		return err
	}
	pidNamespace := os.NewFile(execStage2PIDNamespaceFD, "workload-pid-namespace")
	if pidNamespace == nil {
		return errors.New("workload PID namespace is unavailable")
	}
	defer pidNamespace.Close()
	if err := unix.Setns(int(pidNamespace.Fd()), unix.CLONE_NEWPID); err != nil {
		return fmt.Errorf("join workload PID namespace for exec child: %w", err)
	}
	cgroup := os.NewFile(execStage2CgroupFD, "exec-cgroup")
	if cgroup == nil {
		return errors.New("exec cgroup is unavailable")
	}
	defer cgroup.Close()
	targetPID := os.NewFile(execStage2TargetPIDFD, "exec-target-pid")
	if targetPID == nil {
		return errors.New("exec target PID descriptor is unavailable")
	}
	defer targetPID.Close()
	file := os.NewFile(3, "exec-spec")
	if file == nil {
		return errors.New("exec specification is unavailable")
	}
	defer file.Close()
	root := os.NewFile(4, "workload-root")
	if root == nil {
		return errors.New("workload root is unavailable")
	}
	defer root.Close()
	command := execStage3Command(file, root, cgroup)
	if err := runExecCommand(command, func(pid int) error {
		_, err := fmt.Fprintf(targetPID, "%d\n", pid)
		return err
	}); err != nil {
		return err
	}
	return nil
}

func execStage3Command(spec, root, cgroup *os.File) *exec.Cmd {
	command := exec.Command("/proc/self/exe", execStage3Argument)
	command.ExtraFiles = []*os.File{spec, root}
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroup.Fd()),
	}
	return command
}

func RunExecStage3() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	file := os.NewFile(3, "exec-spec")
	if file == nil {
		return errors.New("exec specification is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, protocol.MaxControlFrame))
	if err != nil {
		return err
	}
	var spec protocol.ExecSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return err
	}
	root := os.NewFile(4, "workload-root")
	if root == nil {
		return errors.New("workload root is unavailable")
	}
	defer root.Close()
	if err := enterExecRoot(int(root.Fd()), unix.Fchdir, unix.Chroot); err != nil {
		return err
	}
	working := spec.WorkingDirectory
	if working == "" {
		working = "/"
	}
	if err := os.Chdir(working); err != nil {
		return fmt.Errorf("change to exec working directory %s: %w", working, err)
	}
	uid, gid, namedGroups, err := resolveUser(spec.User)
	if err != nil {
		return err
	}
	capabilities, err := capabilityMask(spec.CapabilityAdd, spec.CapabilityDrop, spec.Privileged)
	if err != nil {
		return err
	}
	if err := applyRlimits(spec.Rlimits, unix.Setrlimit); err != nil {
		return err
	}
	// Install while the staging process retains CAP_SYS_ADMIN so seccomp does
	// not force the workload's independently selected no-new-privileges state.
	if err := applyDefaultSeccomp(spec.SeccompDefault, capabilities); err != nil {
		return err
	}
	if err := applyCapabilityBoundingSet(capabilities, unix.Prctl); err != nil {
		return err
	}
	groups := make([]int, 0, len(spec.User.AdditionalGroups)+len(namedGroups))
	for _, group := range spec.User.AdditionalGroups {
		groups = append(groups, int(group))
	}
	groups = append(groups, namedGroups...)
	if err := unix.Setgroups(groups); err != nil {
		return err
	}
	if err := unix.Setgid(gid); err != nil {
		return err
	}
	if err := unix.Setuid(uid); err != nil {
		return err
	}
	if err := applyProcessCapabilities(capabilities, uid, unix.Capset); err != nil {
		return err
	}
	if err := applyNoNewPrivileges(spec.NoNewPrivileges, unix.Prctl); err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	environment := processEnvironment(spec.Environment, hostname, homeDirectory(uid), spec.Terminal)
	for _, value := range environment {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) == 2 {
			_ = os.Setenv(parts[0], parts[1])
		}
	}
	if len(spec.Arguments) == 0 {
		return errors.New("exec requires arguments")
	}
	path, err := exec.LookPath(spec.Arguments[0])
	if err != nil {
		return fmt.Errorf("look up exec command %s: %w", spec.Arguments[0], err)
	}
	return unix.Exec(path, spec.Arguments, environment)
}

// runExecCommand keeps each staging process alive as a transparent signal and
// exit-status proxy for its child. SignalExec resolves the final staged child
// directly for signals that cannot pass through these proxies.
func runExecCommand(command *exec.Cmd, started func(int) error) error {
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, forwardedExecSignals()...)
	defer signal.Stop(signals)
	if err := command.Start(); err != nil {
		return err
	}
	if started != nil {
		if err := started(command.Process.Pid); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return fmt.Errorf("publish exec target PID: %w", err)
		}
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	return forwardExecSignalsUntilWait(signals, wait, func(value syscall.Signal) error {
		err := unix.Kill(command.Process.Pid, value)
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return err
	})
}

func forwardedExecSignals() []os.Signal {
	result := make([]os.Signal, 0, 59)
	for value := 1; value < 65; value++ {
		// SIGKILL and SIGSTOP cannot be caught. SIGCHLD is consumed by Wait;
		// signals 32 and 33 are reserved by the Linux threading runtime.
		if value == int(unix.SIGKILL) || value == int(unix.SIGSTOP) ||
			value == int(unix.SIGCHLD) || value == 32 || value == 33 {
			continue
		}
		result = append(result, syscall.Signal(value))
	}
	return result
}

func forwardExecSignalsUntilWait(
	signals <-chan os.Signal,
	wait <-chan error,
	forward func(syscall.Signal) error,
) error {
	for {
		select {
		case err := <-wait:
			return err
		case value := <-signals:
			linuxSignal, ok := value.(syscall.Signal)
			if !ok {
				continue
			}
			if err := forward(linuxSignal); err != nil {
				return fmt.Errorf("forward exec signal %d: %w", linuxSignal, err)
			}
		}
	}
}

func enterExecMountNamespace(fd int, unshare func(int) error, setns func(int, int) error) error {
	if err := unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare exec filesystem context: %w", err)
	}
	if err := setns(fd, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("join workload mount namespace: %w", err)
	}
	return nil
}

// ExecStageExitCode returns the conventional shell exit status for a command
// that could not be executed. Docker clients use 127 to distinguish a missing
// executable from a command that ran and failed.
func ExecStageExitCode(err error) int {
	if exit, ok := err.(*exec.ExitError); ok {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exit.ExitCode()
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return 127
	}
	return 126
}

func enterExecRoot(fd int, fchdir func(int) error, chroot func(string) error) error {
	if err := fchdir(fd); err != nil {
		return fmt.Errorf("enter workload root: %w", err)
	}
	if err := chroot("."); err != nil {
		return fmt.Errorf("chroot workload: %w", err)
	}
	return nil
}

func applyNoNewPrivileges(
	enabled bool,
	prctl func(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) error,
) error {
	if !enabled {
		return nil
	}
	if err := prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no-new-privileges: %w", err)
	}
	return nil
}

func (s *Supervisor) PrepareExec(spec protocol.ExecSpec) error {
	if spec.ID == "" || spec.ID == "." || spec.ID == ".." || filepath.Base(spec.ID) != spec.ID || len(spec.Arguments) == 0 {
		return errors.New("exec requires id and arguments")
	}
	processIO, err := openPinnedProcessIO(ioDirectoryPath, "exec-"+spec.ID+"-", spec.IOClaim)
	if err != nil {
		return fmt.Errorf("pin exec I/O: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command == nil {
		processIO.close()
		return errors.New("workload is not running")
	}
	if s.spec != nil && pathPolicyMasksUserDatabase(s.spec.MaskedPaths) {
		spec.User, err = normalizeExecUserFromSnapshot(
			spec.User, workloadUserDatabaseSnapshotPath,
		)
		if err != nil {
			processIO.close()
			return fmt.Errorf("resolve exec user before masked identity files: %w", err)
		}
	}
	if _, exists := s.execStatus[spec.ID]; exists {
		processIO.close()
		return errors.New("exec already exists")
	}
	s.execSpecs[spec.ID] = spec
	s.execIO[spec.ID] = processIO
	s.execStatus[spec.ID] = protocol.ProcessStatus{Status: "created"}
	return nil
}

func normalizeExecUserFromSnapshot(
	user protocol.User, snapshot string,
) (protocol.User, error) {
	if user.Username == "" {
		return user, nil
	}
	passwd, err := os.ReadFile(filepath.Join(snapshot, "passwd"))
	if err != nil {
		return protocol.User{}, err
	}
	groupData, err := os.ReadFile(filepath.Join(snapshot, "group"))
	if err != nil {
		return protocol.User{}, err
	}
	uid, gid, namedGroups, err := resolveUserFromData(user, passwd, groupData)
	if err != nil {
		return protocol.User{}, err
	}
	if uid < 0 || uint64(uid) > uint64(^uint32(0)) || gid < 0 || uint64(gid) > uint64(^uint32(0)) {
		return protocol.User{}, errors.New("resolved exec user is outside the Linux ID range")
	}
	groups := append([]uint32(nil), user.AdditionalGroups...)
	for _, group := range namedGroups {
		if group < 0 || uint64(group) > uint64(^uint32(0)) {
			return protocol.User{}, errors.New("resolved exec group is outside the Linux ID range")
		}
		groups = append(groups, uint32(group))
	}
	return protocol.User{UID: uint32(uid), GID: uint32(gid), AdditionalGroups: groups}, nil
}

func (s *Supervisor) DiscardExec(id string) error {
	if id == "" {
		return errors.New("exec requires id")
	}
	s.mu.Lock()
	if status, exists := s.execStatus[id]; exists && status.Status != "created" && status.Status != "exited" {
		s.mu.Unlock()
		return errors.New("exec is still running")
	}
	processIO := s.execIO[id]
	terminal := s.execTerminals[id]
	delete(s.execIO, id)
	delete(s.execTerminals, id)
	delete(s.execSpecs, id)
	delete(s.execStatus, id)
	s.mu.Unlock()
	if processIO != nil {
		processIO.close()
	}
	if terminal != nil {
		terminal.Close()
	}
	return nil
}

func (s *Supervisor) StartExec(id string, consoleSize *protocol.TerminalSize) (status protocol.ProcessStatus, err error) {
	s.mu.Lock()
	if s.command == nil || s.command.Process == nil {
		s.mu.Unlock()
		return protocol.ProcessStatus{}, errors.New("workload is not running")
	}
	if err := s.reserveExecStartLocked(id); err != nil {
		s.mu.Unlock()
		return s.execStatus[id], err
	}
	pid := s.command.Process.Pid
	workloadID := s.spec.ID
	spec, specExists := s.execSpecs[id]
	processIO := s.execIO[id]
	s.mu.Unlock()
	if !specExists || processIO == nil {
		s.rollbackExecStart(id)
		return protocol.ProcessStatus{}, errors.New("exec I/O is not prepared")
	}
	committed := false
	defer func() {
		if !committed {
			s.rollbackExecStart(id)
		}
	}()
	data, err := json.Marshal(spec)
	if err != nil {
		return protocol.ProcessStatus{}, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return protocol.ProcessStatus{}, err
	}
	gateReader, gateWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		return protocol.ProcessStatus{}, err
	}
	targetPIDReader, targetPIDWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	stdout, err := duplicateFile(processIO.stdout, "exec-"+id+"-stdout")
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		targetPIDWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	stderr, err := duplicateFile(processIO.stderr, "exec-"+id+"-stderr")
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		targetPIDWriter.Close()
		stdout.Close()
		return protocol.ProcessStatus{}, err
	}
	stdinReader, stdinWriter := io.Pipe()
	var terminalMaster *os.File
	var terminalSlave *os.File
	var terminalInput *os.File
	var terminalOutput *os.File
	if spec.Terminal {
		terminalMaster, terminalSlave, err = openPseudoTerminal(
			selectedTerminalSize(consoleSize, spec.ConsoleSize),
		)
		if err == nil {
			terminalInput, err = duplicateFile(terminalMaster, "exec-"+id+"-terminal-input")
		}
		if err == nil {
			terminalOutput, err = duplicateFile(terminalMaster, "exec-"+id+"-terminal-output")
		}
		if err != nil {
			if terminalOutput != nil {
				terminalOutput.Close()
			}
			if terminalInput != nil {
				terminalInput.Close()
			}
			if terminalSlave != nil {
				terminalSlave.Close()
			}
			if terminalMaster != nil {
				terminalMaster.Close()
			}
			reader.Close()
			writer.Close()
			gateReader.Close()
			gateWriter.Close()
			targetPIDReader.Close()
			targetPIDWriter.Close()
			stdout.Close()
			stderr.Close()
			stdinReader.Close()
			stdinWriter.Close()
			return protocol.ProcessStatus{}, err
		}
	}
	cgroup, err := openExecCgroup("/sys/fs/cgroup", workloadID, id)
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		targetPIDWriter.Close()
		stdout.Close()
		stderr.Close()
		stdinReader.Close()
		stdinWriter.Close()
		if terminalOutput != nil {
			terminalOutput.Close()
		}
		if terminalInput != nil {
			terminalInput.Close()
		}
		if terminalSlave != nil {
			terminalSlave.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		return protocol.ProcessStatus{}, err
	}
	cgroupPath := cgroup.Name()
	defer func() {
		if !committed {
			_ = os.Remove(cgroupPath)
		}
	}()
	command := exec.Command("/proc/self/exe", execStage1Argument, strconv.Itoa(pid))
	command.ExtraFiles = []*os.File{reader, gateReader, cgroup, targetPIDWriter}
	if spec.Terminal {
		command.Stdin = terminalSlave
		command.Stdout = terminalSlave
		command.Stderr = terminalSlave
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	} else {
		command.Stdout = stdout
		command.Stderr = stderr
		command.Stdin = stdinReader
	}
	if err := command.Start(); err != nil {
		cgroup.Close()
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		targetPIDWriter.Close()
		stdout.Close()
		stderr.Close()
		stdinReader.Close()
		stdinWriter.Close()
		if terminalOutput != nil {
			terminalOutput.Close()
		}
		if terminalInput != nil {
			terminalInput.Close()
		}
		if terminalSlave != nil {
			terminalSlave.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		return protocol.ProcessStatus{}, err
	}
	if terminalSlave != nil {
		terminalSlave.Close()
	}
	cgroup.Close()
	reader.Close()
	gateReader.Close()
	targetPIDWriter.Close()
	if terminalOutput != nil {
		go pumpTerminalOutput(terminalOutput, stdout, command)
	} else {
		stdout.Close()
	}
	stderr.Close()
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		stdinWriter.Close()
		if terminalInput != nil {
			terminalInput.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		_ = command.Process.Kill()
		_ = command.Wait()
		return protocol.ProcessStatus{}, err
	}
	writer.Close()
	if _, err := gateWriter.Write([]byte{1}); err != nil {
		gateWriter.Close()
		targetPIDReader.Close()
		stdinWriter.Close()
		if terminalInput != nil {
			terminalInput.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		_ = command.Process.Kill()
		_ = command.Wait()
		return protocol.ProcessStatus{}, err
	}
	gateWriter.Close()
	targetPID, err := readExecTargetPID(targetPIDReader)
	targetPIDReader.Close()
	if err != nil {
		stdinWriter.Close()
		if terminalInput != nil {
			terminalInput.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		_ = command.Process.Kill()
		_ = command.Wait()
		return protocol.ProcessStatus{}, err
	}
	status = protocol.ProcessStatus{Status: "running", PID: execInspectPID(targetPID)}
	s.mu.Lock()
	s.execs[id] = command
	s.execTargets[id] = targetPID
	s.execCgroups[id] = cgroupPath
	if terminalMaster != nil {
		s.execTerminals[id] = terminalMaster
	}
	s.execStatus[id] = status
	s.mu.Unlock()
	committed = true
	go s.reapExec(id, command)
	if terminalInput != nil {
		stdinWriter.Close()
		stdinReader.Close()
		go pumpTerminalInput(processIO.stdin, processIO.stdinClosed, terminalInput, command)
	} else {
		go pumpInput(processIO.stdin, processIO.stdinClosed, stdinWriter, command)
	}
	return status, nil
}

func (s *Supervisor) StartExecAttached(id string, consoleSize *protocol.TerminalSize, stream io.ReadWriter, ready func(protocol.ProcessStatus) error) (status protocol.ProcessStatus, err error) {
	s.mu.Lock()
	if s.command == nil || s.command.Process == nil {
		s.mu.Unlock()
		return protocol.ProcessStatus{}, errors.New("workload is not running")
	}
	if err := s.reserveExecStartLocked(id); err != nil {
		s.mu.Unlock()
		return s.execStatus[id], err
	}
	pid := s.command.Process.Pid
	workloadID := s.spec.ID
	spec, specExists := s.execSpecs[id]
	s.mu.Unlock()
	if !specExists {
		s.failAttachedExecStart(id, errors.New("exec specification is not prepared"))
		return protocol.ProcessStatus{}, errors.New("exec specification is not prepared")
	}
	committed := false
	defer func() {
		if !committed {
			s.failAttachedExecStart(id, err)
		}
	}()

	data, err := json.Marshal(spec)
	if err != nil {
		return protocol.ProcessStatus{}, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return protocol.ProcessStatus{}, err
	}
	gateReader, gateWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		return protocol.ProcessStatus{}, err
	}
	targetPIDReader, targetPIDWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	mux := &dockerStreamMux{writer: stream, terminal: spec.Terminal}
	cgroup, err := openExecCgroup("/sys/fs/cgroup", workloadID, id)
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		targetPIDWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	cgroupPath := cgroup.Name()
	defer func() {
		if !committed {
			_ = os.Remove(cgroupPath)
		}
	}()
	command := exec.Command("/proc/self/exe", execStage1Argument, strconv.Itoa(pid))
	command.ExtraFiles = []*os.File{reader, gateReader, cgroup, targetPIDWriter}
	var stdinFile *os.File
	var cancelStdin func()
	var terminalMaster *os.File
	var terminalSlave *os.File
	var terminalInput *os.File
	var terminalOutput *os.File
	if spec.Terminal {
		terminalMaster, terminalSlave, err = openPseudoTerminal(
			selectedTerminalSize(consoleSize, spec.ConsoleSize),
		)
		if err == nil && spec.AttachStdin {
			terminalInput, err = duplicateFile(terminalMaster, "exec-"+id+"-attached-terminal-input")
		}
		if err == nil && spec.AttachStdout {
			terminalOutput, err = duplicateFile(terminalMaster, "exec-"+id+"-attached-terminal-output")
		}
		if err != nil {
			cgroup.Close()
			if terminalOutput != nil {
				terminalOutput.Close()
			}
			if terminalInput != nil {
				terminalInput.Close()
			}
			if terminalSlave != nil {
				terminalSlave.Close()
			}
			if terminalMaster != nil {
				terminalMaster.Close()
			}
			reader.Close()
			writer.Close()
			gateReader.Close()
			gateWriter.Close()
			targetPIDReader.Close()
			targetPIDWriter.Close()
			return protocol.ProcessStatus{}, err
		}
		command.Stdin = terminalSlave
		command.Stdout = terminalSlave
		command.Stderr = terminalSlave
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	} else if spec.AttachStdin {
		stdinFile, cancelStdin, err = attachedExecStdin(stream)
		if err != nil {
			cgroup.Close()
			reader.Close()
			writer.Close()
			gateReader.Close()
			gateWriter.Close()
			targetPIDReader.Close()
			targetPIDWriter.Close()
			return protocol.ProcessStatus{}, err
		}
		command.Stdin = stdinFile
	}
	if !spec.Terminal && spec.AttachStdout {
		command.Stdout = mux.stream(1)
	}
	if !spec.Terminal && spec.AttachStderr {
		command.Stderr = mux.stream(2)
	}
	if err := command.Start(); err != nil {
		cgroup.Close()
		if cancelStdin != nil {
			cancelStdin()
		}
		if stdinFile != nil {
			stdinFile.Close()
		}
		if terminalOutput != nil {
			terminalOutput.Close()
		}
		if terminalInput != nil {
			terminalInput.Close()
		}
		if terminalSlave != nil {
			terminalSlave.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		targetPIDWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	cgroup.Close()
	if stdinFile != nil {
		stdinFile.Close()
	}
	if terminalSlave != nil {
		terminalSlave.Close()
	}
	if terminalOutput != nil {
		go pumpTerminalOutput(terminalOutput, mux.stream(1), command)
	}
	if terminalInput != nil {
		cancelStdin = attachedTerminalInput(stream, terminalInput)
	}
	reader.Close()
	gateReader.Close()
	targetPIDWriter.Close()
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		gateWriter.Close()
		targetPIDReader.Close()
		if cancelStdin != nil {
			cancelStdin()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		_ = command.Process.Kill()
		_ = command.Wait()
		return protocol.ProcessStatus{}, err
	}
	writer.Close()
	status = protocol.ProcessStatus{Status: "starting"}
	s.mu.Lock()
	s.execs[id] = command
	s.execCgroups[id] = cgroupPath
	if terminalMaster != nil {
		s.execTerminals[id] = terminalMaster
	}
	s.execStatus[id] = status
	s.mu.Unlock()
	committed = true
	go s.reapExec(id, command, cancelStdin)
	if err := ready(status); err != nil {
		gateWriter.Close()
		targetPIDReader.Close()
		_ = command.Process.Kill()
		return protocol.ProcessStatus{}, err
	}
	if _, err := gateWriter.Write([]byte{1}); err != nil {
		gateWriter.Close()
		targetPIDReader.Close()
		_ = command.Process.Kill()
		return protocol.ProcessStatus{}, err
	}
	gateWriter.Close()
	targetPID, err := readExecTargetPID(targetPIDReader)
	targetPIDReader.Close()
	if err != nil {
		_ = command.Process.Kill()
		return protocol.ProcessStatus{}, err
	}
	status = s.publishExecTargetPID(id, command, targetPID)
	return status, nil
}

func (s *Supervisor) reserveExecStartLocked(id string) error {
	status, exists := s.execStatus[id]
	if !exists {
		return errors.New("exec is not prepared")
	}
	if status.Status != "created" {
		return errors.New("exec has already started")
	}
	s.execStatus[id] = protocol.ProcessStatus{Status: "starting"}
	return nil
}

func (s *Supervisor) rollbackExecStart(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.execStatus[id].Status == "starting" {
		s.execStatus[id] = protocol.ProcessStatus{Status: "created"}
	}
}

func (s *Supervisor) failAttachedExecStart(id string, err error) {
	code := ExecStageExitCode(err)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.execStatus[id].Status == "starting" {
		s.execStatus[id] = protocol.ProcessStatus{Status: "exited", ExitCode: &code}
	}
}

func (s *Supervisor) publishExecTargetPID(id string, command *exec.Cmd, targetPID int) protocol.ProcessStatus {
	inspectPID := execInspectPID(targetPID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.execs[id] == command {
		s.execTargets[id] = targetPID
		status := protocol.ProcessStatus{Status: "running", PID: inspectPID}
		s.execStatus[id] = status
		return status
	}
	status := s.execStatus[id]
	if status.Status == "exited" {
		status.PID = inspectPID
		s.execStatus[id] = status
	}
	return status
}

func attachedExecStdin(stream io.Reader) (*os.File, func(), error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create attached exec stdin pipe: %w", err)
	}
	cancel := func() {
		_ = writer.Close()
		if closer, ok := stream.(interface{ CloseRead() error }); ok {
			_ = closer.CloseRead()
		}
	}
	go func() {
		_, _ = io.Copy(writer, stream)
		_ = writer.Close()
	}()
	return reader, cancel, nil
}

func attachedTerminalInput(stream io.Reader, destination *os.File) func() {
	cancel := func() {
		_ = destination.Close()
		if closer, ok := stream.(interface{ CloseRead() error }); ok {
			_ = closer.CloseRead()
		}
	}
	go func() {
		_, _ = io.Copy(destination, stream)
		_ = destination.Close()
	}()
	return cancel
}

func selectedTerminalSize(
	start, configured *protocol.TerminalSize,
) *protocol.TerminalSize {
	if start != nil && (start.Height != 0 || start.Width != 0) {
		return start
	}
	return configured
}

type dockerStreamMux struct {
	writer   io.Writer
	terminal bool
	mu       sync.Mutex
}

type dockerStreamWriter struct {
	mux    *dockerStreamMux
	stream byte
}

func (mux *dockerStreamMux) stream(stream byte) io.Writer {
	return dockerStreamWriter{mux: mux, stream: stream}
}

func (writer dockerStreamWriter) Write(payload []byte) (int, error) {
	writer.mux.mu.Lock()
	defer writer.mux.mu.Unlock()
	if writer.mux.terminal {
		if err := writeAll(writer.mux.writer, payload); err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	var header [8]byte
	header[0] = writer.stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	if err := writeAll(writer.mux.writer, header[:]); err != nil {
		return 0, err
	}
	if err := writeAll(writer.mux.writer, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func openExecCgroup(root, workloadID, execID string) (*os.File, error) {
	if execID == "" || filepath.Base(execID) != execID || execID == "." || execID == ".." {
		return nil, fmt.Errorf("invalid exec cgroup identifier %q", execID)
	}
	parent := filepath.Join(root, "cengine", workloadID, ".cengine-exec")
	if err := os.Mkdir(parent, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create exec cgroup: %w", err)
	}
	path := filepath.Join(parent, execID)
	if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create per-exec cgroup: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open exec cgroup: %w", err)
	}
	return file, nil
}

func readExecTargetPID(reader io.Reader) (int, error) {
	var pid int
	if _, err := fmt.Fscan(io.LimitReader(reader, 32), &pid); err != nil {
		return 0, fmt.Errorf("read exec target PID: %w", err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid exec target PID %d", pid)
	}
	return pid, nil
}

func execInspectPID(targetPID int) int {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", targetPID))
	if err != nil {
		return targetPID
	}
	return execInspectPIDFromStatus(status, targetPID)
}

func execInspectPIDFromStatus(status []byte, fallback int) int {
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "NSpid:" {
			continue
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		if err == nil && pid > 0 {
			return pid
		}
	}
	return fallback
}

func (s *Supervisor) ExecStatus(id string) protocol.ProcessStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execStatus[id]
}

func (s *Supervisor) ResizeExec(id string, size protocol.TerminalSize) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	spec, exists := s.execSpecs[id]
	if !exists || !spec.Terminal {
		return errors.New("exec does not have a terminal")
	}
	if s.execStatus[id].Status != "running" {
		return errors.New("exec is not running")
	}
	return setTerminalSize(s.execTerminals[id], size)
}

func (s *Supervisor) SignalExec(id string, signal int) error {
	s.mu.Lock()
	command := s.execs[id]
	if command == nil || command.Process == nil {
		s.mu.Unlock()
		return errors.New("exec is not running")
	}
	if signal <= 0 || signal >= 65 {
		s.mu.Unlock()
		return syscall.EINVAL
	}
	targetPID := s.execTargets[id]
	cgroup := s.execCgroups[id]
	s.mu.Unlock()
	if unix.Signal(signal) == unix.SIGKILL && cgroup != "" {
		if err := os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), []byte("1"), 0o644); err != nil {
			return fmt.Errorf("kill exec cgroup: %w", err)
		}
		return nil
	}
	target := execSignalTarget(command.Process.Pid, targetPID, unix.Signal(signal))
	if target <= 0 {
		return errors.New("exec target is not running")
	}
	return unix.Kill(target, unix.Signal(signal))
}

func execSignalTarget(stagePID, targetPID int, signal unix.Signal) int {
	if signal == unix.SIGKILL || signal == unix.SIGSTOP {
		return targetPID
	}
	return stagePID
}
func (s *Supervisor) WaitExec(id string) protocol.ProcessStatus {
	for {
		status := s.ExecStatus(id)
		if !execWaitPending(status.Status) {
			return status
		}
		_ = unix.Nanosleep(&unix.Timespec{Nsec: 20_000_000}, nil)
	}
}

func execWaitPending(status string) bool {
	return status == "starting" || status == "running"
}
func (s *Supervisor) reapExec(id string, command *exec.Cmd, afterWait ...func()) {
	err := command.Wait()
	for _, action := range afterWait {
		if action != nil {
			action()
		}
	}
	code := 0
	if command.ProcessState != nil {
		code = command.ProcessState.ExitCode()
		if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code = 128 + int(status.Signal())
		}
	}
	if err != nil && code < 0 {
		code = 255
	}
	s.mu.Lock()
	cgroup := s.execCgroups[id]
	processIO := s.execIO[id]
	terminal := s.execTerminals[id]
	inspectPID := s.execStatus[id].PID
	if inspectPID == 0 {
		inspectPID = execInspectPID(s.execTargets[id])
	}
	delete(s.execs, id)
	delete(s.execTargets, id)
	delete(s.execCgroups, id)
	delete(s.execIO, id)
	delete(s.execTerminals, id)
	delete(s.execSpecs, id)
	s.execStatus[id] = protocol.ProcessStatus{Status: "exited", PID: inspectPID, ExitCode: &code}
	s.mu.Unlock()
	if processIO != nil {
		processIO.close()
	}
	if terminal != nil {
		terminal.Close()
	}
	if cgroup != "" {
		_ = os.Remove(cgroup)
	}
}
