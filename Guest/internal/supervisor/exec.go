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
const execStage1CgroupFD = 5
const execStage2MountNamespaceFD = 5
const execStage2PIDNamespaceFD = 6
const execStage2CgroupFD = 7

func IsExecStage1(arguments []string) bool {
	return len(arguments) == 3 && arguments[1] == execStage1Argument
}
func IsExecStage2(arguments []string) bool {
	return len(arguments) == 2 && arguments[1] == execStage2Argument
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
	command := execStage2Command(spec, root, mountNamespace, pidNamespace, cgroup)
	if err := command.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit
		}
		return fmt.Errorf("run exec stage 2: %w", err)
	}
	return nil
}

func execStage2Command(spec, root, mountNamespace, pidNamespace, cgroup *os.File) *exec.Cmd {
	command := exec.Command("/proc/self/exe", execStage2Argument)
	command.ExtraFiles = []*os.File{spec, root, mountNamespace, pidNamespace, cgroup}
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
	if err := applyCapabilityBoundingSet(capabilities, unix.Prctl); err != nil {
		return err
	}
	groups := make([]int, 0, len(spec.User.AdditionalGroups)+len(namedGroups))
	for _, group := range spec.User.AdditionalGroups {
		groups = append(groups, int(group))
	}
	groups = append(groups, namedGroups...)
	var credential *syscall.Credential
	if uid == 0 {
		if err := unix.Setgroups(groups); err != nil {
			return err
		}
		if err := unix.Setgid(gid); err != nil {
			return err
		}
	} else {
		credentialGroups := make([]uint32, len(groups))
		for index, group := range groups {
			credentialGroups[index] = uint32(group)
		}
		credential = &syscall.Credential{
			Uid: uint32(uid), Gid: uint32(gid), Groups: credentialGroups,
		}
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
	command := exec.Command(path, spec.Arguments[1:]...)
	command.Args = spec.Arguments
	command.Env = environment
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroup.Fd()),
		Credential:  credential,
	}
	if err := command.Run(); err != nil {
		return err
	}
	return nil
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
		return fmt.Errorf("set no-new-privileges for exec: %w", err)
	}
	return nil
}

func (s *Supervisor) PrepareExec(spec protocol.ExecSpec) error {
	if spec.ID == "" || len(spec.Arguments) == 0 {
		return errors.New("exec requires id and arguments")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command == nil {
		return errors.New("workload is not running")
	}
	if _, exists := s.execStatus[spec.ID]; exists {
		return errors.New("exec already exists")
	}
	s.execStatus[spec.ID] = protocol.ProcessStatus{Status: "created"}
	data, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return os.WriteFile("/run/cengine/io/exec-"+spec.ID+".json", data, 0600)
}

func (s *Supervisor) StartExec(id string) (protocol.ProcessStatus, error) {
	s.mu.Lock()
	if s.command == nil || s.command.Process == nil {
		s.mu.Unlock()
		return protocol.ProcessStatus{}, errors.New("workload is not running")
	}
	if _, exists := s.execs[id]; exists {
		s.mu.Unlock()
		return s.execStatus[id], errors.New("exec is running")
	}
	pid := s.command.Process.Pid
	workloadID := s.spec.ID
	s.mu.Unlock()
	data, err := os.ReadFile("/run/cengine/io/exec-" + id + ".json")
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
	stdout, err := os.OpenFile("/run/cengine/io/exec-"+id+"-stdout", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	stderr, err := os.OpenFile("/run/cengine/io/exec-"+id+"-stderr", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		stdout.Close()
		return protocol.ProcessStatus{}, err
	}
	stdinReader, stdinWriter := io.Pipe()
	cgroup, err := openWorkloadCgroup("/sys/fs/cgroup", workloadID)
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		stdout.Close()
		stderr.Close()
		stdinReader.Close()
		stdinWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	command := exec.Command("/proc/self/exe", execStage1Argument, strconv.Itoa(pid))
	command.ExtraFiles = []*os.File{reader, gateReader, cgroup}
	command.Stdout = stdout
	command.Stderr = stderr
	command.Stdin = stdinReader
	if err := command.Start(); err != nil {
		cgroup.Close()
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		stdout.Close()
		stderr.Close()
		stdinReader.Close()
		stdinWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	cgroup.Close()
	reader.Close()
	gateReader.Close()
	stdout.Close()
	stderr.Close()
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		gateWriter.Close()
		stdinWriter.Close()
		_ = command.Process.Kill()
		return protocol.ProcessStatus{}, err
	}
	writer.Close()
	if _, err := gateWriter.Write([]byte{1}); err != nil {
		gateWriter.Close()
		stdinWriter.Close()
		_ = command.Process.Kill()
		return protocol.ProcessStatus{}, err
	}
	gateWriter.Close()
	status := protocol.ProcessStatus{Status: "running", PID: command.Process.Pid}
	s.mu.Lock()
	s.execs[id] = command
	s.execStatus[id] = status
	s.mu.Unlock()
	go s.reapExec(id, command)
	go pumpInput("/run/cengine/io/exec-"+id+"-stdin", stdinWriter, command)
	return status, nil
}

func (s *Supervisor) StartExecAttached(id string, stream io.ReadWriter, ready func(protocol.ProcessStatus) error) (protocol.ProcessStatus, error) {
	s.mu.Lock()
	if s.command == nil || s.command.Process == nil {
		s.mu.Unlock()
		return protocol.ProcessStatus{}, errors.New("workload is not running")
	}
	if _, exists := s.execs[id]; exists {
		s.mu.Unlock()
		return s.execStatus[id], errors.New("exec is running")
	}
	pid := s.command.Process.Pid
	workloadID := s.spec.ID
	s.mu.Unlock()

	data, err := os.ReadFile("/run/cengine/io/exec-" + id + ".json")
	if err != nil {
		return protocol.ProcessStatus{}, err
	}
	var spec protocol.ExecSpec
	if err := json.Unmarshal(data, &spec); err != nil {
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
	mux := &dockerStreamMux{writer: stream, terminal: spec.Terminal}
	cgroup, err := openWorkloadCgroup("/sys/fs/cgroup", workloadID)
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	command := exec.Command("/proc/self/exe", execStage1Argument, strconv.Itoa(pid))
	command.ExtraFiles = []*os.File{reader, gateReader, cgroup}
	var stdinFile *os.File
	var cancelStdin func()
	if spec.AttachStdin {
		stdinFile, cancelStdin, err = attachedExecStdin(stream)
		if err != nil {
			cgroup.Close()
			reader.Close()
			writer.Close()
			gateReader.Close()
			gateWriter.Close()
			return protocol.ProcessStatus{}, err
		}
		command.Stdin = stdinFile
	}
	if spec.AttachStdout {
		command.Stdout = mux.stream(1)
	}
	if spec.AttachStderr {
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
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return protocol.ProcessStatus{}, err
	}
	cgroup.Close()
	if stdinFile != nil {
		stdinFile.Close()
	}
	reader.Close()
	gateReader.Close()
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		gateWriter.Close()
		if cancelStdin != nil {
			cancelStdin()
		}
		_ = command.Process.Kill()
		_ = command.Wait()
		return protocol.ProcessStatus{}, err
	}
	writer.Close()
	status := protocol.ProcessStatus{Status: "running", PID: command.Process.Pid}
	s.mu.Lock()
	s.execs[id] = command
	s.execStatus[id] = status
	s.mu.Unlock()
	go s.reapExec(id, command, cancelStdin)
	if err := ready(status); err != nil {
		gateWriter.Close()
		_ = command.Process.Kill()
		return protocol.ProcessStatus{}, err
	}
	if _, err := gateWriter.Write([]byte{1}); err != nil {
		gateWriter.Close()
		_ = command.Process.Kill()
		return protocol.ProcessStatus{}, err
	}
	gateWriter.Close()
	return status, nil
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

func openWorkloadCgroup(root, workloadID string) (*os.File, error) {
	path := filepath.Join(root, "cengine", workloadID)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workload cgroup for exec: %w", err)
	}
	return file, nil
}

func (s *Supervisor) ExecStatus(id string) protocol.ProcessStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execStatus[id]
}
func (s *Supervisor) SignalExec(id string, signal int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	command := s.execs[id]
	if command == nil || command.Process == nil {
		return errors.New("exec is not running")
	}
	if signal <= 0 || signal >= 65 {
		return syscall.EINVAL
	}
	return unix.Kill(command.Process.Pid, unix.Signal(signal))
}
func (s *Supervisor) WaitExec(id string) protocol.ProcessStatus {
	for {
		status := s.ExecStatus(id)
		if status.Status != "running" {
			return status
		}
		_ = unix.Nanosleep(&unix.Timespec{Nsec: 20_000_000}, nil)
	}
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
	delete(s.execs, id)
	s.execStatus[id] = protocol.ProcessStatus{Status: "exited", ExitCode: &code}
	s.mu.Unlock()
}
