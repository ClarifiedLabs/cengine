//go:build linux

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dev.cengine/guest/internal/disk"
	guestnetwork "dev.cengine/guest/internal/network"
	"dev.cengine/guest/internal/protocol"
	"dev.cengine/guest/internal/volume"
	"golang.org/x/sys/unix"
)

const stage2Argument = "cengine-workload-stage2"

type Supervisor struct {
	mu         sync.Mutex
	spec       *protocol.WorkloadSpec
	command    *exec.Cmd
	status     protocol.ProcessStatus
	waiters    []chan protocol.ProcessStatus
	execs      map[string]*exec.Cmd
	execStatus map[string]protocol.ProcessStatus
}

func New() *Supervisor {
	return &Supervisor{status: protocol.ProcessStatus{Status: "empty"}, execs: map[string]*exec.Cmd{}, execStatus: map[string]protocol.ProcessStatus{}}
}

func IsStage2(arguments []string) bool {
	return len(arguments) == 2 && arguments[1] == stage2Argument
}

func RunStage2() error {
	file := os.NewFile(3, "workload-spec")
	if file == nil {
		return errors.New("workload specification file descriptor is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, protocol.MaxControlFrame))
	if err != nil {
		return err
	}
	var spec protocol.WorkloadSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("decode workload specification: %w", err)
	}
	gate := os.NewFile(4, "network-ready")
	if gate == nil {
		return errors.New("network readiness file descriptor is unavailable")
	}
	defer gate.Close()
	if err := enterPlacedCgroupNamespace(gate, unix.Unshare); err != nil {
		return err
	}
	return enterWorkload(spec)
}

func enterPlacedCgroupNamespace(gate io.Reader, unshare func(int) error) error {
	var ready [1]byte
	if _, err := io.ReadFull(gate, ready[:]); err != nil {
		return fmt.Errorf("wait for workload placement: %w", err)
	}
	if err := unshare(unix.CLONE_NEWCGROUP); err != nil {
		return fmt.Errorf("create cgroup namespace: %w", err)
	}
	return nil
}

func (s *Supervisor) Prepare(spec protocol.WorkloadSpec) error {
	if spec.ID == "" || spec.RootDevice == "" || len(spec.Arguments) == 0 {
		return errors.New("workload requires id, rootDevice, and arguments")
	}
	if err := validateVolumeMounts(spec); err != nil {
		return err
	}
	for _, mount := range spec.Mounts {
		if mount.Kind == "volume" && mount.Device == "" {
			if err := volume.MountNFS(spec.VolumeServer); err != nil {
				return err
			}
			break
		}
	}
	for _, mount := range spec.Mounts {
		if mount.Kind != "volume" {
			continue
		}
		if err := prepareVolume(mount); err != nil {
			return err
		}
	}
	if err := disk.EnsureExt4(spec.RootDevice, "/run/cengine/rootfs", "cengine-root"); err != nil {
		return err
	}
	for _, mount := range spec.Mounts {
		if mount.Kind == "volume" && !mount.NoCopy {
			if err := initializeVolume(spec, mount); err != nil {
				return fmt.Errorf("initialize volume %s: %w", mount.Source, err)
			}
		}
	}
	if err := os.MkdirAll("/run/cengine/io", 0755); err != nil {
		return err
	}
	if err := unix.Mount("cengine-io", "/run/cengine/io", "virtiofs", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
		return fmt.Errorf("mount cengine I/O share: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command != nil {
		return errors.New("cannot replace a running workload")
	}
	s.spec = &spec
	s.status = protocol.ProcessStatus{Status: "prepared"}
	return nil
}

func validateVolumeMounts(spec protocol.WorkloadSpec) error {
	for _, mount := range spec.Mounts {
		if mount.Kind == "volume" && mount.Device == "" && spec.VolumeServer == "" {
			return fmt.Errorf("shared volume %s has no volume server", mount.Source)
		}
	}
	return nil
}

func prepareVolume(mount protocol.Mount) error {
	if mount.Source == "" || mount.Source == "." || mount.Source == ".." || strings.ContainsRune(mount.Source, '/') {
		return fmt.Errorf("invalid volume name %q", mount.Source)
	}
	if mount.Device == "" {
		_, err := volume.Ensure(mount.Source)
		return err
	}
	return disk.EnsureExt4(mount.Device, filepath.Join("/run/cengine/volumes", mount.Source), "cengine-volume")
}

func (s *Supervisor) Start() (protocol.ProcessStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.spec == nil {
		return s.status, errors.New("workload is not prepared")
	}
	if s.command != nil {
		return s.status, errors.New("workload is already running")
	}
	data, err := json.Marshal(s.spec)
	if err != nil {
		return s.status, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return s.status, err
	}
	gateReader, gateWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		return s.status, err
	}
	command := exec.Command("/proc/self/exe", stage2Argument)
	command.ExtraFiles = []*os.File{reader, gateReader}
	stdout, err := os.OpenFile("/run/cengine/io/stdout", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return s.status, err
	}
	var stderr *os.File
	var stdinReader *io.PipeReader
	var stdinWriter *io.PipeWriter
	var terminalMaster *os.File
	var terminalSlave *os.File
	if s.spec.Terminal {
		terminalMaster, terminalSlave, err = openPseudoTerminal()
		if err != nil {
			stdout.Close()
			reader.Close()
			writer.Close()
			gateReader.Close()
			gateWriter.Close()
			return s.status, err
		}
		command.Stdin = terminalSlave
		command.Stdout = terminalSlave
		command.Stderr = terminalSlave
	} else {
		stderr, err = os.OpenFile("/run/cengine/io/stderr", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			stdout.Close()
			reader.Close()
			writer.Close()
			gateReader.Close()
			gateWriter.Close()
			return s.status, err
		}
		stdinReader, stdinWriter = io.Pipe()
		command.Stdin = stdinReader
		command.Stdout = stdout
		command.Stderr = stderr
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWNET,
		Pdeathsig:  unix.SIGKILL,
	}
	if s.spec.Terminal {
		command.SysProcAttr.Setsid = true
		command.SysProcAttr.Setctty = true
		command.SysProcAttr.Ctty = 0
	}
	if err := command.Start(); err != nil {
		stdout.Close()
		if stderr != nil {
			stderr.Close()
		}
		if stdinReader != nil {
			stdinReader.Close()
		}
		if stdinWriter != nil {
			stdinWriter.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		if terminalSlave != nil {
			terminalSlave.Close()
		}
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return s.status, err
	}
	if terminalSlave != nil {
		terminalSlave.Close()
		go pumpTerminalOutput(terminalMaster, stdout, command)
	} else {
		stdout.Close()
		stderr.Close()
	}
	reader.Close()
	gateReader.Close()
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	writer.Close()
	if err := applyCgroup(s.spec, command.Process.Pid); err != nil {
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	if err := guestnetwork.Attach(command.Process.Pid, s.spec.Networks); err != nil {
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	if _, err := gateWriter.Write([]byte{1}); err != nil {
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	gateWriter.Close()
	s.command = command
	s.status = protocol.ProcessStatus{Status: "running", PID: command.Process.Pid}
	go s.reap(command)
	if terminalMaster != nil {
		go pumpTerminalInput("/run/cengine/io/stdin", terminalMaster, command)
	} else {
		go pumpInput("/run/cengine/io/stdin", stdinWriter, command)
	}
	return s.status, nil
}

func openPseudoTerminal() (*os.File, *os.File, error) {
	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	master := os.NewFile(uintptr(masterFD), "ptmx")
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, err
	}
	number, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	_ = unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80})
	return master, slave, nil
}

func pumpTerminalOutput(master, destination *os.File, command *exec.Cmd) {
	defer master.Close()
	defer destination.Close()
	buffer := make([]byte, 32*1024)
	for {
		count, err := master.Read(buffer)
		if count > 0 {
			if _, writeErr := destination.Write(buffer[:count]); writeErr != nil {
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, unix.EIO) && command.ProcessState == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return
	}
}

func pumpTerminalInput(path string, destination io.Writer, command *exec.Cmd) {
	var offset int64
	for {
		file, err := os.Open(path)
		if err == nil {
			_, _ = file.Seek(offset, io.SeekStart)
			written, _ := io.Copy(destination, file)
			offset += written
			file.Close()
		}
		if _, err := os.Stat(path + ".closed"); err == nil {
			return
		}
		if command.ProcessState != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func applyCgroup(spec *protocol.WorkloadSpec, pid int) error {
	root := "/sys/fs/cgroup"
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	if err := unix.Mount("none", root, "cgroup2", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
		return fmt.Errorf("mount cgroup2: %w", err)
	}
	if err := enableCgroupControllers(root); err != nil {
		return err
	}
	parent := filepath.Join(root, "cengine")
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	if err := enableCgroupControllers(parent); err != nil {
		return err
	}
	path := filepath.Join(parent, spec.ID)
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	if err := writeCgroupResourceLimits(path, spec.Resources, true); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)
}

type cgroupResourceLimit struct {
	name  string
	value string
}

func cgroupResourceLimits(resources protocol.Resources) []cgroupResourceLimit {
	memory := "max"
	if resources.MemoryBytes > 0 {
		memory = fmt.Sprint(resources.MemoryBytes)
	}
	cpu := "max"
	if resources.CPUQuota > 0 && resources.CPUPeriod > 0 {
		cpu = fmt.Sprintf("%d %d", resources.CPUQuota, resources.CPUPeriod)
	}
	pids := "max"
	if resources.PIDs > 0 {
		pids = fmt.Sprint(resources.PIDs)
	}
	return []cgroupResourceLimit{
		{name: "memory.max", value: memory},
		{name: "cpu.max", value: cpu},
		{name: "pids.max", value: pids},
	}
}

func writeCgroupResourceLimits(path string, resources protocol.Resources, ignoreMissing bool) error {
	return replaceCgroupResourceLimits(path, resources, ignoreMissing, os.ReadFile, os.WriteFile)
}

func replaceCgroupResourceLimits(
	path string,
	resources protocol.Resources,
	ignoreMissing bool,
	readFile func(string) ([]byte, error),
	writeFile func(string, []byte, os.FileMode) error,
) error {
	type previousValue struct {
		path  string
		value []byte
	}
	previous := []previousValue{}
	for _, limit := range cgroupResourceLimits(resources) {
		file := filepath.Join(path, limit.name)
		old, err := readFile(file)
		if errors.Is(err, os.ErrNotExist) && ignoreMissing {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", limit.name, err)
		}
		if err := writeFile(file, []byte(limit.value), 0644); err != nil {
			for index := len(previous) - 1; index >= 0; index-- {
				_ = writeFile(previous[index].path, previous[index].value, 0644)
			}
			return fmt.Errorf("update %s: %w", limit.name, err)
		}
		previous = append(previous, previousValue{path: file, value: old})
	}
	return nil
}

func (s *Supervisor) UpdateResources(resources protocol.Resources) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command == nil || s.command.Process == nil || s.spec == nil || s.status.Status != "running" {
		return errors.New("workload is not running")
	}
	path := filepath.Join("/sys/fs/cgroup/cengine", s.spec.ID)
	if err := writeCgroupResourceLimits(path, resources, false); err != nil {
		return err
	}
	s.spec.Resources = resources
	return nil
}

func enableCgroupControllers(path string) error {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup controllers at %s: %w", path, err)
	}
	available := map[string]bool{}
	for _, name := range strings.Fields(string(data)) {
		available[name] = true
	}
	directives := []string{}
	for _, name := range []string{"cpu", "memory", "pids"} {
		if available[name] {
			directives = append(directives, "+"+name)
		}
	}
	if len(directives) == 0 {
		return fmt.Errorf("cgroup at %s exposes none of the required cpu, memory, or pids controllers", path)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), []byte(strings.Join(directives, " ")), 0644); err != nil {
		return fmt.Errorf("enable cgroup controllers at %s: %w", path, err)
	}
	return nil
}

func pumpInput(path string, destination *io.PipeWriter, command *exec.Cmd) {
	defer destination.Close()
	var offset int64
	for {
		file, err := os.Open(path)
		if err == nil {
			_, _ = file.Seek(offset, io.SeekStart)
			written, _ := io.Copy(destination, file)
			offset += written
			file.Close()
		}
		if _, err := os.Stat(path + ".closed"); err == nil {
			return
		}
		if command.ProcessState != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *Supervisor) Signal(signal int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command == nil || s.command.Process == nil {
		return errors.New("workload is not running")
	}
	if signal <= 0 || signal >= 65 {
		return fmt.Errorf("invalid signal %d", signal)
	}
	return unix.Kill(s.command.Process.Pid, unix.Signal(signal))
}

func (s *Supervisor) Status() protocol.ProcessStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Supervisor) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command == nil || s.command.Process == nil {
		return 0
	}
	return s.command.Process.Pid
}

func (s *Supervisor) ConnectNetwork(endpoint protocol.NetworkEndpoint) error {
	s.mu.Lock()
	if s.spec == nil {
		s.mu.Unlock()
		return errors.New("workload is not prepared")
	}
	found := false
	for index := range s.spec.Networks {
		if s.spec.Networks[index].NetworkID == endpoint.NetworkID {
			s.spec.Networks[index] = endpoint
			found = true
			break
		}
	}
	if !found {
		s.spec.Networks = append(s.spec.Networks, endpoint)
	}
	pid := 0
	if s.command != nil && s.command.Process != nil {
		pid = s.command.Process.Pid
	}
	s.mu.Unlock()
	if pid == 0 {
		return nil
	}
	return guestnetwork.AttachOne(pid, endpoint)
}

func (s *Supervisor) DisconnectNetwork(name string) error {
	s.mu.Lock()
	if s.spec == nil {
		s.mu.Unlock()
		return errors.New("workload is not prepared")
	}
	filtered := s.spec.Networks[:0]
	interfaceName := name
	for _, endpoint := range s.spec.Networks {
		if endpoint.NetworkID == name || endpoint.Name == name {
			interfaceName = endpoint.Name
			continue
		}
		filtered = append(filtered, endpoint)
	}
	s.spec.Networks = filtered
	pid := 0
	if s.command != nil && s.command.Process != nil {
		pid = s.command.Process.Pid
	}
	s.mu.Unlock()
	if pid == 0 {
		return nil
	}
	return guestnetwork.Remove(pid, interfaceName)
}

func (s *Supervisor) Wait() protocol.ProcessStatus {
	s.mu.Lock()
	if s.command == nil {
		status := s.status
		s.mu.Unlock()
		return status
	}
	waiter := make(chan protocol.ProcessStatus, 1)
	s.waiters = append(s.waiters, waiter)
	s.mu.Unlock()
	return <-waiter
}

func (s *Supervisor) reap(command *exec.Cmd) {
	err := command.Wait()
	unix.Sync()
	exitCode := 255
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
		if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			exitCode = 128 + int(status.Signal())
		}
	}
	if err == nil && exitCode < 0 {
		exitCode = 0
	}
	s.mu.Lock()
	s.command = nil
	s.status = protocol.ProcessStatus{Status: "exited", ExitCode: &exitCode}
	waiters := s.waiters
	s.waiters = nil
	status := s.status
	s.mu.Unlock()
	for _, waiter := range waiters {
		waiter <- status
		close(waiter)
	}
}

func enterWorkload(spec protocol.WorkloadSpec) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	root := "/run/cengine/rootfs"
	if err := disk.EnsureExt4(spec.RootDevice, root, "cengine-root"); err != nil {
		return err
	}
	if err := writeNetworkFiles(root, spec); err != nil {
		return err
	}
	workingDirectory := spec.WorkingDirectory
	if workingDirectory == "" {
		workingDirectory = "/"
	}
	if err := os.MkdirAll(filepath.Join(root, filepath.Clean("/"+workingDirectory)), 0755); err != nil {
		return err
	}
	for _, mount := range spec.Mounts {
		if err := applyMount(root, mount); err != nil {
			return fmt.Errorf("mount %s: %w", mount.Destination, err)
		}
	}
	for _, directory := range []string{"proc", "sys", "dev", "run", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0755); err != nil {
			return err
		}
	}
	if spec.ReadOnlyRoot {
		if err := unix.Mount("", root, "", unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return fmt.Errorf("remount root device read-only: %w", err)
		}
	}
	for _, directory := range []string{"proc", "sys", "dev", "run", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0755); err != nil {
			return err
		}
	}
	if err := unix.Mount("proc", filepath.Join(root, "proc"), "proc", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil {
		return err
	}
	sysFlags := uintptr(unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV)
	if err := unix.Mount("sysfs", filepath.Join(root, "sys"), "sysfs", sysFlags, ""); err != nil {
		return err
	}
	devKind := "tmpfs"
	devSource := "tmpfs"
	devData := "mode=755"
	if spec.Privileged {
		devKind = "devtmpfs"
		devSource = "devtmpfs"
		devData = "mode=755"
	}
	if err := unix.Mount(devSource, filepath.Join(root, "dev"), devKind, unix.MS_NOSUID, devData); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "dev/pts"), 0755); err != nil {
		return err
	}
	if err := unix.Mount("devpts", filepath.Join(root, "dev/pts"), "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(root, "dev/ptmx"))
	if err := os.Symlink("pts/ptmx", filepath.Join(root, "dev/ptmx")); err != nil {
		return err
	}
	if err := createStandardDeviceSymlinks(root); err != nil {
		return err
	}
	if err := configureContainerConsole(root, spec.Terminal); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "dev/shm"), 01777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", filepath.Join(root, "dev/shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=67108864"); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "dev/mqueue"), 0755); err != nil {
		return err
	}
	if err := unix.Mount("mqueue", filepath.Join(root, "dev/mqueue"), "mqueue", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil && !errors.Is(err, unix.ENODEV) {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/fs/cgroup"), 0755); err != nil {
		return err
	}
	if err := unix.Mount("none", filepath.Join(root, "sys/fs/cgroup"), "cgroup2", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
		return err
	}
	if !spec.Privileged {
		_ = remountCgroupReadOnly(filepath.Join(root, "sys/fs/cgroup"), unix.Mount)
		_ = unix.Mount("", filepath.Join(root, "sys"), "", unix.MS_REMOUNT|unix.MS_RDONLY, "")
	}
	for _, device := range []struct {
		name string
		mode uint32
		dev  int
	}{
		{"null", unix.S_IFCHR | 0666, int(unix.Mkdev(1, 3))},
		{"zero", unix.S_IFCHR | 0666, int(unix.Mkdev(1, 5))},
		{"full", unix.S_IFCHR | 0666, int(unix.Mkdev(1, 7))},
		{"random", unix.S_IFCHR | 0666, int(unix.Mkdev(1, 8))},
		{"urandom", unix.S_IFCHR | 0666, int(unix.Mkdev(1, 9))},
		{"tty", unix.S_IFCHR | 0666, int(unix.Mkdev(5, 0))},
	} {
		if err := unix.Mknod(filepath.Join(root, "dev", device.name), device.mode, device.dev); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		if err := unix.Chmod(filepath.Join(root, "dev", device.name), device.mode&07777); err != nil {
			return err
		}
	}
	if spec.Hostname != "" {
		if err := unix.Sethostname([]byte(spec.Hostname)); err != nil {
			return err
		}
	}
	if err := unix.Chroot(root); err != nil {
		return err
	}
	if err := startSocketProxies(spec.Mounts); err != nil {
		return err
	}
	workingDirectory = spec.WorkingDirectory
	if workingDirectory == "" {
		workingDirectory = "/"
	}
	if err := os.MkdirAll(workingDirectory, 0755); err != nil {
		return err
	}
	if err := os.Chdir(workingDirectory); err != nil {
		return err
	}
	uid, gid, namedGroups, err := resolveUser(spec.User)
	if err != nil {
		return err
	}
	groups := make([]int, 0, len(spec.User.AdditionalGroups)+len(namedGroups))
	for index, group := range spec.User.AdditionalGroups {
		_ = index
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
	if !spec.Privileged {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
	}
	unix.Umask(0022)
	environment := processEnvironment(spec.Environment, spec.Hostname, homeDirectory(uid), spec.Terminal)
	os.Clearenv()
	for _, value := range environment {
		pair := []byte(value)
		for index, character := range pair {
			if character == '=' {
				if err := os.Setenv(string(pair[:index]), string(pair[index+1:])); err != nil {
					return err
				}
				break
			}
		}
	}
	path, err := exec.LookPath(spec.Arguments[0])
	if err != nil {
		return err
	}
	return unix.Exec(path, spec.Arguments, environment)
}

func remountCgroupReadOnly(path string, mount func(string, string, string, uintptr, string) error) error {
	return mount("", path, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
}

func createStandardDeviceSymlinks(root string) error {
	links := map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1",
		"stderr": "/proc/self/fd/2",
	}
	for name, target := range links {
		path := filepath.Join(root, "dev", name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Symlink(target, path); err != nil {
			return err
		}
	}
	return nil
}

func configureContainerConsole(root string, terminal bool) error {
	path := filepath.Join(root, "dev", "console")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !terminal {
		return os.Symlink("/proc/1/fd/1", path)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	source, err := os.Readlink("/proc/self/fd/0")
	if err != nil {
		return fmt.Errorf("resolve terminal console: %w", err)
	}
	if err := unix.Mount(source, path, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("mount terminal console: %w", err)
	}
	return nil
}

func resolveUser(user protocol.User) (int, int, []int, error) {
	if user.Username == "" {
		return int(user.UID), int(user.GID), nil, nil
	}
	parts := strings.SplitN(user.Username, ":", 2)
	name := parts[0]
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, 0, nil, err
	}
	uid, gid := -1, -1
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && fields[0] == name {
			uid, _ = strconv.Atoi(fields[2])
			gid, _ = strconv.Atoi(fields[3])
			break
		}
	}
	if uid < 0 {
		return 0, 0, nil, fmt.Errorf("user %s not found", name)
	}
	if len(parts) == 2 && parts[1] != "" {
		if value, parseErr := strconv.Atoi(parts[1]); parseErr == nil {
			gid = value
		} else {
			groupData, _ := os.ReadFile("/etc/group")
			for _, line := range strings.Split(string(groupData), "\n") {
				fields := strings.Split(line, ":")
				if len(fields) >= 3 && fields[0] == parts[1] {
					gid, _ = strconv.Atoi(fields[2])
					break
				}
			}
		}
	}
	var groups []int
	groupData, _ := os.ReadFile("/etc/group")
	for _, line := range strings.Split(string(groupData), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && containsString(strings.Split(fields[3], ","), name) {
			if value, err := strconv.Atoi(fields[2]); err == nil && value != gid {
				groups = append(groups, value)
			}
		}
	}
	return uid, gid, groups, nil
}
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func initializeVolume(spec protocol.WorkloadSpec, mount protocol.Mount) error {
	destination := filepath.Join("/run/cengine/volumes", mount.Source)
	empty, err := dockerVolumeIsEmpty(destination)
	if err != nil {
		return err
	}
	if !empty {
		return nil
	}
	source := filepath.Join("/run/cengine/rootfs", filepath.Clean("/"+mount.Destination))
	info, err := os.Stat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	sourceEntries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range sourceEntries {
		if err := copyVolumeEntry(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func dockerVolumeIsEmpty(destination string) (bool, error) {
	entries, err := os.ReadDir(destination)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() != "lost+found" {
			return false, nil
		}
	}
	return true, nil
}
func copyVolumeEntry(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(destination, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyVolumeEntry(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
	} else if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(source)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, destination); err != nil {
			return err
		}
	} else if info.Mode().IsRegular() {
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(destination, int(stat.Uid), int(stat.Gid))
	}
	return nil
}

func writeNetworkFiles(root string, spec protocol.WorkloadSpec) error {
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		return err
	}
	hosts := "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n"
	keys := make([]string, 0, len(spec.Hosts))
	for name := range spec.Hosts {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		if name != "" && spec.Hosts[name] != "" {
			hosts += spec.Hosts[name] + " " + name + "\n"
		}
	}
	if spec.Hostname != "" {
		for _, endpoint := range spec.Networks {
			if len(endpoint.Addresses) > 0 {
				hosts += strings.Split(endpoint.Addresses[0], "/")[0] + " " + spec.Hostname + "\n"
				break
			}
		}
	}
	if err := os.RemoveAll(filepath.Join(root, "etc/hosts")); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "etc/hosts"), []byte(hosts), 0644); err != nil {
		return err
	}
	var nameservers []string
	seen := map[string]bool{}
	for _, endpoint := range spec.Networks {
		for _, address := range endpoint.DNS {
			if address != "" && !seen[address] {
				nameservers = append(nameservers, address)
				seen[address] = true
			}
		}
	}
	if len(nameservers) == 0 {
		nameservers = []string{"1.1.1.1"}
	}
	resolv := "options ndots:0\n"
	for _, server := range nameservers {
		resolv += "nameserver " + server + "\n"
	}
	if err := os.RemoveAll(filepath.Join(root, "etc/resolv.conf")); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "etc/resolv.conf"), []byte(resolv), 0644)
}

func applyMount(root string, mount protocol.Mount) error {
	destination := filepath.Join(root, filepath.Clean("/"+mount.Destination))
	if !filepath.IsAbs(mount.Destination) || destination == root {
		return errors.New("mount destination must be an absolute non-root path")
	}
	flags := uintptr(0)
	if mount.ReadOnly {
		flags |= unix.MS_RDONLY
	}
	switch mount.Kind {
	case "tmpfs":
		if err := os.MkdirAll(destination, 0755); err != nil {
			return err
		}
		return unix.Mount("tmpfs", destination, "tmpfs", flags|unix.MS_NOSUID|unix.MS_NODEV, joinOptions(mount.Options))
	case "bind":
		staging := filepath.Join("/run/cengine/binds", mount.Source)
		if err := os.MkdirAll(staging, 0755); err != nil {
			return err
		}
		if err := unix.Mount(mount.Source, staging, "virtiofs", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return err
		}
		source, err := mountSubpath(staging, mount.Subpath)
		if err != nil {
			return err
		}
		if err := prepareMountpoint(source, destination); err != nil {
			return err
		}
		if err := unix.Mount(source, destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return err
		}
		if mount.ReadOnly {
			return unix.Mount("", destination, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
		}
		return nil
	case "socket":
		return nil
	case "volume":
		staging := filepath.Join("/run/cengine/volumes", mount.Source)
		source, err := mountSubpath(staging, mount.Subpath)
		if err != nil {
			return err
		}
		if err := prepareMountpoint(source, destination); err != nil {
			return err
		}
		if err := unix.Mount(source, destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return err
		}
		if mount.ReadOnly {
			return unix.Mount("", destination, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
		}
		return nil
	default:
		return fmt.Errorf("unsupported mount kind %q", mount.Kind)
	}
}

func mountSubpath(root, subpath string) (string, error) {
	if subpath == "" {
		return root, nil
	}
	clean := filepath.Clean(subpath)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("mount subpath escapes source")
	}
	target := filepath.Join(root, clean)
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", errors.New("mount subpath escapes source")
	}
	return target, nil
}
func prepareMountpoint(source, destination string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.MkdirAll(destination, 0755)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_RDONLY, 0644)
	if err == nil {
		err = file.Close()
	}
	return err
}

func joinOptions(options []string) string {
	result := ""
	for _, option := range options {
		if result != "" {
			result += ","
		}
		result += option
	}
	return result
}
