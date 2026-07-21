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
	"runtime"
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
const workloadReadyFD = 5

type Supervisor struct {
	mu          sync.Mutex
	spec        *protocol.WorkloadSpec
	command     *exec.Cmd
	status      protocol.ProcessStatus
	waiters     []chan protocol.ProcessStatus
	execs       map[string]*exec.Cmd
	execTargets map[string]int
	execCgroups map[string]string
	execStatus  map[string]protocol.ProcessStatus
	processIO   *pinnedProcessIO
	execIO      map[string]*pinnedProcessIO
	execSpecs   map[string]protocol.ExecSpec
}

func New() *Supervisor {
	return &Supervisor{
		status:      protocol.ProcessStatus{Status: "empty"},
		execs:       map[string]*exec.Cmd{},
		execTargets: map[string]int{},
		execCgroups: map[string]string{},
		execStatus:  map[string]protocol.ProcessStatus{},
		execIO:      map[string]*pinnedProcessIO{},
		execSpecs:   map[string]protocol.ExecSpec{},
	}
}

func IsStage2(arguments []string) bool {
	return len(arguments) == 2 && arguments[1] == stage2Argument
}

func RunStage2() error {
	// Capability, credential, namespace, and no-new-privileges state is scoped
	// to the calling Linux thread. Keep the goroutine pinned until unix.Exec
	// replaces that thread with the workload.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
	ready := os.NewFile(workloadReadyFD, "workload-ready")
	if ready == nil {
		return errors.New("workload readiness file descriptor is unavailable")
	}
	defer ready.Close()
	unix.CloseOnExec(workloadReadyFD)
	return enterWorkload(spec, ready)
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
	processIO, err := openPinnedProcessIO(ioDirectoryPath, "", spec.IOClaim)
	if err != nil {
		return fmt.Errorf("pin workload I/O: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command != nil {
		processIO.close()
		return errors.New("cannot replace a running workload")
	}
	if s.processIO != nil {
		s.processIO.close()
	}
	s.spec = &spec
	s.processIO = processIO
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
	if s.processIO == nil {
		return s.status, errors.New("workload I/O is not prepared")
	}
	processIO := s.processIO
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
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		gateReader.Close()
		gateWriter.Close()
		return s.status, err
	}
	command := exec.Command("/proc/self/exe", stage2Argument)
	command.ExtraFiles = []*os.File{reader, gateReader, readyWriter}
	stdout, err := duplicateFile(processIO.stdout, "stdout")
	if err != nil {
		readyReader.Close()
		readyWriter.Close()
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
			readyReader.Close()
			readyWriter.Close()
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
		stderr, err = duplicateFile(processIO.stderr, "stderr")
		if err != nil {
			readyReader.Close()
			readyWriter.Close()
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
		readyReader.Close()
		readyWriter.Close()
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
	readyWriter.Close()
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
		readyReader.Close()
		writer.Close()
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	writer.Close()
	if err := applyCgroup(s.spec, command.Process.Pid); err != nil {
		readyReader.Close()
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	if err := guestnetwork.Attach(command.Process.Pid, s.spec.Networks); err != nil {
		readyReader.Close()
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	if _, err := gateWriter.Write([]byte{1}); err != nil {
		readyReader.Close()
		gateWriter.Close()
		_ = command.Process.Kill()
		return s.status, err
	}
	gateWriter.Close()
	var ready [1]byte
	if _, err := io.ReadFull(readyReader, ready[:]); err != nil {
		readyReader.Close()
		if stdinWriter != nil {
			stdinWriter.Close()
		}
		if terminalMaster != nil {
			terminalMaster.Close()
		}
		_ = command.Wait()
		return s.status, fmt.Errorf("workload failed before becoming ready: %w", err)
	}
	readyReader.Close()
	s.command = command
	s.status = protocol.ProcessStatus{Status: "running", PID: command.Process.Pid}
	go s.reap(command)
	if terminalMaster != nil {
		go pumpTerminalInput(processIO.stdin, processIO.stdinClosed, terminalMaster, command)
	} else {
		go pumpInput(processIO.stdin, processIO.stdinClosed, stdinWriter, command)
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

func pumpTerminalInput(source, closed *os.File, destination io.Writer, command *exec.Cmd) {
	for {
		inputClosed, err := pumpInputStep(source, closed, destination)
		if err != nil || inputClosed {
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
	requireIO := hasBlockIOLimits(spec.Resources)
	if err := enableCgroupControllers(root, requireIO); err != nil {
		return err
	}
	parent := filepath.Join(root, "cengine")
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	if err := enableCgroupControllers(parent, requireIO); err != nil {
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

type cgroupIOValue struct {
	device string
	key    string
	value  string
}

// ResourceRollbackIncompleteError means a resource update failed and at least
// one best-effort restoration write failed too. Callers must treat the
// workload's live cgroup state as unknown and stop or recreate it from durable
// resources before reporting it as running again.
type ResourceRollbackIncompleteError struct {
	UpdateError    error
	RollbackErrors []error
}

func (e *ResourceRollbackIncompleteError) Error() string {
	details := make([]string, 0, len(e.RollbackErrors))
	for _, err := range e.RollbackErrors {
		details = append(details, err.Error())
	}
	return fmt.Sprintf(
		"resource update failed (%v); rollback incomplete (%s)",
		e.UpdateError, strings.Join(details, "; "),
	)
}

func (e *ResourceRollbackIncompleteError) Unwrap() error { return e.UpdateError }

func hasBlockIOLimits(resources protocol.Resources) bool {
	return len(resources.BlockIOReadBps) > 0 || len(resources.BlockIOWriteBps) > 0 ||
		len(resources.BlockIOReadIOps) > 0 || len(resources.BlockIOWriteIOps) > 0
}

func resolveBlockDevice(path string) (string, error) {
	return resolveBlockDeviceWithStat(path, unix.Stat)
}

func resolveBlockDeviceWithStat(path string, stat func(string, *unix.Stat_t) error) (string, error) {
	if path != "/dev/vda" {
		return "", fmt.Errorf("block I/O throttle path %q is not the VM root device /dev/vda", path)
	}
	var status unix.Stat_t
	if err := stat(path, &status); err != nil {
		return "", fmt.Errorf("stat block I/O throttle device %s: %w", path, err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFBLK {
		return "", fmt.Errorf("block I/O throttle device %s is not a block device", path)
	}
	return fmt.Sprintf("%d:%d", unix.Major(uint64(status.Rdev)), unix.Minor(uint64(status.Rdev))), nil
}

func desiredIOMax(
	resources protocol.Resources, resolveDevice func(string) (string, error),
) (map[string]map[string]string, error) {
	desired := map[string]map[string]string{}
	types := []struct {
		key    string
		limits []protocol.BlockIOThrottle
	}{
		{key: "rbps", limits: resources.BlockIOReadBps},
		{key: "wbps", limits: resources.BlockIOWriteBps},
		{key: "riops", limits: resources.BlockIOReadIOps},
		{key: "wiops", limits: resources.BlockIOWriteIOps},
	}
	resolved := map[string]string{}
	for _, throttleType := range types {
		seen := map[string]bool{}
		for _, limit := range throttleType.limits {
			if limit.Rate == 0 {
				return nil, fmt.Errorf("block I/O throttle %s for %q must be positive", throttleType.key, limit.Path)
			}
			if seen[limit.Path] {
				return nil, fmt.Errorf("duplicate block I/O throttle %s path %q", throttleType.key, limit.Path)
			}
			seen[limit.Path] = true
			device, ok := resolved[limit.Path]
			if !ok {
				var err error
				device, err = resolveDevice(limit.Path)
				if err != nil {
					return nil, err
				}
				resolved[limit.Path] = device
			}
			if desired[device] == nil {
				desired[device] = map[string]string{}
			}
			if _, duplicate := desired[device][throttleType.key]; duplicate {
				return nil, fmt.Errorf("duplicate block I/O throttle %s device %s", throttleType.key, device)
			}
			desired[device][throttleType.key] = strconv.FormatUint(limit.Rate, 10)
		}
	}
	return desired, nil
}

func parseIOMax(data []byte) (map[string]map[string]string, error) {
	result := map[string]map[string]string{}
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		deviceParts := strings.Split(fields[0], ":")
		if len(deviceParts) != 2 {
			return nil, fmt.Errorf("parse io.max line %d: invalid device %q", lineNumber+1, fields[0])
		}
		if _, err := strconv.ParseUint(deviceParts[0], 10, 32); err != nil {
			return nil, fmt.Errorf("parse io.max line %d: invalid major number", lineNumber+1)
		}
		if _, err := strconv.ParseUint(deviceParts[1], 10, 32); err != nil {
			return nil, fmt.Errorf("parse io.max line %d: invalid minor number", lineNumber+1)
		}
		if result[fields[0]] == nil {
			result[fields[0]] = map[string]string{}
		}
		for _, field := range fields[1:] {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) != 2 || !isIOMaxKey(parts[0]) || (parts[1] != "max" && !isPositiveDecimal(parts[1])) {
				return nil, fmt.Errorf("parse io.max line %d: invalid limit %q", lineNumber+1, field)
			}
			if _, duplicate := result[fields[0]][parts[0]]; duplicate {
				return nil, fmt.Errorf("parse io.max line %d: duplicate key %s", lineNumber+1, parts[0])
			}
			result[fields[0]][parts[0]] = parts[1]
		}
	}
	return result, nil
}

func isIOMaxKey(value string) bool {
	return value == "rbps" || value == "wbps" || value == "riops" || value == "wiops"
}

func isPositiveDecimal(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0
}

func ioMaxChanges(current, desired map[string]map[string]string) []cgroupIOValue {
	devices := map[string]bool{}
	for device := range current {
		devices[device] = true
	}
	for device := range desired {
		devices[device] = true
	}
	deviceNames := make([]string, 0, len(devices))
	for device := range devices {
		deviceNames = append(deviceNames, device)
	}
	sort.Strings(deviceNames)
	changes := []cgroupIOValue{}
	for _, device := range deviceNames {
		for _, key := range []string{"rbps", "wbps", "riops", "wiops"} {
			oldValue := "max"
			if value := current[device][key]; value != "" {
				oldValue = value
			}
			newValue := "max"
			if value := desired[device][key]; value != "" {
				newValue = value
			}
			if oldValue != newValue {
				changes = append(changes, cgroupIOValue{device: device, key: key, value: newValue})
			}
		}
	}
	return changes
}

func replaceCgroupResourceLimits(
	path string,
	resources protocol.Resources,
	ignoreMissing bool,
	readFile func(string) ([]byte, error),
	writeFile func(string, []byte, os.FileMode) error,
) error {
	return replaceCgroupResourceLimitsWithResolver(
		path, resources, ignoreMissing, readFile, writeFile, resolveBlockDevice,
	)
}

func replaceCgroupResourceLimitsWithResolver(
	path string,
	resources protocol.Resources,
	ignoreMissing bool,
	readFile func(string) ([]byte, error),
	writeFile func(string, []byte, os.FileMode) error,
	resolveDevice func(string) (string, error),
) error {
	return replaceCgroupResourceLimitsWithResolverAndFailure(
		path, resources, ignoreMissing, readFile, writeFile, resolveDevice, 0,
	)
}

func replaceCgroupResourceLimitsWithResolverAndFailure(
	path string,
	resources protocol.Resources,
	ignoreMissing bool,
	readFile func(string) ([]byte, error),
	writeFile func(string, []byte, os.FileMode) error,
	resolveDevice func(string) (string, error),
	compatibilityFailureAfterWrites uint32,
) error {
	type previousValue struct {
		path  string
		value []byte
	}
	type resourceWrite struct {
		path     string
		name     string
		value    []byte
		previous []byte
	}
	writes := []resourceWrite{}
	for _, limit := range cgroupResourceLimits(resources) {
		file := filepath.Join(path, limit.name)
		old, err := readFile(file)
		if errors.Is(err, os.ErrNotExist) && ignoreMissing {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", limit.name, err)
		}
		writes = append(writes, resourceWrite{
			path: file, name: limit.name, value: []byte(limit.value), previous: old,
		})
	}

	desiredIO, err := desiredIOMax(resources, resolveDevice)
	if err != nil {
		return err
	}
	ioFile := filepath.Join(path, "io.max")
	currentIO := map[string]map[string]string{}
	ioData, err := readFile(ioFile)
	if errors.Is(err, os.ErrNotExist) && !hasBlockIOLimits(resources) {
		ioData = nil
	} else if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("io controller is unavailable for configured block I/O throttles")
	} else if err != nil {
		return fmt.Errorf("read io.max: %w", err)
	} else {
		currentIO, err = parseIOMax(ioData)
		if err != nil {
			return err
		}
	}
	ioChanges := ioMaxChanges(currentIO, desiredIO)
	previous := []previousValue{}
	previousIO := []cgroupIOValue{}
	successfulWrites := uint32(0)
	transactionWrite := func(path string, value []byte, mode os.FileMode) error {
		if compatibilityFailureAfterWrites > 0 && successfulWrites == compatibilityFailureAfterWrites {
			return fmt.Errorf(
				"compatibility injected resource write failure after %d successful writes",
				successfulWrites,
			)
		}
		if err := writeFile(path, value, mode); err != nil {
			return err
		}
		successfulWrites++
		return nil
	}
	rollback := func(updateError error) error {
		rollbackErrors := []error{}
		for index := len(previousIO) - 1; index >= 0; index-- {
			value := previousIO[index]
			directive := fmt.Sprintf("%s %s=%s", value.device, value.key, value.value)
			if err := writeFile(ioFile, []byte(directive), 0644); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf(
					"restore io.max %s %s: %w", value.device, value.key, err,
				))
			}
		}
		for index := len(previous) - 1; index >= 0; index-- {
			if err := writeFile(previous[index].path, previous[index].value, 0644); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf(
					"restore %s: %w", filepath.Base(previous[index].path), err,
				))
			}
		}
		if len(rollbackErrors) != 0 {
			return &ResourceRollbackIncompleteError{
				UpdateError: updateError, RollbackErrors: rollbackErrors,
			}
		}
		return updateError
	}
	for _, write := range writes {
		if err := transactionWrite(write.path, write.value, 0644); err != nil {
			return rollback(fmt.Errorf("update %s: %w", write.name, err))
		}
		previous = append(previous, previousValue{path: write.path, value: write.previous})
	}
	for _, change := range ioChanges {
		directive := fmt.Sprintf("%s %s=%s", change.device, change.key, change.value)
		if err := transactionWrite(ioFile, []byte(directive), 0644); err != nil {
			return rollback(fmt.Errorf("update io.max %s %s: %w", change.device, change.key, err))
		}
		oldValue := "max"
		if value := currentIO[change.device][change.key]; value != "" {
			oldValue = value
		}
		previousIO = append(previousIO, cgroupIOValue{
			device: change.device, key: change.key, value: oldValue,
		})
	}
	return nil
}

func (s *Supervisor) UpdateResources(resources protocol.Resources) error {
	return s.updateResources(resources, 0)
}

func (s *Supervisor) UpdateResourcesWithCompatibilityFailure(
	resources protocol.Resources, failureAfterWrites uint32,
) error {
	return s.updateResources(resources, failureAfterWrites)
}

func (s *Supervisor) updateResources(resources protocol.Resources, failureAfterWrites uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command == nil || s.command.Process == nil || s.spec == nil || s.status.Status != "running" {
		return errors.New("workload is not running")
	}
	path := filepath.Join("/sys/fs/cgroup/cengine", s.spec.ID)
	if err := replaceCgroupResourceLimitsWithResolverAndFailure(
		path, resources, false, os.ReadFile, os.WriteFile, resolveBlockDevice, failureAfterWrites,
	); err != nil {
		return err
	}
	s.spec.Resources = resources
	return nil
}

func enableCgroupControllers(path string, requireIO bool) error {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup controllers at %s: %w", path, err)
	}
	available := map[string]bool{}
	for _, name := range strings.Fields(string(data)) {
		available[name] = true
	}
	directives := []string{}
	if requireIO && !available["io"] {
		return fmt.Errorf("cgroup at %s does not expose the required io controller", path)
	}
	for _, name := range []string{"cpu", "io", "memory", "pids"} {
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

func pumpInput(source, closed *os.File, destination *io.PipeWriter, command *exec.Cmd) {
	defer destination.Close()
	for {
		inputClosed, err := pumpInputStep(source, closed, destination)
		if err != nil || inputClosed {
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

type rootSwitchOperations struct {
	chdir  func(string) error
	mount  func(string, string, string, uintptr, string) error
	chroot func(string) error
}

func switchWorkloadRoot(root string, operations rootSwitchOperations) error {
	if err := operations.chdir(root); err != nil {
		return fmt.Errorf("change to workload root: %w", err)
	}
	// Nested runtimes resolve exec roots from the mount namespace root, so the
	// workload filesystem must replace that root rather than only become a chroot.
	if err := operations.mount(root, "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move workload root mount: %w", err)
	}
	if err := operations.chroot("."); err != nil {
		return fmt.Errorf("chroot workload: %w", err)
	}
	if err := operations.chdir("/"); err != nil {
		return fmt.Errorf("change to workload root directory: %w", err)
	}
	return nil
}

func enterWorkload(spec protocol.WorkloadSpec, ready io.Writer) error {
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
	if err := mountWorkloadSharedMemory(root, spec.IPCMode, os.MkdirAll, unix.Mount); err != nil {
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
	if pathPolicyMasksUserDatabase(spec.MaskedPaths) {
		if err := snapshotUserDatabase(root, workloadUserDatabaseSnapshotPath); err != nil {
			return err
		}
	}
	if err := switchWorkloadRoot(root, rootSwitchOperations{
		chdir: unix.Chdir, mount: unix.Mount, chroot: unix.Chroot,
	}); err != nil {
		return err
	}
	uid, gid, namedGroups, err := resolveUser(spec.User)
	if err != nil {
		return err
	}
	if err := applyReadonlyPaths(spec.ReadonlyPaths, unix.Mount, unix.Statfs); err != nil {
		return err
	}
	if err := applyMaskedPaths(spec.MaskedPaths); err != nil {
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
	capabilities, err := capabilityMask(spec.CapabilityAdd, spec.CapabilityDrop, spec.Privileged)
	if err != nil {
		return err
	}
	if err := applyRlimits(spec.Rlimits, unix.Setrlimit); err != nil {
		return err
	}
	if err := applyCapabilityBoundingSet(capabilities, unix.Prctl); err != nil {
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
	if err := applyProcessCapabilities(capabilities, uid, unix.Capset); err != nil {
		return err
	}
	if err := applyNoNewPrivileges(spec.NoNewPrivileges, unix.Prctl); err != nil {
		return err
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
	if _, err := ready.Write([]byte{1}); err != nil {
		return fmt.Errorf("signal workload readiness: %w", err)
	}
	return unix.Exec(path, spec.Arguments, environment)
}

func mountWorkloadSharedMemory(
	root, mode string,
	mkdirAll func(string, os.FileMode) error,
	mount func(string, string, string, uintptr, string) error,
) error {
	switch mode {
	case "none":
		return nil
	case "", "private":
		path := filepath.Join(root, "dev/shm")
		if err := mkdirAll(path, 01777); err != nil {
			return err
		}
		if err := mount(
			"tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV,
			"mode=1777,size=67108864",
		); err != nil {
			return fmt.Errorf("mount private shared memory: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported IPC namespace mode %q", mode)
	}
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
	return resolveUserAtRoot(user, "/")
}

func resolveUserAtRoot(user protocol.User, root string) (int, int, []int, error) {
	passwd, err := os.ReadFile(filepath.Join(root, "etc/passwd"))
	if err != nil {
		return 0, 0, nil, err
	}
	groupData, err := os.ReadFile(filepath.Join(root, "etc/group"))
	if err != nil {
		return 0, 0, nil, err
	}
	return resolveUserFromData(user, passwd, groupData)
}

func resolveUserFromData(user protocol.User, passwd, groupData []byte) (int, int, []int, error) {
	parts := strings.SplitN(user.Username, ":", 2)
	name := ""
	uid, numericError := strconv.Atoi(parts[0])
	gid := int(user.GID)
	if numericError != nil {
		name = parts[0]
		uid, gid = -1, -1
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
	}
	if len(parts) == 2 && parts[1] != "" {
		if value, parseErr := strconv.Atoi(parts[1]); parseErr == nil {
			gid = value
		} else {
			found := false
			for _, line := range strings.Split(string(groupData), "\n") {
				fields := strings.Split(line, ":")
				if len(fields) >= 3 && fields[0] == parts[1] {
					gid, _ = strconv.Atoi(fields[2])
					found = true
					break
				}
			}
			if !found {
				return 0, 0, nil, fmt.Errorf("group %s not found", parts[1])
			}
		}
	}
	var groups []int
	if name != "" {
		for _, line := range strings.Split(string(groupData), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) >= 4 && containsString(strings.Split(fields[3], ","), name) {
				if value, err := strconv.Atoi(fields[2]); err == nil && value != gid {
					groups = append(groups, value)
				}
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
		if err := unix.Mount(source, destination, "", bindMountFlags(mount), ""); err != nil {
			return err
		}
		return applyBindMountAttributes(destination, mount, unix.Mount, unix.MountSetattr)
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

type mountOperation func(source, target, filesystem string, flags uintptr, data string) error
type mountSetattrOperation func(dirfd int, path string, flags uint, attr *unix.MountAttr) error

func bindMountFlags(spec protocol.Mount) uintptr {
	if spec.NonRecursive {
		return unix.MS_BIND
	}
	return unix.MS_BIND | unix.MS_REC
}

func applyBindMountAttributes(
	destination string,
	spec protocol.Mount,
	mount mountOperation,
	mountSetattr mountSetattrOperation,
) error {
	flags, err := mountPropagationFlags(spec.Propagation)
	if err != nil {
		return err
	}
	if err := mount("", destination, "", flags, ""); err != nil {
		return fmt.Errorf("set mount propagation on %s: %w", destination, err)
	}
	if !spec.ReadOnly {
		return nil
	}
	if spec.ReadOnlyNonRecursive {
		if spec.ReadOnlyForceRecursive {
			return errors.New("read-only bind mount cannot be both non-recursive and force-recursive")
		}
		return mount("", destination, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
	}
	attribute := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
	if err := mountSetattr(unix.AT_FDCWD, destination, unix.AT_RECURSIVE, attribute); err == nil {
		return nil
	} else if spec.ReadOnlyForceRecursive ||
		(!errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP)) {
		return fmt.Errorf("make bind mount recursively read-only at %s: %w", destination, err)
	}
	return mount("", destination, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
}

func mountPropagationFlags(propagation string) (uintptr, error) {
	switch propagation {
	case "", "rprivate":
		return unix.MS_PRIVATE | unix.MS_REC, nil
	case "private":
		return unix.MS_PRIVATE, nil
	default:
		return 0, fmt.Errorf("unsupported mount propagation mode %q", propagation)
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
