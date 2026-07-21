//go:build linux

package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestCgroupNamespaceRootIsFixedBeforeInitMovesToDelegatedLeaf(t *testing.T) {
	calls := []string{}
	gate := &recordingCgroupDelegation{calls: &calls}
	if err := enterDelegatedCgroupNamespace(gate, func(flag int) error {
		calls = append(calls, "unshare")
		if flag != unix.CLONE_NEWCGROUP {
			t.Fatalf("unshare flag = %d", flag)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{
		"placement", "unshare", "namespace-ready", "leaf-ready",
	}) {
		t.Fatalf("cgroup namespace sequence = %#v", calls)
	}
}

type recordingCgroupDelegation struct {
	calls *[]string
	reads int
}

func (gate *recordingCgroupDelegation) Read(value []byte) (int, error) {
	name := "placement"
	if gate.reads > 0 {
		name = "leaf-ready"
	}
	gate.reads++
	*gate.calls = append(*gate.calls, name)
	value[0] = 1
	return 1, nil
}

func (gate *recordingCgroupDelegation) Write(value []byte) (int, error) {
	*gate.calls = append(*gate.calls, "namespace-ready")
	return len(value), nil
}

func TestEnableCgroupControllersDelegatesDockerResourceControllers(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpuset cpu io memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enableCgroupControllers(root, false); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "+cpu +io +memory +pids" {
		t.Fatalf("unexpected controller delegation %q", value)
	}
}

func TestEnableCgroupControllersRequiresIOOnlyForConfiguredThrottles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enableCgroupControllers(root, false); err != nil {
		t.Fatalf("controller delegation without I/O limits failed: %v", err)
	}
	if err := enableCgroupControllers(root, true); err == nil || !strings.Contains(err.Error(), "required io controller") {
		t.Fatalf("enableCgroupControllers(requireIO=true) error = %v", err)
	}
}

func TestResolveBlockDeviceUsesConfiguredHostDeviceNumber(t *testing.T) {
	device, err := resolveBlockDeviceWithStat("/dev/vdb", func(path string, status *unix.Stat_t) error {
		if path != "/dev/vdb" {
			t.Fatalf("stat path = %q", path)
		}
		status.Mode = unix.S_IFBLK
		status.Rdev = uint64(unix.Mkdev(8, 17))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if device != "8:17" {
		t.Fatalf("device = %q, want 8:17", device)
	}
	if _, err := resolveBlockDeviceWithStat("relative", func(string, *unix.Stat_t) error { return nil }); err == nil {
		t.Fatal("relative device was accepted")
	}
	if _, err := resolveBlockDeviceWithStat("/dev/vda", func(_ string, status *unix.Stat_t) error {
		status.Mode = unix.S_IFREG
		return nil
	}); err == nil || !strings.Contains(err.Error(), "not a block device") {
		t.Fatalf("regular-file stat error = %v", err)
	}
}

func TestDesiredIOMaxMapsDockerThrottleListsAndRejectsDuplicates(t *testing.T) {
	resolutions := 0
	resources := protocol.Resources{
		BlockIOReadBps:   []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: uint64(1) << 63}},
		BlockIOWriteBps:  []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: ^uint64(0)}},
		BlockIOReadIOps:  []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: 3}},
		BlockIOWriteIOps: []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: 4}},
	}
	desired, err := desiredIOMax(resources, func(path string) (string, error) {
		resolutions++
		if path != "/dev/vda" {
			t.Fatalf("resolved path = %q", path)
		}
		return "254:0", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolutions != 1 {
		t.Fatalf("device resolutions = %d, want 1", resolutions)
	}
	want := map[string]string{
		"rbps": "9223372036854775808", "wbps": "18446744073709551615", "riops": "3", "wiops": "4",
	}
	if !reflect.DeepEqual(desired["254:0"], want) {
		t.Fatalf("desired io.max = %#v, want %#v", desired, want)
	}
	resources.BlockIOReadBps = append(resources.BlockIOReadBps, protocol.BlockIOThrottle{Path: "/dev/vda", Rate: 5})
	if _, err := desiredIOMax(resources, func(string) (string, error) { return "254:0", nil }); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate throttle error = %v", err)
	}
}

func TestParseAndDiffIOMaxClearsAbsentKeysOnce(t *testing.T) {
	current, err := parseIOMax([]byte(
		"8:0 rbps=9223372036854775808 wbps=18446744073709551615\n8:1 riops=30\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	desired := map[string]map[string]string{
		"8:0": {"rbps": "150", "riops": "40"},
	}
	changes := ioMaxChanges(current, desired)
	want := []cgroupIOValue{
		{device: "8:0", key: "rbps", value: "150"},
		{device: "8:0", key: "wbps", value: "max"},
		{device: "8:0", key: "riops", value: "40"},
		{device: "8:1", key: "riops", value: "max"},
	}
	if !reflect.DeepEqual(changes, want) {
		t.Fatalf("io.max changes = %#v, want %#v", changes, want)
	}
	seen := map[string]bool{}
	for _, change := range changes {
		key := change.device + "/" + change.key
		if seen[key] {
			t.Fatalf("duplicate io.max write for %s", key)
		}
		seen[key] = true
	}
	if _, err := parseIOMax([]byte("8:0 rbps=0")); err == nil {
		t.Fatal("invalid zero io.max value was accepted")
	}
	if _, err := parseIOMax([]byte("8:0 rbps=18446744073709551616")); err == nil {
		t.Fatal("overflowing io.max value was accepted")
	}
}

func TestCgroupResourceAndIOMaxUpdateRollBackTogether(t *testing.T) {
	path := "/cgroup/workload"
	values := map[string][]byte{
		filepath.Join(path, "memory.max"): []byte("1073741824"),
		filepath.Join(path, "cpu.max"):    []byte("400000 100000"),
		filepath.Join(path, "pids.max"):   []byte("max"),
		filepath.Join(path, "io.max"):     []byte("8:0 rbps=100 wbps=200\n"),
	}
	ioValues := map[string]string{"rbps": "100", "wbps": "200"}
	readFile := func(name string) ([]byte, error) {
		value, ok := values[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), value...), nil
	}
	writes := []string{}
	writeFile := func(name string, value []byte, _ os.FileMode) error {
		if filepath.Base(name) != "io.max" {
			values[name] = append([]byte(nil), value...)
			return nil
		}
		directive := string(value)
		writes = append(writes, directive)
		fields := strings.Fields(directive)
		parts := strings.SplitN(fields[1], "=", 2)
		if parts[0] == "wbps" && parts[1] == "400" {
			return errors.New("injected io.max write failure")
		}
		ioValues[parts[0]] = parts[1]
		return nil
	}
	err := replaceCgroupResourceLimitsWithResolver(path, protocol.Resources{
		MemoryBytes:     64 * 1024 * 1024,
		CPUQuota:        200000,
		CPUPeriod:       100000,
		BlockIOReadBps:  []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: 300}},
		BlockIOWriteBps: []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: 400}},
	}, false, readFile, writeFile, func(string) (string, error) { return "8:0", nil })
	if err == nil || !strings.Contains(err.Error(), "update io.max") {
		t.Fatalf("resource update error = %v", err)
	}
	if got := string(values[filepath.Join(path, "memory.max")]); got != "1073741824" {
		t.Fatalf("memory.max after rollback = %q", got)
	}
	if got := string(values[filepath.Join(path, "cpu.max")]); got != "400000 100000" {
		t.Fatalf("cpu.max after rollback = %q", got)
	}
	if !reflect.DeepEqual(ioValues, map[string]string{"rbps": "100", "wbps": "200"}) {
		t.Fatalf("io.max after rollback = %#v", ioValues)
	}
	if !reflect.DeepEqual(writes, []string{"8:0 rbps=300", "8:0 wbps=400", "8:0 rbps=100"}) {
		t.Fatalf("io.max writes = %#v", writes)
	}
}

func TestCompatibilityFailureAfterSuccessfulScalarAndIOWritesRollsBack(t *testing.T) {
	path := "/cgroup/workload"
	original := map[string][]byte{
		filepath.Join(path, "memory.max"): []byte("1073741824"),
		filepath.Join(path, "cpu.max"):    []byte("400000 100000"),
		filepath.Join(path, "pids.max"):   []byte("max"),
		filepath.Join(path, "io.max"):     []byte("8:0 rbps=100 riops=30\n"),
	}
	values := map[string][]byte{}
	for name, value := range original {
		values[name] = append([]byte(nil), value...)
	}
	ioValues := map[string]string{"rbps": "100", "riops": "30"}
	readFile := func(name string) ([]byte, error) {
		value, ok := values[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), value...), nil
	}
	writes := 0
	writeFile := func(name string, value []byte, _ os.FileMode) error {
		writes++
		if filepath.Base(name) != "io.max" {
			values[name] = append([]byte(nil), value...)
			return nil
		}
		fields := strings.Fields(string(value))
		parts := strings.SplitN(fields[1], "=", 2)
		ioValues[parts[0]] = parts[1]
		return nil
	}
	err := replaceCgroupResourceLimitsWithResolverAndFailure(
		path,
		protocol.Resources{
			MemoryBytes:     512 * 1024 * 1024,
			CPUQuota:        200000,
			CPUPeriod:       100000,
			BlockIOReadBps:  []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: 300}},
			BlockIOReadIOps: []protocol.BlockIOThrottle{{Path: "/dev/vda", Rate: 50}},
		},
		false, readFile, writeFile, func(string) (string, error) { return "8:0", nil }, 4,
	)
	if err == nil || !strings.Contains(err.Error(), "failure after 4 successful writes") {
		t.Fatalf("compatibility resource failure = %v", err)
	}
	for name, expected := range original {
		if filepath.Base(name) == "io.max" {
			continue
		}
		if !bytes.Equal(values[name], expected) {
			t.Fatalf("%s after rollback = %q, want %q", name, values[name], expected)
		}
	}
	if !reflect.DeepEqual(ioValues, map[string]string{"rbps": "100", "riops": "30"}) {
		t.Fatalf("io.max after compatibility rollback = %#v", ioValues)
	}
	if writes != 8 {
		t.Fatalf("underlying writes = %d, want 4 transaction writes plus 4 rollbacks", writes)
	}
}

func TestCgroupResourceUpdateWritesLiveLimits(t *testing.T) {
	path := t.TempDir()
	for _, name := range []string{"memory.max", "cpu.max", "pids.max"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("max"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resources := protocol.Resources{
		MemoryBytes: 64 * 1024 * 1024,
		CPUQuota:    200000,
		CPUPeriod:   100000,
		PIDs:        128,
	}
	if err := writeCgroupResourceLimits(path, resources, false); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"memory.max": "67108864",
		"cpu.max":    "200000 100000",
		"pids.max":   "128",
	}
	for name, expected := range want {
		value, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(value) != expected {
			t.Fatalf("%s = %q, want %q", name, value, expected)
		}
	}
}

func TestCgroupResourceUpdateRollsBackEarlierLimitsOnFailure(t *testing.T) {
	path := "/cgroup/workload"
	values := map[string][]byte{
		filepath.Join(path, "memory.max"): []byte("1073741824"),
		filepath.Join(path, "cpu.max"):    []byte("400000 100000"),
		filepath.Join(path, "pids.max"):   []byte("max"),
	}
	readFile := func(name string) ([]byte, error) {
		value, ok := values[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), value...), nil
	}
	writeFile := func(name string, value []byte, _ os.FileMode) error {
		if filepath.Base(name) == "cpu.max" && string(value) == "200000 100000" {
			return errors.New("injected write failure")
		}
		values[name] = append([]byte(nil), value...)
		return nil
	}
	err := replaceCgroupResourceLimits(path, protocol.Resources{
		MemoryBytes: 64 * 1024 * 1024,
		CPUQuota:    200000,
		CPUPeriod:   100000,
	}, false, readFile, writeFile)
	if err == nil {
		t.Fatal("resource update unexpectedly succeeded")
	}
	if got := string(values[filepath.Join(path, "memory.max")]); got != "1073741824" {
		t.Fatalf("memory.max after rollback = %q", got)
	}
	if got := string(values[filepath.Join(path, "cpu.max")]); got != "400000 100000" {
		t.Fatalf("cpu.max after rollback = %q", got)
	}
}

func TestCgroupResourceUpdateReportsSingleRollbackFailure(t *testing.T) {
	path := "/cgroup/workload"
	original := map[string][]byte{
		filepath.Join(path, "memory.max"): []byte("1073741824"),
		filepath.Join(path, "cpu.max"):    []byte("400000 100000"),
		filepath.Join(path, "pids.max"):   []byte("max"),
	}
	values := map[string][]byte{}
	for name, value := range original {
		values[name] = append([]byte(nil), value...)
	}
	readFile := func(name string) ([]byte, error) {
		value, ok := values[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), value...), nil
	}
	writeFile := func(name string, value []byte, _ os.FileMode) error {
		base := filepath.Base(name)
		if base == "pids.max" && string(value) == "128" {
			return errors.New("forward pids failure")
		}
		if base == "cpu.max" && string(value) == "400000 100000" {
			return errors.New("rollback cpu failure")
		}
		values[name] = append([]byte(nil), value...)
		return nil
	}
	err := replaceCgroupResourceLimitsWithResolver(
		path,
		protocol.Resources{
			MemoryBytes: 64 * 1024 * 1024, CPUQuota: 200000, CPUPeriod: 100000, PIDs: 128,
		},
		false, readFile, writeFile, func(string) (string, error) { return "8:0", nil },
	)
	var rollbackIncomplete *ResourceRollbackIncompleteError
	if !errors.As(err, &rollbackIncomplete) {
		t.Fatalf("resource update error = %T %v, want ResourceRollbackIncompleteError", err, err)
	}
	if !strings.Contains(rollbackIncomplete.UpdateError.Error(), "forward pids failure") {
		t.Fatalf("forward error = %v", rollbackIncomplete.UpdateError)
	}
	if len(rollbackIncomplete.RollbackErrors) != 1 ||
		!strings.Contains(rollbackIncomplete.RollbackErrors[0].Error(), "rollback cpu failure") {
		t.Fatalf("rollback errors = %#v", rollbackIncomplete.RollbackErrors)
	}
	if got := string(values[filepath.Join(path, "memory.max")]); got != "1073741824" {
		t.Fatalf("memory.max after rollback = %q", got)
	}
}

func TestCgroupResourceUpdateAttemptsEveryRollbackAfterMultipleFailures(t *testing.T) {
	path := "/cgroup/workload"
	original := map[string][]byte{
		filepath.Join(path, "memory.max"): []byte("1073741824"),
		filepath.Join(path, "cpu.max"):    []byte("400000 100000"),
		filepath.Join(path, "pids.max"):   []byte("max"),
	}
	values := map[string][]byte{}
	for name, value := range original {
		values[name] = append([]byte(nil), value...)
	}
	readFile := func(name string) ([]byte, error) {
		value, ok := values[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), value...), nil
	}
	rollbackAttempts := []string{}
	writeFile := func(name string, value []byte, _ os.FileMode) error {
		base := filepath.Base(name)
		if base == "pids.max" && string(value) == "128" {
			return errors.New("forward pids failure")
		}
		if bytes.Equal(value, original[name]) {
			rollbackAttempts = append(rollbackAttempts, base)
			return fmt.Errorf("rollback %s failure", base)
		}
		values[name] = append([]byte(nil), value...)
		return nil
	}
	err := replaceCgroupResourceLimitsWithResolver(
		path,
		protocol.Resources{
			MemoryBytes: 64 * 1024 * 1024, CPUQuota: 200000, CPUPeriod: 100000, PIDs: 128,
		},
		false, readFile, writeFile, func(string) (string, error) { return "8:0", nil },
	)
	var rollbackIncomplete *ResourceRollbackIncompleteError
	if !errors.As(err, &rollbackIncomplete) {
		t.Fatalf("resource update error = %T %v, want ResourceRollbackIncompleteError", err, err)
	}
	if len(rollbackIncomplete.RollbackErrors) != 2 {
		t.Fatalf("rollback errors = %#v", rollbackIncomplete.RollbackErrors)
	}
	if !reflect.DeepEqual(rollbackAttempts, []string{"cpu.max", "memory.max"}) {
		t.Fatalf("rollback attempts = %#v", rollbackAttempts)
	}
}

func TestCgroupResourceUpdateRejectsExitedWorkload(t *testing.T) {
	supervisor := New()
	spec := protocol.WorkloadSpec{ID: "workload"}
	supervisor.spec = &spec
	supervisor.command = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	supervisor.status = protocol.ProcessStatus{Status: "exited"}

	err := supervisor.UpdateResources(protocol.Resources{MemoryBytes: 64 * 1024 * 1024})
	if err == nil || err.Error() != "workload is not running" {
		t.Fatalf("UpdateResources() error = %v, want workload is not running", err)
	}
}

func TestExecUsesDedicatedLeafBeneathTheWorkloadCgroup(t *testing.T) {
	root := t.TempDir()
	workload := filepath.Join(root, "cengine", "workload")
	if err := os.MkdirAll(workload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workload, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cgroup, err := openExecCgroup(root, "workload", "exec-id")
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	rootProcesses, err := os.ReadFile(filepath.Join(workload, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rootProcesses) != 0 {
		t.Fatalf("workload root contains exec process %q", rootProcesses)
	}
	cgroupInfo, err := cgroup.Stat()
	if err != nil {
		t.Fatal(err)
	}
	pathInfo, err := os.Stat(filepath.Join(workload, ".cengine-exec", "exec-id"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(cgroupInfo, pathInfo) {
		t.Fatal("exec cgroup descriptor does not reference the per-exec leaf")
	}
}

func TestNonPrivilegedCgroupMountIsReadOnlyWithoutRemountingSuperblock(t *testing.T) {
	var source, target, filesystem, data string
	var flags uintptr
	err := remountCgroupReadOnly("/root/sys/fs/cgroup", func(
		mountSource, mountTarget, mountFilesystem string, mountFlags uintptr, mountData string,
	) error {
		source = mountSource
		target = mountTarget
		filesystem = mountFilesystem
		flags = mountFlags
		data = mountData
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if source != "" || target != "/root/sys/fs/cgroup" || filesystem != "" || data != "" {
		t.Fatalf("unexpected read-only cgroup remount arguments %q %q %q %q", source, target, filesystem, data)
	}
	expected := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY)
	if flags != expected {
		t.Fatalf("read-only cgroup remount flags = %#x, want %#x", flags, expected)
	}
}
