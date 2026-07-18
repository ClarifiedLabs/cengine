//go:build linux

package supervisor

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestCgroupNamespaceIsCreatedAfterParentPlacement(t *testing.T) {
	calls := []string{}
	gate := &recordingReader{
		Reader: bytes.NewReader([]byte{1}),
		calls:  &calls,
	}
	if err := enterPlacedCgroupNamespace(gate, func(flag int) error {
		calls = append(calls, "unshare")
		if flag != unix.CLONE_NEWCGROUP {
			t.Fatalf("unshare flag = %d", flag)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"placement", "unshare"}) {
		t.Fatalf("cgroup namespace sequence = %#v", calls)
	}
}

type recordingReader struct {
	*bytes.Reader
	calls *[]string
}

func (reader *recordingReader) Read(value []byte) (int, error) {
	*reader.calls = append(*reader.calls, "placement")
	return reader.Reader.Read(value)
}

func TestEnableCgroupControllersDelegatesDockerResourceControllers(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpuset cpu io memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enableCgroupControllers(root); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "+cpu +memory +pids" {
		t.Fatalf("unexpected controller delegation %q", value)
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

func TestExecUsesTheWorkloadCgroup(t *testing.T) {
	root := t.TempDir()
	workload := filepath.Join(root, "cengine", "workload")
	if err := os.MkdirAll(workload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workload, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cgroup, err := openWorkloadCgroup(root, "workload")
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
	pathInfo, err := os.Stat(workload)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(cgroupInfo, pathInfo) {
		t.Fatal("exec cgroup descriptor does not reference the workload cgroup")
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
