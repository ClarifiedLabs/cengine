//go:build linux

package supervisor

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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

func TestExecCgroupPlacementKeepsWorkloadRootEmpty(t *testing.T) {
	root := t.TempDir()
	workload := filepath.Join(root, "cengine", "workload")
	if err := os.MkdirAll(workload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workload, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := placeExecInCgroup(root, "workload", "exec", 42); err != nil {
		t.Fatal(err)
	}
	rootProcesses, err := os.ReadFile(filepath.Join(workload, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rootProcesses) != 0 {
		t.Fatalf("workload root contains exec process %q", rootProcesses)
	}
	execProcesses, err := os.ReadFile(filepath.Join(workload, "cengine-exec-exec", "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(execProcesses) != "42" {
		t.Fatalf("exec cgroup processes = %q", execProcesses)
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
