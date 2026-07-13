//go:build linux

package supervisor

import (
	"fmt"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestExecUnsharesFilesystemContextBeforeJoiningWorkloadNamespaces(t *testing.T) {
	var calls []string
	operations := namespaceOperations{
		unshare: func(flag int) error { calls = append(calls, fmt.Sprintf("unshare:%d", flag)); return nil },
		open: func(path string, _ int, _ uint32) (int, error) { calls = append(calls, "open:"+path); return len(calls), nil },
		setns: func(_ int, flag int) error { calls = append(calls, fmt.Sprintf("setns:%d", flag)); return nil },
		close: func(_ int) error { return nil },
	}
	if err := joinWorkloadNamespaces(42, operations); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		fmt.Sprintf("unshare:%d", unix.CLONE_FS),
		"open:/proc/42/ns/mnt", fmt.Sprintf("setns:%d", unix.CLONE_NEWNS),
		"open:/proc/42/ns/uts", fmt.Sprintf("setns:%d", unix.CLONE_NEWUTS),
		"open:/proc/42/ns/ipc", fmt.Sprintf("setns:%d", unix.CLONE_NEWIPC),
		"open:/proc/42/ns/net", fmt.Sprintf("setns:%d", unix.CLONE_NEWNET),
		"open:/proc/42/ns/cgroup", fmt.Sprintf("setns:%d", unix.CLONE_NEWCGROUP),
		"open:/proc/42/ns/pid", fmt.Sprintf("setns:%d", unix.CLONE_NEWPID),
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected namespace sequence %#v", calls)
	}
}

func TestExecEntersRootThroughDescriptorCapturedBeforeNamespaceChanges(t *testing.T) {
	var calls []string
	err := enterExecRoot(4, func(fd int) error {
		calls = append(calls, fmt.Sprintf("fchdir:%d", fd))
		return nil
	}, func(path string) error {
		calls = append(calls, "chroot:"+path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"fchdir:4", "chroot:."}) {
		t.Fatalf("unexpected root entry sequence %#v", calls)
	}
}
