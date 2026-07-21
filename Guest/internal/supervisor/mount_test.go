//go:build linux

package supervisor

import (
	"fmt"
	"reflect"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestMountPropagationFlags(t *testing.T) {
	tests := map[string]uintptr{
		"":         unix.MS_PRIVATE | unix.MS_REC,
		"private":  unix.MS_PRIVATE,
		"rprivate": unix.MS_PRIVATE | unix.MS_REC,
	}
	for propagation, expected := range tests {
		t.Run(propagation, func(t *testing.T) {
			flags, err := mountPropagationFlags(propagation)
			if err != nil {
				t.Fatal(err)
			}
			if flags != expected {
				t.Fatalf("flags = %#x, want %#x", flags, expected)
			}
		})
	}
	for _, propagation := range []string{"shared", "rshared", "slave", "rslave", "invalid"} {
		if _, err := mountPropagationFlags(propagation); err == nil {
			t.Fatalf("unsupported propagation %q unexpectedly accepted", propagation)
		}
	}
}

func TestBindMountAttributesApplyPropagationBeforeReadOnly(t *testing.T) {
	calls := []string{}
	mount := func(_, target, _ string, flags uintptr, _ string) error {
		calls = append(calls, fmt.Sprintf("%s:%#x", target, flags))
		return nil
	}
	mountSetattr := func(_ int, path string, flags uint, attr *unix.MountAttr) error {
		calls = append(calls, fmt.Sprintf("%s:%#x:%#x", path, flags, attr.Attr_set))
		return nil
	}
	err := applyBindMountAttributes("/root/data", protocol.Mount{
		Propagation: "rprivate",
		ReadOnly:    true,
	}, mount, mountSetattr)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		fmt.Sprintf("/root/data:%#x", uintptr(unix.MS_PRIVATE|unix.MS_REC)),
		fmt.Sprintf("/root/data:%#x:%#x", uint(unix.AT_RECURSIVE), uint64(unix.MOUNT_ATTR_RDONLY)),
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("mount calls = %#v, want %#v", calls, expected)
	}
}

func TestBindMountRecursionAndReadOnlyModes(t *testing.T) {
	if got := bindMountFlags(protocol.Mount{}); got != unix.MS_BIND|unix.MS_REC {
		t.Fatalf("default bind flags = %#x, want recursive bind", got)
	}
	if got := bindMountFlags(protocol.Mount{NonRecursive: true}); got != unix.MS_BIND {
		t.Fatalf("non-recursive bind flags = %#x, want bind only", got)
	}

	remounts := 0
	mount := func(_, _ string, _ string, flags uintptr, _ string) error {
		if flags == unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY {
			remounts++
		}
		return nil
	}
	mountSetattr := func(_ int, _ string, _ uint, _ *unix.MountAttr) error {
		t.Fatal("non-recursive read-only unexpectedly used mount_setattr")
		return nil
	}
	if err := applyBindMountAttributes("/root/data", protocol.Mount{
		Propagation: "private", ReadOnly: true, ReadOnlyNonRecursive: true,
	}, mount, mountSetattr); err != nil {
		t.Fatal(err)
	}
	if remounts != 1 {
		t.Fatalf("top-level read-only remounts = %d, want 1", remounts)
	}
}

func TestRecursiveReadOnlyFallbackAndForceBehavior(t *testing.T) {
	mount := func(_, _ string, _ string, _ uintptr, _ string) error { return nil }
	unsupported := func(_ int, _ string, _ uint, _ *unix.MountAttr) error { return unix.ENOSYS }

	if err := applyBindMountAttributes("/root/data", protocol.Mount{
		Propagation: "rprivate", ReadOnly: true,
	}, mount, unsupported); err != nil {
		t.Fatalf("default recursive read-only did not fall back: %v", err)
	}
	if err := applyBindMountAttributes("/root/data", protocol.Mount{
		Propagation: "rprivate", ReadOnly: true, ReadOnlyForceRecursive: true,
	}, mount, unsupported); err == nil {
		t.Fatal("force-recursive read-only unexpectedly fell back")
	}
	if err := applyBindMountAttributes("/root/data", protocol.Mount{
		Propagation: "rprivate", ReadOnly: true,
		ReadOnlyNonRecursive: true, ReadOnlyForceRecursive: true,
	}, mount, unsupported); err == nil {
		t.Fatal("conflicting read-only modes unexpectedly succeeded")
	}
}

func TestTmpfsMountConfigurationDefaultsToNoexecAndAppliesLastOverride(t *testing.T) {
	tests := []struct {
		name       string
		options    []string
		wantNoexec bool
		wantData   string
	}{
		{name: "default", options: []string{"size=1048576", "mode=700"}, wantNoexec: true, wantData: "size=1048576,mode=700"},
		{name: "exec", options: []string{"size=1048576", "exec"}, wantNoexec: false, wantData: "size=1048576"},
		{name: "last noexec wins", options: []string{"exec", "noexec"}, wantNoexec: true},
		{name: "last exec wins", options: []string{"noexec", "exec"}, wantNoexec: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flags, data, err := tmpfsMountConfiguration(test.options)
			if err != nil {
				t.Fatal(err)
			}
			if flags&unix.MS_NOSUID == 0 || flags&unix.MS_NODEV == 0 {
				t.Fatalf("tmpfs safety flags = %#x, want nosuid and nodev", flags)
			}
			if got := flags&unix.MS_NOEXEC != 0; got != test.wantNoexec {
				t.Fatalf("noexec = %t, want %t", got, test.wantNoexec)
			}
			if data != test.wantData {
				t.Fatalf("mount data = %q, want %q", data, test.wantData)
			}
		})
	}

	if _, _, err := tmpfsMountConfiguration([]string{"uid=1000"}); err == nil {
		t.Fatal("unsupported tmpfs option unexpectedly accepted")
	}
}
