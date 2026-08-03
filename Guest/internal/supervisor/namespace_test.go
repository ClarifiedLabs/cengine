//go:build linux

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestPrivateIPCModeMountsSharedMemory(t *testing.T) {
	var calls []string
	err := mountWorkloadSharedMemory(
		"/run/cengine/rootfs", "private", 32*1024*1024,
		func(path string, mode os.FileMode) error {
			calls = append(calls, fmt.Sprintf("mkdir:%s:%o", path, mode))
			return nil
		},
		func(source, target, kind string, flags uintptr, data string) error {
			calls = append(calls, fmt.Sprintf(
				"mount:%s:%s:%s:%d:%s", source, target, kind, flags, data,
			))
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("/run/cengine/rootfs", "dev/shm")
	want := []string{
		fmt.Sprintf("mkdir:%s:%o", path, os.FileMode(01777)),
		fmt.Sprintf(
			"mount:tmpfs:%s:tmpfs:%d:mode=1777,size=33554432",
			path, unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV,
		),
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("private IPC setup calls = %#v, want %#v", calls, want)
	}
}

func TestSharedMemoryMountClassification(t *testing.T) {
	tests := []struct {
		destination string
		targets     bool
		overrides   bool
	}{
		{destination: "/dev/shm", targets: true, overrides: true},
		{destination: "/dev/shm/", targets: true, overrides: true},
		{destination: "/dev/shm/cache", targets: true},
		{destination: "/dev/shm-other"},
		{destination: "/tmp"},
	}
	for _, test := range tests {
		targets, overrides := classifySharedMemoryMount(test.destination)
		if targets != test.targets || overrides != test.overrides {
			t.Fatalf("classify %q = (%t, %t), want (%t, %t)",
				test.destination, targets, overrides, test.targets, test.overrides)
		}
	}
}

func TestSharedMemoryMountsAreSortedParentFirstAndStable(t *testing.T) {
	mounts := []protocol.Mount{
		{Destination: "/dev/shm/cache"},
		{Destination: "/dev/shm"},
		{Destination: "/dev/shm/logs/current"},
		{Destination: "/dev/shm/logs"},
		{Destination: "/dev/shm/other"},
	}
	sortSharedMemoryMounts(mounts)
	got := make([]string, len(mounts))
	for index := range mounts {
		got[index] = mounts[index].Destination
	}
	want := []string{
		"/dev/shm", "/dev/shm/cache", "/dev/shm/logs", "/dev/shm/other",
		"/dev/shm/logs/current",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shared-memory mount order = %#v, want %#v", got, want)
	}
}

func TestDefaultSharedMemorySizeIsMounted(t *testing.T) {
	var data string
	err := mountWorkloadSharedMemory(
		"/run/cengine/rootfs", "", 64*1024*1024,
		func(string, os.FileMode) error { return nil },
		func(_, _ string, _ string, _ uintptr, value string) error { data = value; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if data != "mode=1777,size=67108864" {
		t.Fatalf("default shared memory mount data = %q", data)
	}
}

func TestIPCNoneDoesNotCreateOrMountSharedMemory(t *testing.T) {
	called := false
	err := mountWorkloadSharedMemory(
		"/run/cengine/rootfs", "none", 0,
		func(string, os.FileMode) error { called = true; return nil },
		func(string, string, string, uintptr, string) error { called = true; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("IPC none created or mounted /dev/shm")
	}
}

func TestNonpositivePrivateSharedMemorySizeFailsClosed(t *testing.T) {
	for _, size := range []int64{0, -1} {
		if err := mountWorkloadSharedMemory(
			"/run/cengine/rootfs", "private", size,
			func(string, os.FileMode) error { return nil },
			func(string, string, string, uintptr, string) error { return nil },
		); err == nil || !strings.Contains(err.Error(), "must be positive") {
			t.Fatalf("size %d error = %v", size, err)
		}
	}
}

func TestUnsupportedIPCModeFailsClosed(t *testing.T) {
	err := mountWorkloadSharedMemory(
		"/run/cengine/rootfs", "host", 64*1024*1024,
		func(string, os.FileMode) error { return nil },
		func(string, string, string, uintptr, string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported IPC namespace mode") {
		t.Fatalf("unsupported IPC mode error = %v", err)
	}
}
