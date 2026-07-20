//go:build linux

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivateIPCModeMountsSharedMemory(t *testing.T) {
	var calls []string
	err := mountWorkloadSharedMemory(
		"/run/cengine/rootfs", "private",
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
			"mount:tmpfs:%s:tmpfs:%d:mode=1777,size=67108864",
			path, unix.MS_NOSUID|unix.MS_NODEV,
		),
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("private IPC setup calls = %#v, want %#v", calls, want)
	}
}

func TestIPCNoneDoesNotCreateOrMountSharedMemory(t *testing.T) {
	called := false
	err := mountWorkloadSharedMemory(
		"/run/cengine/rootfs", "none",
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

func TestUnsupportedIPCModeFailsClosed(t *testing.T) {
	err := mountWorkloadSharedMemory(
		"/run/cengine/rootfs", "host",
		func(string, os.FileMode) error { return nil },
		func(string, string, string, uintptr, string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported IPC namespace mode") {
		t.Fatalf("unsupported IPC mode error = %v", err)
	}
}
