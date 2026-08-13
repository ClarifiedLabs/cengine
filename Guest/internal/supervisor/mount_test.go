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

func TestConfinedVolumeMountPinsSourceAndDestinationThroughAttributes(t *testing.T) {
	parent := t.TempDir()
	sourceRoot := filepath.Join(parent, "volume")
	destinationRoot := filepath.Join(parent, "rootfs")
	outsideSource := filepath.Join(parent, "outside-source")
	outsideDestination := filepath.Join(parent, "outside-destination")
	for _, directory := range []string{
		filepath.Join(sourceRoot, "nested"), destinationRoot, outsideSource, outsideDestination,
	} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "nested", "marker"), []byte("pinned"), 0644); err != nil {
		t.Fatal(err)
	}

	calls := []string{}
	mount := func(source, target, filesystem string, flags uintptr, data string) error {
		calls = append(calls, "mount")
		if !strings.HasPrefix(source, "/proc/self/fd/") ||
			!strings.HasPrefix(target, "/proc/self/fd/") || !strings.HasSuffix(target, "/data") {
			t.Fatalf("mount paths are not descriptor-confined: %q -> %q", source, target)
		}
		if filesystem != "" || data != "" || flags != unix.MS_BIND|unix.MS_REC {
			t.Fatalf("mount arguments = %q %#x %q", filesystem, flags, data)
		}
		if err := os.Rename(sourceRoot, sourceRoot+"-moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideSource, sourceRoot); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(destinationRoot, destinationRoot+"-moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideDestination, destinationRoot); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(filepath.Join(source, "marker"))
		if err != nil {
			t.Fatalf("read pinned source after replacement: %v", err)
		}
		if string(contents) != "pinned" {
			t.Fatalf("pinned source contents = %q", contents)
		}
		if info, err := os.Stat(target); err != nil || !info.IsDir() {
			t.Fatalf("pinned destination after replacement = %v, %v", info, err)
		}
		return nil
	}
	mountSetattr := func(_ int, path string, flags uint, attr *unix.MountAttr) error {
		calls = append(calls, "attributes")
		if !strings.HasPrefix(path, "/proc/self/fd/") {
			t.Fatalf("attribute path is not a pinned descriptor: %q", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("destination descriptor closed before attributes: %v", err)
		}
		if flags != unix.AT_RECURSIVE || attr.Attr_set != unix.MOUNT_ATTR_RDONLY {
			t.Fatalf("mount attributes = %#x %#x", flags, attr.Attr_set)
		}
		return nil
	}
	err := mountConfinedVolume(sourceRoot, destinationRoot, protocol.Mount{
		Destination: "/data", Subpath: "nested", ReadOnly: true,
	}, mount, mountSetattr)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"mount", "attributes"}) {
		t.Fatalf("mount ordering = %#v", calls)
	}
	if _, err := os.Lstat(filepath.Join(outsideDestination, "data")); !os.IsNotExist(err) {
		t.Fatalf("replacement destination was modified: %v", err)
	}
}

func TestConfinedVolumeMountRejectsFinalSubpathSymlink(t *testing.T) {
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(sourceRoot, "directory"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("directory", filepath.Join(sourceRoot, "link")); err != nil {
		t.Fatal(err)
	}
	mountCalled := false
	err := mountConfinedVolume(sourceRoot, destinationRoot, protocol.Mount{
		Destination: "/data", Subpath: "link",
	}, func(string, string, string, uintptr, string) error {
		mountCalled = true
		return nil
	}, unix.MountSetattr)
	if err == nil {
		t.Fatal("final VolumeSubpath symlink unexpectedly accepted")
	}
	if mountCalled {
		t.Fatal("mount called for rejected VolumeSubpath")
	}
}

func TestConfinedBindMountAllowsContainedIntermediateSymlink(t *testing.T) {
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(sourceRoot, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destinationRoot, "usr", "lib"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(destinationRoot, "lib")); err != nil {
		t.Fatal(err)
	}
	called := false
	err := mountConfinedBind(sourceRoot, destinationRoot, protocol.Mount{
		Destination: "/lib/modules", Subpath: "nested",
	}, func(_, target, _ string, _ uintptr, _ string) error {
		called = true
		if info, err := os.Stat(target); err != nil || !info.IsDir() {
			t.Fatalf("resolved mount target = %v, %v", info, err)
		}
		return nil
	}, func(int, string, uint, *unix.MountAttr) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("mount was not called for contained intermediate symlink")
	}
	if info, err := os.Stat(filepath.Join(destinationRoot, "usr", "lib", "modules")); err != nil || !info.IsDir() {
		t.Fatalf("contained mountpoint = %v, %v", info, err)
	}
}

func TestConfinedBindAndTmpfsRejectSymlinkedDestinations(t *testing.T) {
	sourceRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(sourceRoot, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"bind", "tmpfs"} {
		t.Run(kind, func(t *testing.T) {
			destinationRoot := t.TempDir()
			outside := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(destinationRoot, "escape")); err != nil {
				t.Fatal(err)
			}
			called := false
			mount := func(string, string, string, uintptr, string) error {
				called = true
				return nil
			}
			var err error
			if kind == "bind" {
				err = mountConfinedBind(sourceRoot, destinationRoot, protocol.Mount{
					Destination: "/escape/data", Subpath: "nested",
				}, mount, unix.MountSetattr)
			} else {
				err = mountConfinedTmpfs(
					destinationRoot, "/escape/data", 0, "", mount,
				)
			}
			if err == nil {
				t.Fatal("symlinked destination unexpectedly accepted")
			}
			if called {
				t.Fatal("mount called for symlinked destination")
			}
			if _, err := os.Lstat(filepath.Join(outside, "data")); !os.IsNotExist(err) {
				t.Fatalf("outside destination changed: %v", err)
			}
		})
	}
}

func TestVolumeReadOnlyIsRecursive(t *testing.T) {
	calls := []string{}
	mountSetattr := func(_ int, path string, flags uint, attr *unix.MountAttr) error {
		calls = append(calls, fmt.Sprintf("%s:%#x:%#x", path, flags, attr.Attr_set))
		return nil
	}
	if err := applyVolumeMountAttributes("/root/data", protocol.Mount{
		ReadOnly: true,
	}, mountSetattr); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		fmt.Sprintf("/root/data:%#x:%#x", uint(unix.AT_RECURSIVE), uint64(unix.MOUNT_ATTR_RDONLY)),
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("mount calls = %#v, want %#v", calls, expected)
	}

	if err := applyVolumeMountAttributes("/root/writable", protocol.Mount{}, mountSetattr); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("writable volume changed mount attributes: %#v", calls)
	}

	failure := func(_ int, _ string, _ uint, _ *unix.MountAttr) error { return unix.EPERM }
	if err := applyVolumeMountAttributes("/root/data", protocol.Mount{
		ReadOnly: true,
	}, failure); err == nil {
		t.Fatal("read-only volume unexpectedly ignored recursive read-only failure")
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
