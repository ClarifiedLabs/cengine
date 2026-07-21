//go:build linux

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

type recordedPathPolicyMount struct {
	source     string
	target     string
	filesystem string
	flags      uintptr
}

func TestReadonlyPathsRetainSecurityFlagsAndIgnoreMissingTargets(t *testing.T) {
	var calls []recordedPathPolicyMount
	mount := func(source, target, filesystem string, flags uintptr, _ string) error {
		if target == "/missing" {
			return unix.ENOENT
		}
		calls = append(calls, recordedPathPolicyMount{source, target, filesystem, flags})
		return nil
	}
	statfs := func(path string, status *unix.Statfs_t) error {
		if path != "/proc/sys" {
			return fmt.Errorf("unexpected statfs path %q", path)
		}
		status.Flags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RELATIME
		return nil
	}
	if err := applyReadonlyPaths([]string{"/proc/sys", "/missing"}, mount, statfs); err != nil {
		t.Fatal(err)
	}
	want := []recordedPathPolicyMount{
		{"/proc/sys", "/proc/sys", "", unix.MS_BIND | unix.MS_REC},
		{"", "/proc/sys", "", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("mount calls = %#v, want %#v", calls, want)
	}
}

func TestMaskedPathsUseReadonlyTmpfsForDirectoriesAndVerifiedDeviceForFiles(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "directory")
	file := filepath.Join(root, "file")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []recordedPathPolicyMount
	mount := func(source, target, filesystem string, flags uintptr, _ string) error {
		calls = append(calls, recordedPathPolicyMount{source, target, filesystem, flags})
		return nil
	}
	if err := maskPaths(
		[]string{directory, file, filepath.Join(root, "missing")},
		"/proc/self/fd/9", os.Stat, mount,
	); err != nil {
		t.Fatal(err)
	}
	want := []recordedPathPolicyMount{
		{"tmpfs", directory, "tmpfs", unix.MS_RDONLY},
		{"/proc/self/fd/9", file, "", unix.MS_BIND},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("mount calls = %#v, want %#v", calls, want)
	}
}

func TestPathPoliciesRejectRelativePaths(t *testing.T) {
	mount := func(string, string, string, uintptr, string) error {
		t.Fatal("relative path reached mount")
		return nil
	}
	if err := applyReadonlyPaths(
		[]string{"proc/sys"}, mount, func(string, *unix.Statfs_t) error { return nil },
	); err == nil {
		t.Fatal("relative read-only path unexpectedly accepted")
	}
	if err := maskPaths(
		[]string{"proc/kcore"}, "/dev/null",
		func(string) (os.FileInfo, error) { return nil, nil }, mount,
	); err == nil {
		t.Fatal("relative masked path unexpectedly accepted")
	}
}

func TestPathPolicyDetectsIdentityFileMasks(t *testing.T) {
	for _, paths := range [][]string{
		{"/etc/passwd"}, {"/etc/group"}, {"/etc"}, {"/"},
	} {
		if !pathPolicyMasksUserDatabase(paths) {
			t.Fatalf("identity mask not detected: %#v", paths)
		}
	}
	for _, paths := range [][]string{
		nil, {"/proc/kcore"}, {"/etc/passwd.d"}, {"etc/passwd"},
	} {
		if pathPolicyMasksUserDatabase(paths) {
			t.Fatalf("unrelated mask treated as identity mask: %#v", paths)
		}
	}
}
