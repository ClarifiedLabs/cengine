//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type pathStatOperation func(string) (os.FileInfo, error)
type statfsOperation func(string, *unix.Statfs_t) error

const workloadUserDatabaseSnapshotPath = "/run/cengine/user-database"

func pathPolicyMasksUserDatabase(paths []string) bool {
	for _, path := range paths {
		masked := filepath.Clean(path)
		for _, identityFile := range []string{"/etc/passwd", "/etc/group"} {
			if masked == "/" || masked == identityFile || strings.HasPrefix(identityFile, masked+"/") {
				return true
			}
		}
	}
	return false
}

func snapshotUserDatabase(root, destination string) error {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return fmt.Errorf("create workload user database snapshot: %w", err)
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		return fmt.Errorf("secure workload user database snapshot: %w", err)
	}
	for _, name := range []string{"passwd", "group"} {
		data, err := os.ReadFile(filepath.Join(root, "etc", name))
		if errors.Is(err, os.ErrNotExist) {
			data = nil
		} else if err != nil {
			return fmt.Errorf("read workload %s before applying masked paths: %w", name, err)
		}
		path := filepath.Join(destination, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("snapshot workload %s before applying masked paths: %w", name, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("secure workload %s snapshot: %w", name, err)
		}
	}
	return nil
}

func validatePolicyPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("runtime policy path %q is not absolute", path)
	}
	return nil
}

// applyReadonlyPaths follows the OCI/runc two-mount sequence: create a private
// recursive bind at each path, then remount that bind read-only while retaining
// the security-relevant flags inherited from the underlying filesystem.
func applyReadonlyPaths(paths []string, mount mountOperation, statfs statfsOperation) error {
	for _, path := range paths {
		if err := validatePolicyPath(path); err != nil {
			return err
		}
		if err := mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("make %q a private bind: %w", path, err)
		}
		var status unix.Statfs_t
		if err := statfs(path, &status); err != nil {
			return fmt.Errorf("inspect filesystem for read-only path %q: %w", path, err)
		}
		securityFlags := uintptr(status.Flags) & (unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
		if err := mount(
			"", path, "",
			securityFlags|unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY,
			"",
		); err != nil {
			return fmt.Errorf("remount %q read-only: %w", path, err)
		}
	}
	return nil
}

func applyMaskedPaths(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	devNull, err := unix.Open("/dev/null", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open trusted /dev/null for masked paths: %w", err)
	}
	defer unix.Close(devNull)
	var status unix.Stat_t
	if err := unix.Fstat(devNull, &status); err != nil {
		return fmt.Errorf("inspect trusted /dev/null for masked paths: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFCHR || uint64(status.Rdev) != unix.Mkdev(1, 3) {
		return errors.New("masked paths require /dev/null to be character device 1:3")
	}
	return maskPaths(
		paths, fmt.Sprintf("/proc/self/fd/%d", devNull), os.Stat, unix.Mount,
	)
}

// maskPaths covers directories with an empty read-only tmpfs and files with a
// bind of a verified /dev/null descriptor. Missing targets are intentionally
// ignored, matching runc's OCI behavior.
func maskPaths(
	paths []string,
	devNullSource string,
	stat pathStatOperation,
	mount mountOperation,
) error {
	for _, path := range paths {
		if err := validatePolicyPath(path); err != nil {
			return err
		}
		info, err := stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("inspect masked path %q: %w", path, err)
		}
		if info.IsDir() {
			err = mount("tmpfs", path, "tmpfs", unix.MS_RDONLY, "")
		} else {
			err = mount(devNullSource, path, "", unix.MS_BIND, "")
		}
		if err != nil {
			return fmt.Errorf("mask path %q: %w", path, err)
		}
	}
	return nil
}
