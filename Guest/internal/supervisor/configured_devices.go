//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

type standardDevice struct {
	mode uint32
	dev  int
}

var workloadStandardDevices = map[string]standardDevice{
	"null":    {mode: unix.S_IFCHR | 0666, dev: int(unix.Mkdev(1, 3))},
	"zero":    {mode: unix.S_IFCHR | 0666, dev: int(unix.Mkdev(1, 5))},
	"full":    {mode: unix.S_IFCHR | 0666, dev: int(unix.Mkdev(1, 7))},
	"random":  {mode: unix.S_IFCHR | 0666, dev: int(unix.Mkdev(1, 8))},
	"urandom": {mode: unix.S_IFCHR | 0666, dev: int(unix.Mkdev(1, 9))},
	"tty":     {mode: unix.S_IFCHR | 0666, dev: int(unix.Mkdev(5, 0))},
}

func normalizedDeviceRelative(path string) (string, error) {
	if !strings.HasPrefix(path, "/dev/") || strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("device destination %q is not beneath /dev", path)
	}
	relative := strings.TrimPrefix(path, "/dev/")
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("device destination %q is not normalized", path)
	}
	return relative, nil
}

func openDeviceParent(devRoot int, relative string) (int, string, error) {
	parts := strings.Split(relative, "/")
	parent, err := unix.Dup(devRoot)
	if err != nil {
		return -1, "", err
	}
	for _, component := range parts[:len(parts)-1] {
		if component == "" || component == "." || component == ".." {
			unix.Close(parent)
			return -1, "", fmt.Errorf("invalid device destination component %q", component)
		}
		if err := unix.Mkdirat(parent, component, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(parent)
			return -1, "", err
		}
		next, err := unix.Openat(parent, component, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(parent)
		if err != nil {
			return -1, "", err
		}
		parent = next
	}
	return parent, parts[len(parts)-1], nil
}

func createDeviceAt(devRoot int, relative string, mode uint32, device int) error {
	parent, name, err := openDeviceParent(devRoot, relative)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if err := unix.Unlinkat(parent, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := unix.Mknodat(parent, name, mode, device); err != nil {
		return err
	}
	return chmodDeviceAt(parent, name, mode&07777)
}

func chmodDeviceAt(parent int, name string, mode uint32) error {
	return unix.Fchmodat(parent, name, mode, unix.AT_SYMLINK_NOFOLLOW)
}

func removeOrRestoreDeviceAt(devRoot int, relative string) error {
	if standard, ok := workloadStandardDevices[relative]; ok {
		return createDeviceAt(devRoot, relative, standard.mode, standard.dev)
	}
	parent, name, err := openDeviceParent(devRoot, relative)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if err := unix.Unlinkat(parent, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func replaceConfiguredDevices(
	root string, old, desired []protocol.DeviceMapping,
	lstat func(string, *unix.Stat_t) error,
) error {
	devRoot, err := unix.Open(filepath.Join(root, "dev"), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open workload device root: %w", err)
	}
	defer unix.Close(devRoot)
	desiredPaths := map[string]bool{}
	for _, device := range desired {
		relative, err := normalizedDeviceRelative(device.PathInContainer)
		if err != nil {
			return err
		}
		desiredPaths[relative] = true
	}
	for _, device := range old {
		relative, err := normalizedDeviceRelative(device.PathInContainer)
		if err != nil {
			return err
		}
		if !desiredPaths[relative] {
			if err := removeOrRestoreDeviceAt(devRoot, relative); err != nil {
				return fmt.Errorf("remove configured device %s: %w", device.PathInContainer, err)
			}
		}
	}
	for _, device := range desired {
		var status unix.Stat_t
		if err := lstat(device.PathOnHost, &status); err != nil {
			return fmt.Errorf("inspect configured device %s: %w", device.PathOnHost, err)
		}
		if _, err := deviceType(status.Mode); err != nil {
			return fmt.Errorf("configured device %s %w", device.PathOnHost, err)
		}
		relative, _ := normalizedDeviceRelative(device.PathInContainer)
		if err := createDeviceAt(devRoot, relative, status.Mode, int(status.Rdev)); err != nil {
			return fmt.Errorf("create configured device %s: %w", device.PathInContainer, err)
		}
	}
	return nil
}

func applyConfiguredDevices(
	root string, old, desired []protocol.DeviceMapping,
	lstat func(string, *unix.Stat_t) error,
) error {
	if err := replaceConfiguredDevices(root, old, desired, lstat); err != nil {
		if rollbackErr := replaceConfiguredDevices(root, desired, old, lstat); rollbackErr != nil {
			return &ResourceRollbackIncompleteError{
				UpdateError: err,
				RollbackErrors: []error{
					fmt.Errorf("restore configured devices: %w", rollbackErr),
				},
			}
		}
		return err
	}
	return nil
}

func applyConfiguredDevicesForHost(root string, old, desired []protocol.DeviceMapping) error {
	return applyConfiguredDevices(root, old, desired, unix.Lstat)
}

func createStandardDevices(root string) error {
	names := make([]string, 0, len(workloadStandardDevices))
	for name := range workloadStandardDevices {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		device := workloadStandardDevices[name]
		path := filepath.Join(root, "dev", name)
		if err := unix.Mknod(path, device.mode, device.dev); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		if err := unix.Chmod(path, device.mode&07777); err != nil {
			return err
		}
	}
	return nil
}
