//go:build linux

package disk

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func EnsureExt4(device, destination, label string) error {
	if err := os.MkdirAll(destination, 0755); err != nil {
		return err
	}
	err := unix.Mount(device, destination, "ext4", unix.MS_NODEV|unix.MS_NOSUID, "errors=remount-ro")
	if err == nil || errors.Is(err, unix.EBUSY) {
		return nil
	}
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("mount ext4 disk: %w", err)
	}
	command := exec.Command("/sbin/mke2fs", "-F", "-t", "ext4", "-L", label, "-O", "metadata_csum,64bit,dir_index,extent", device)
	command.Stdin = nil
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("format ext4 disk: %w", err)
	}
	if err := unix.Mount(device, destination, "ext4", unix.MS_NODEV|unix.MS_NOSUID, "errors=remount-ro"); err != nil {
		return fmt.Errorf("mount formatted ext4 disk: %w", err)
	}
	return nil
}
