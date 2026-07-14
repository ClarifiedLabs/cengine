//go:build linux

package boot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type kernelFilesystem struct {
	source string
	target string
	kind   string
	data   string
	flags  uintptr
}

func kernelFilesystems() []kernelFilesystem {
	return []kernelFilesystem{
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID},
		{"devpts", "/dev/pts", "devpts", "ptmxmode=0666,mode=0620", unix.MS_NOSUID | unix.MS_NOEXEC},
		{"proc", "/proc", "proc", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
		{"sysfs", "/sys", "sysfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
		{"tmpfs", "/run", "tmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NODEV},
	}
}

func MountKernelFilesystems() error {
	for _, value := range kernelFilesystems() {
		if err := os.MkdirAll(value.target, 0755); err != nil {
			return err
		}
		if err := unix.Mount(value.source, value.target, value.kind, value.flags, value.data); err != nil && !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("mount %s: %w", value.target, err)
		}
	}
	if err := linkPseudoTerminalMultiplexer("/dev"); err != nil {
		return fmt.Errorf("link pseudo-terminal multiplexer: %w", err)
	}
	return nil
}

func linkPseudoTerminalMultiplexer(deviceRoot string) error {
	path := filepath.Join(deviceRoot, "ptmx")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Symlink("pts/ptmx", path)
}

func MountVirtioFS(tag, target string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	if err := unix.Mount(tag, target, "virtiofs", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
		return fmt.Errorf("mount virtiofs %s: %w", tag, err)
	}
	return nil
}
