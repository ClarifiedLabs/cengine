//go:build linux

package boot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
		// PID1-only control filesystem; never an attachment/workload export.
		{"fusectl", "/sys/fs/fuse/connections", "fusectl", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
		{"tmpfs", "/run", "tmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NODEV},
	}
}

func MountKernelFilesystems() error {
	for _, value := range kernelFilesystems() {
		if err := os.MkdirAll(value.target, 0755); err != nil {
			return err
		}
		alreadyMounted := false
		if value.kind == "fusectl" {
			info, err := os.ReadFile("/proc/self/mountinfo")
			if err != nil {
				return err
			}
			alreadyMounted, err = fuseControlMounted(string(info))
			if err != nil {
				return err
			}
		}
		if !alreadyMounted {
			if err := unix.Mount(value.source, value.target, value.kind, value.flags, value.data); err != nil && !errors.Is(err, unix.EBUSY) {
				return fmt.Errorf("mount %s: %w", value.target, err)
			}
		}
		if value.kind == "fusectl" {
			mounted, err := os.ReadFile("/proc/self/mountinfo")
			if err != nil {
				return err
			}
			present, err := fuseControlMounted(string(mounted))
			if err != nil {
				return err
			}
			if !present {
				return errors.New("missing fusectl after mount")
			}
			var info unix.Statfs_t
			if err := unix.Statfs(value.target, &info); err != nil {
				return err
			}
			if info.Type != 0x65735543 {
				return fmt.Errorf("mount %s: not fusectl", value.target)
			}
			if err := unix.Mount("", value.target, "", unix.MS_PRIVATE, ""); err != nil {
				return err
			}
		}
	}
	if err := linkPseudoTerminalMultiplexer("/dev"); err != nil {
		return fmt.Errorf("link pseudo-terminal multiplexer: %w", err)
	}
	return nil
}

// Refuse a substituted or stacked control mount; do not mount over it.
func fuseControlMounted(info string) (bool, error) {
	found := false
	for _, line := range strings.Split(info, "\n") {
		p := strings.Fields(line)
		if len(p) < 5 || p[4] != "/sys/fs/fuse/connections" {
			continue
		}
		if found {
			return false, errors.New("stacked fusectl mount")
		}
		sep := 0
		for i := 6; i < len(p); i++ {
			if p[i] == "-" {
				sep = i
				break
			}
		}
		if sep == 0 || sep+3 >= len(p) || p[3] != "/" || p[sep+1] != "fusectl" {
			return false, errors.New("substituted fusectl mount")
		}
		flags := "," + p[5] + ","
		for _, required := range []string{"nosuid", "nodev", "noexec"} {
			if !strings.Contains(flags, ","+required+",") {
				return false, errors.New("unsafe fusectl mount flags")
			}
		}
		found = true
	}
	return found, nil
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
