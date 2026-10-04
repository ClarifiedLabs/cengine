//go:build linux

package disk

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// VerifyInheritedMountedExt4 verifies only an existing exact ext4 mount in the
// caller's inherited namespace. Unlike MountExistingExt4, it never opens a block
// device for data access: stage 2 is already under the workload's device cgroup.
// PID1 must have mounted and verified the root before cloning this namespace.
// Caller exclusion of privileged namespace/device mutation remains mandatory.
// This is not a UUID/capacity observation or initialization authorization.
func VerifyInheritedMountedExt4(device, destination string) error {
	return verifyInheritedMountedExt4(&explicitTransitionMu, linuxInheritedMountOps{}, device, destination)
}

type linuxInheritedMountOps struct{ linuxExt4Ops }

func (linuxInheritedMountOps) pinDeviceMetadata(path string) (*pinnedDevice, error) {
	parent, err := secureDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	// O_PATH obtains only the node identity. No device open callback, data access,
	// ioctl, or flock is performed; the device-cgroup read/write denial stays intact.
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		file.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Uid != 0 {
		file.Close()
		return nil, fmt.Errorf("not a root-owned block device")
	}
	return &pinnedDevice{file, unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))}, nil
}

func (linuxInheritedMountOps) verifyTargetDevice(target *pinnedTarget, device *pinnedDevice) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(target.file.Fd()), &st); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(target.file.Fd()), &fs); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || fs.Type != unix.EXT4_SUPER_MAGIC ||
		unix.Major(uint64(st.Dev)) != device.major || unix.Minor(uint64(st.Dev)) != device.minor {
		return fmt.Errorf("inherited root filesystem identity changed")
	}
	return nil
}
