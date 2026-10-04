//go:build linux

package disk

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const promotionMountFlags = unix.MS_NODEV | unix.MS_NOSUID
const promotionMountData = "errors=remount-ro,data=ordered"

func (linuxExt4Ops) mountJournaled(d *pinnedDevice, target *pinnedTarget) error {
	// New journaled superblock, only after clean/no-recovery proof while
	// unmounted. Never use mount()/pinnedMountSource or reopen the device.
	return unix.Mount(fmt.Sprintf("/proc/self/fd/%d", d.file.Fd()), fmt.Sprintf("/proc/self/fd/%d", target.file.Fd()), "ext4", promotionMountFlags, promotionMountData)
}
