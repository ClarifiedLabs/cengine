//go:build linux

package workloadstorage

import (
	"golang.org/x/sys/unix"
	"os"
)

func retainedFDOpen(root int) (int, error) {
	// No fallback: older kernels must fail closed rather than lose confinement.
	return unix.Openat2(root, retainedFDName, &unix.OpenHow{
		Flags:   unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
}
func retainedStat(file *os.File, directory, writable bool) (retainedFDIdentity, error) {
	st, err := retainedStatBasic(file, directory, writable)
	if err != nil {
		return retainedFDIdentity{}, err
	}
	var sx unix.Statx_t
	const mask = unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_TYPE
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, mask, &sx); err != nil {
		return retainedFDIdentity{}, err
	}
	if sx.Mask&mask != mask || sx.Ino != st.Ino || sx.Mode&unix.S_IFMT != uint16(st.Mode&unix.S_IFMT) {
		return retainedFDIdentity{}, ErrInvalidFrame
	}
	return retainedFDIdentity{device: uint64(st.Dev), inode: sx.Ino, mount: sx.Mnt_id}, nil
}
