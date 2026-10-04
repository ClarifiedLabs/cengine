//go:build linux

package workloadstorage

import "golang.org/x/sys/unix"

func retainedReadOpen(root int) (int, error) {
	return unix.Openat2(root, retainedReadName, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOATIME,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
}
