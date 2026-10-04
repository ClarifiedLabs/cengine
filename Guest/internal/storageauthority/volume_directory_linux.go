//go:build linux

package storageauthority

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// NO_XDEV rejects mount transitions including same-device bind mounts. Do not
// fall back on ENOSYS: activation requires a kernel with confined openat2.
func volumeDirectory(dir *os.File, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat2(int(dir.Fd()), name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
