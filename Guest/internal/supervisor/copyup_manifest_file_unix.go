//go:build darwin || linux

package supervisor

import (
	"errors"
	"os"

	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

// managedManifestFile consumes the exclusively owned descriptor on every path.
// The caller opens with O_NONBLOCK to avoid waiting on a substituted FIFO. Keep
// that protection until Fstat proves this exact fd is a bounded regular file.
// Then clear it BEFORE NewFile: wrapping an O_NONBLOCK FUSE fd registers it with
// Go's runtime epoll, whose raw epoll_ctl can wait for this same process's FUSE
// server while occupying its only P (see go-fuse/fuse/poll.go). Regular-file IO
// uses ordinary scheduler-aware syscalls instead. No FUSE/auth policy changes.
func managedManifestFile(fd int) (file *os.File, err error) {
	defer func() {
		if file == nil {
			_ = unix.Close(fd)
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || stat.Size > a.MaxCopyManifestBytes {
		return nil, errors.New("unbounded managed journal")
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		return nil, err
	}
	file = os.NewFile(uintptr(fd), "managed-copy-up-manifest")
	if file == nil {
		return nil, errors.New("open managed journal descriptor")
	}
	return file, nil
}
