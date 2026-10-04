//go:build linux || darwin

package supervisor

import (
	"errors"
	"io"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// os.OpenFile/os.ReadFile register regular FUSE files with Go's netpoller on
// Linux, issuing an incidental POLL before the intended I/O. These fixture-only
// helpers keep actual mounted WRITE/READ and file/directory FSYNC, without that
// registration. The existing native process deadline still bounds syscalls.
func snapshot101Progress(mount, value string) (err error) {
	if err = snapshot101WriteProgress(filepath.Join(mount, "progress"), value); err != nil {
		return err
	}
	fd, err := unix.Open(mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	return unix.Fsync(fd)
}

func snapshot101WriteProgress(path, value string) (err error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	n, err := unix.Write(fd, []byte(value))
	if err != nil {
		return err
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	return unix.Fsync(fd)
}

var errSnapshot101Readback = errors.New("snapshot101 mounted bytes differ")

func snapshot101Readback(path, want string) (err error) {
	// This fixture's probe is small and fixed; do not grow an unbounded read.
	if len(want) == 0 || len(want) > 4096 {
		return errSnapshot101Readback
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	data := make([]byte, len(want)+1)
	n, err := unix.Pread(fd, data, 0)
	if err != nil {
		return err
	}
	if n != len(want) || string(data[:n]) != want {
		return errSnapshot101Readback
	}
	return nil
}
