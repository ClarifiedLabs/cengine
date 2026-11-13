//go:build linux

package storageboot

import "golang.org/x/sys/unix"

// Open only the real console character device, never a redirected path. A single
// nonblocking write is diagnostic-only: failure cannot affect DATA or shutdown.
func writeDataFailureConsole(line []byte) {
	fd, err := unix.Open("/dev/console", unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	writeDataFailureConsoleFD(fd, line)
}

func writeDataFailureConsoleFD(fd int, line []byte) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || uint64(st.Rdev) != unix.Mkdev(5, 1) {
		return
	}
	_, _ = unix.Write(fd, line)
}
