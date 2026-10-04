//go:build linux

package workloadstorage

import (
	"strconv"

	"golang.org/x/sys/unix"
)

func emitMountFailure(line string) { emitMountFailureTo(2, line) }

// PID1's stderr is the guest console. Open a separate nonblocking description:
// dup/F_SETFL would change flags on the inherited stderr description as well.
// One best-effort write, no retries, logger locks, arbitrary writers or workers.
// A full/failed sink may lose the diagnostic but must never prevent retirement.
func emitMountFailureTo(stderr int, line string) {
	var before unix.Stat_t
	if unix.Fstat(stderr, &before) != nil {
		return
	}
	kind := before.Mode & unix.S_IFMT
	if kind != unix.S_IFCHR && kind != unix.S_IFIFO {
		return // regular files/sockets do not provide this nonblocking console sink
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(stderr), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Rdev != after.Rdev || before.Mode&unix.S_IFMT != after.Mode&unix.S_IFMT {
		return
	}
	_, _ = unix.Write(fd, []byte(line+"\n")) // closed vocabulary, well below PIPE_BUF
}
