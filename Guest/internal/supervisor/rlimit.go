//go:build linux

package supervisor

import (
	"fmt"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

var linuxRlimitResources = map[string]int{
	"core":       unix.RLIMIT_CORE,
	"cpu":        unix.RLIMIT_CPU,
	"data":       unix.RLIMIT_DATA,
	"fsize":      unix.RLIMIT_FSIZE,
	"locks":      unix.RLIMIT_LOCKS,
	"memlock":    unix.RLIMIT_MEMLOCK,
	"msgqueue":   unix.RLIMIT_MSGQUEUE,
	"nice":       unix.RLIMIT_NICE,
	"nofile":     unix.RLIMIT_NOFILE,
	"nproc":      unix.RLIMIT_NPROC,
	"rss":        unix.RLIMIT_RSS,
	"rtprio":     unix.RLIMIT_RTPRIO,
	"rttime":     unix.RLIMIT_RTTIME,
	"sigpending": unix.RLIMIT_SIGPENDING,
	"stack":      unix.RLIMIT_STACK,
}

func applyRlimits(
	limits []protocol.Rlimit,
	setrlimit func(resource int, limit *unix.Rlimit) error,
) error {
	seen := make(map[string]struct{}, len(limits))
	for _, value := range limits {
		resource, ok := linuxRlimitResources[value.Type]
		if !ok {
			return fmt.Errorf("unknown rlimit %q", value.Type)
		}
		if _, duplicate := seen[value.Type]; duplicate {
			return fmt.Errorf("duplicate rlimit %q", value.Type)
		}
		seen[value.Type] = struct{}{}
		if value.Hard != unix.RLIM_INFINITY &&
			(value.Soft == unix.RLIM_INFINITY || value.Soft > value.Hard) {
			return fmt.Errorf("rlimit %q soft value exceeds hard value", value.Type)
		}
		limit := unix.Rlimit{Cur: value.Soft, Max: value.Hard}
		if err := setrlimit(resource, &limit); err != nil {
			return fmt.Errorf("set rlimit %s: %w", value.Type, err)
		}
	}
	return nil
}
