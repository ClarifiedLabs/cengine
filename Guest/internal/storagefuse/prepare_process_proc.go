package storagefuse

import (
	"strconv"
	"strings"
)

// Linux /proc/<tid>/stat: comm can contain whitespace and ')' characters.
// Starttime is field 22; it is supplementary evidence, not a PID-reuse lock.
func prepareProcStat(data string, pid uint32) (uint64, bool) {
	return prepareProcIdentity(data, pid, false)
}

// A zombie leader does not imply a dead process: pidfd polling supplies TGID
// liveness while this retained proc record supplies its immutable starttime.
func prepareProcIdentity(data string, pid uint32, leader bool) (uint64, bool) {
	left, right := strings.IndexByte(data, '('), strings.LastIndexByte(data, ')')
	if left < 1 || right <= left {
		return 0, false
	}
	id, err := strconv.ParseUint(strings.TrimSpace(data[:left]), 10, 32)
	fields := strings.Fields(data[right+1:])
	if err != nil || id != uint64(pid) || len(fields) < 20 || len(fields[0]) != 1 || strings.ContainsAny(fields[0], "Xx") || (!leader && fields[0] == "Z") {
		return 0, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	// Field 22 is clock ticks since boot, so early-created PID1 may have zero.
	// Retained procfs descriptors and a live pidfd, not a nonzero timestamp,
	// protect this process identity against numeric PID reuse.
	return start, err == nil
}

func prepareProcTGID(data string) (uint32, bool) {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			id, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")), 10, 32)
			return uint32(id), err == nil && id > 0
		}
	}
	return 0, false
}
