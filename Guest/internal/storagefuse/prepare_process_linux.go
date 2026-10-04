//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

type linuxPrepareProcess struct {
	proc  *os.File // pinned TGID directory, never reopened by numeric PID
	root  *os.File // pinned procfs root in the mount creator's PID namespace
	pidfd int
	tgid  uint32
	start uint64
	// Serialized by prepareProcessGate.mu after publication.
	failure processMatchFailure
}

func prepareProcDir(parent int, name string) (*os.File, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		return nil, ErrProfile
	}
	return os.NewFile(uintptr(fd), "prepare-proc"), nil
}

func prepareProcRead(dir *os.File, name string) (string, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "prepare-proc-field")
	defer file.Close()
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return "", ErrProfile
	}
	// Tgid precedes potentially enormous supplementary-group lists. Only the
	// bounded prefix is needed; stat itself is smaller than this bound.
	data, err := io.ReadAll(io.LimitReader(file, 8192))
	return string(data), err
}

func prepareTaskLive(dir *os.File, tid uint32) (uint64, bool) {
	data, err := prepareProcRead(dir, "stat")
	if err != nil {
		return 0, false
	}
	return prepareProcStat(data, tid)
}

func pinPrepareProcess(tid uint32) (prepareProcess, error) {
	if tid == 0 {
		return nil, ErrProfile
	}
	proc, err := prepareProcDir(unix.AT_FDCWD, "/proc")
	if err != nil {
		return nil, err
	}
	defer func() {
		if proc != nil {
			proc.Close()
		}
	}()
	// Header IDs use the mount creator's PID namespace. Reject a procfs from
	// any other PID namespace, even when it is genuine procfs.
	self := make([]byte, 32)
	n, err := unix.Readlinkat(int(proc.Fd()), "self", self)
	if err != nil || string(self[:n]) != strconv.Itoa(os.Getpid()) {
		return nil, ErrProfile
	}
	task, err := prepareProcDir(int(proc.Fd()), strconv.FormatUint(uint64(tid), 10))
	if err != nil {
		return nil, err
	}
	defer task.Close()
	status, err := prepareProcRead(task, "status")
	tgid, ok := prepareProcTGID(status)
	if err != nil || !ok {
		return nil, ErrProfile
	}
	owner, err := prepareProcDir(int(proc.Fd()), strconv.FormatUint(uint64(tgid), 10))
	if err != nil {
		return nil, err
	}
	p := &linuxPrepareProcess{proc: owner, root: proc, pidfd: -1, tgid: tgid}
	proc = nil // p now owns both retained procfs descriptors
	good := false
	defer func() {
		if !good {
			p.close()
		}
	}()
	p.pidfd, err = unix.PidfdOpen(int(tgid), 0)
	if err != nil {
		return nil, err // no starttime-only fallback
	}
	leaderStat, statErr := prepareProcRead(owner, "stat")
	p.start, ok = prepareProcIdentity(leaderStat, tgid, true)
	ok = ok && statErr == nil
	if !ok || !p.matches(tid) {
		return nil, ErrProfile
	}
	// The first retained task descriptor must still describe the same live
	// TID as the TGID-checked member. A proc descriptor remains attached to
	// its original struct pid; it cannot silently adopt a recycled number.
	member, err := p.thread(tid)
	if err != nil {
		return nil, err
	}
	defer member.Close()
	memberStart, memberLive := prepareTaskLive(member, tid)
	taskStart, taskLive := prepareTaskLive(task, tid)
	if !memberLive || !taskLive || memberStart != taskStart || !p.matches(tid) {
		return nil, ErrProfile
	}
	good = true
	return p, nil
}

func (p *linuxPrepareProcess) lastMatchFailure() processMatchFailure { return p.failure }

func (p *linuxPrepareProcess) thread(tid uint32) (*os.File, error) {
	// /proc/<tgid>/task can disappear when the leader exits before its
	// workers. Direct /proc/<tid> plus kernel Tgid remains usable then.
	task, err := prepareProcDir(int(p.root.Fd()), strconv.FormatUint(uint64(tid), 10))
	if err != nil {
		p.failure = processMatchFailure{matchMemberDir, err}
		return nil, err
	}
	status, err := prepareProcRead(task, "status")
	tgid, ok := prepareProcTGID(status)
	if err != nil || !ok || tgid != p.tgid {
		p.failure = processMemberFailure(tgid, p.tgid, ok, err)
		task.Close()
		return nil, ErrProfile
	}
	return task, nil
}

func pollPreparePIDFD(fd int) (int, int16, error) {
	// Recreate the output buffer on each attempt; EINTR output is not evidence.
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	return n, fds[0].Revents, err
}

func (p *linuxPrepareProcess) live(final bool) bool {
	return p.liveWithPoll(final, pollPreparePIDFD)
}

// Private syscall seam for deterministic EINTR tests. Production always uses
// pollPreparePIDFD; ownership and procfs identity checks are never substituted.
func (p *linuxPrepareProcess) liveWithPoll(final bool, poll func(int) (int, int16, error)) bool {
	if p.pidfd < 0 || p.proc == nil {
		p.failure = processMatchFailure{stage: matchClosed}
		return false
	}
	n, events, err := pollPrepareProcess(p.pidfd, poll)
	p.failure = processPollFailure(final, n, events, err)
	if p.failure.stage != matchNone {
		return false // includes death, invalid FD and poll errors
	}
	data, err := prepareProcRead(p.proc, "stat")
	start, ok := prepareProcIdentity(data, p.tgid, true)
	p.failure = processStatFailure(true, start, p.start, ok, err)
	return err == nil && ok && start == p.start
}

func (p *linuxPrepareProcess) matches(tid uint32) bool {
	return p.matchesWithPoll(tid, pollPreparePIDFD)
}

func (p *linuxPrepareProcess) matchesWithPoll(tid uint32, poll func(int) (int, int16, error)) bool {
	p.failure = processMatchFailure{}
	if tid == 0 {
		p.failure.stage = matchZeroTID
		return false
	}
	if !p.liveWithPoll(false, poll) {
		return false
	}
	task, err := p.thread(tid)
	if err != nil {
		return false
	}
	defer task.Close()
	data, err := prepareProcRead(task, "stat")
	start, ok := prepareProcStat(data, tid)
	p.failure = processStatFailure(false, start, 0, ok, err)
	return err == nil && ok && p.liveWithPoll(true, poll)
}

func (p *linuxPrepareProcess) close() {
	if p.pidfd >= 0 {
		unix.Close(p.pidfd)
		p.pidfd = -1
	}
	if p.proc != nil {
		p.proc.Close()
		p.proc = nil
	}
	if p.root != nil {
		p.root.Close()
		p.root = nil
	}
}
