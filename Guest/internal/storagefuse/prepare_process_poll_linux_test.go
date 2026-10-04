//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Real retained procfs/pidfd identity, with deterministic interruption of only
// the poll syscall. No signal timing, global hooks, or production activation.
func TestPrepareProcessLinuxPollEINTR(t *testing.T) {
	for _, tc := range []struct {
		name          string
		final         bool
		interruptions int
	}{
		{"first", false, 1},
		{"final", true, 1},
		{"last-attempt", false, prepareProcessPollAttempts - 1},
		{"exhausted-first", false, prepareProcessPollAttempts},
		{"exhausted-final", true, prepareProcessPollAttempts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pinnedPollTestOwner(t)
			calls, interrupted := 0, 0
			ok := p.matchesWithPoll(uint32(os.Getpid()), func(fd int) (int, int16, error) {
				calls++
				if fd != p.pidfd {
					t.Fatal("pidfd changed")
				}
				if (!tc.final || calls > 1) && interrupted < tc.interruptions {
					interrupted++
					return -1, 0, unix.EINTR
				}
				return pollPreparePIDFD(fd)
			})
			if tc.interruptions == prepareProcessPollAttempts {
				stage := matchFirstPoll
				wantCalls := prepareProcessPollAttempts
				if tc.final {
					stage = matchFinalPoll
					wantCalls++
				}
				if ok || calls != wantCalls || p.failure.stage != stage || p.failure.cause != unix.EINTR {
					t.Fatal("persistent interruption did not fail closed", ok, calls, p.failure)
				}
			} else if !ok || calls != tc.interruptions+2 || p.failure != (processMatchFailure{}) {
				t.Fatal("retry bypassed/failed identity checks", ok, calls, p.failure)
			}
			// The next complete evaluation must clear any exhausted diagnostic.
			if !p.matches(uint32(os.Getpid())) || p.failure != (processMatchFailure{}) {
				t.Fatal("failure persisted after recovery", p.failure)
			}
		})
	}

	t.Run("error-after-interrupt", func(t *testing.T) {
		for _, err := range []error{unix.EBADF, unix.EIO} {
			p := pinnedPollTestOwner(t)
			calls := 0
			if p.matchesWithPoll(uint32(os.Getpid()), func(int) (int, int16, error) {
				calls++
				if calls == 1 {
					return -1, 0, unix.EINTR
				}
				return -1, 0, err
			}) || calls != 2 || p.failure.stage != matchFirstPoll || p.failure.cause != err {
				t.Fatal("non-EINTR failure retried or accepted", calls, p.failure)
			}
		}
	})
	t.Run("ready-after-interrupt", func(t *testing.T) {
		for _, events := range []int16{unix.POLLIN, unix.POLLHUP, unix.POLLERR, unix.POLLNVAL} {
			p := pinnedPollTestOwner(t)
			calls := 0
			if p.matchesWithPoll(uint32(os.Getpid()), func(int) (int, int16, error) {
				calls++
				if calls == 1 {
					return -1, 0, unix.EINTR
				}
				return 1, events, nil
			}) || calls != 2 || p.failure.stage != matchFirstReady {
				t.Fatal("readiness retried or accepted", calls, p.failure)
			}
		}
	})
	t.Run("starttime-after-interrupt", func(t *testing.T) {
		p := pinnedPollTestOwner(t)
		p.start++
		calls := 0
		if p.matchesWithPoll(uint32(os.Getpid()), interruptedRealPoll(&calls)) || calls != 2 || p.failure.stage != matchLeaderStart {
			t.Fatal("retry bypassed retained starttime", calls, p.failure)
		}
	})
	t.Run("foreign-thread", func(t *testing.T) {
		p := pinnedPollTestOwner(t)
		parent := uint32(os.Getppid())
		if parent == 0 || parent == uint32(os.Getpid()) {
			t.Fatal("live foreign process control required")
		}
		calls := 0
		if p.matchesWithPoll(parent, interruptedRealPoll(&calls)) || calls != 2 || p.failure.stage != matchMemberTGIDMismatch {
			t.Fatal("retry bypassed TGID membership", calls, p.failure)
		}
	})
	t.Run("closed-owner", func(t *testing.T) {
		p := pinnedPollTestOwner(t)
		p.close()
		calls := 0
		if p.matchesWithPoll(uint32(os.Getpid()), interruptedRealPoll(&calls)) || calls != 0 || p.failure.stage != matchClosed {
			t.Fatal("closed owner polled or accepted", calls, p.failure)
		}
	})
}

func pinnedPollTestOwner(t *testing.T) *linuxPrepareProcess {
	t.Helper()
	owner, err := pinPrepareProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.close)
	return owner.(*linuxPrepareProcess)
}

func interruptedRealPoll(calls *int) func(int) (int, int16, error) {
	return func(fd int) (int, int16, error) {
		*calls++
		if *calls == 1 {
			return -1, 0, unix.EINTR
		}
		return pollPreparePIDFD(fd)
	}
}
