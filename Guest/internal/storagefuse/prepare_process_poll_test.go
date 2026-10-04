package storagefuse

import (
	"syscall"
	"testing"
)

func TestPrepareProcessPollInterrupted(t *testing.T) {
	for _, interruptions := range []int{0, 1, prepareProcessPollAttempts - 1, prepareProcessPollAttempts} {
		calls := 0
		n, events, err := pollPrepareProcess(71, func(fd int) (int, int16, error) {
			calls++
			if fd != 71 {
				t.Fatal("retained descriptor changed", fd)
			}
			if calls <= interruptions {
				return -1, 0, syscall.EINTR
			}
			return 0, 0, nil
		})
		if interruptions == prepareProcessPollAttempts {
			if calls != prepareProcessPollAttempts || n != -1 || events != 0 || err != syscall.EINTR {
				t.Fatal("interruption budget did not fail closed", calls, n, events, err)
			}
		} else if calls != interruptions+1 || n != 0 || events != 0 || err != nil {
			t.Fatal("interrupted poll did not recover", calls, n, events, err)
		}
	}
}

func TestPrepareProcessPollPreservesRejection(t *testing.T) {
	for _, result := range []struct {
		n      int
		events int16
		err    error
	}{
		{1, 1, nil},  // pidfd ready: process exited
		{0, 32, nil}, // POLLNVAL, even if the ready count is inconsistent
		{-1, 0, syscall.EBADF},
		{-1, 0, syscall.EIO},
	} {
		for _, interrupted := range []bool{false, true} {
			calls := 0
			n, events, err := pollPrepareProcess(71, func(fd int) (int, int16, error) {
				calls++
				if interrupted && calls == 1 {
					return -1, 0, syscall.EINTR
				}
				return result.n, result.events, result.err
			})
			wantCalls := 1
			if interrupted {
				wantCalls++
			}
			if calls != wantCalls || n != result.n || events != result.events || err != result.err {
				t.Fatal("non-interruption result changed", calls, n, events, err)
			}
			if failure := processPollFailure(false, n, events, err); failure.stage == matchNone {
				t.Fatal("rejection became liveness", result)
			}
		}
	}
}
