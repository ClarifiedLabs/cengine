package storagefuse

import "syscall"

// A zero-timeout pidfd poll interrupted by a signal says nothing about process
// liveness (Linux poll(2)/ppoll(2), EINTR). Retry only that syscall on the same
// retained descriptor, never the request or identity acquisition. Bound work
// under the prepare gate: persistent interruption still fails closed with EINTR.
const prepareProcessPollAttempts = 16

func pollPrepareProcess(fd int, poll func(int) (int, int16, error)) (int, int16, error) {
	for attempt := 0; ; attempt++ {
		n, events, err := poll(fd)
		if err != syscall.EINTR || attempt+1 == prepareProcessPollAttempts {
			return n, events, err
		}
	}
}
