package storagefuse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// Linux PR_SET_PDEATHSIG follows the thread that created the child, not merely
// the parent process. A storage identity worker can retire an unlocked thread.
// Reserve a dedicated thread from Start through the exact sole Wait instead.
// No caller cancellation can release that reservation. The startup gate lets
// the parent pin the child's birth before Wait can reap it and recycle its PID.
type nativeChildOwner struct {
	waitGate chan struct{}
	done     <-chan nativeChildResult
}

type nativeChildResult struct {
	err   error
	state *os.ProcessState
}

func (r nativeChildResult) reaped() bool { return r.state != nil }

func nativeStartChild(command *exec.Cmd) (*nativeChildOwner, error) {
	return nativeOwnChild(command.Start, func() nativeChildResult {
		err := command.Wait() // the only Wait, on the creating OS thread
		return nativeChildResult{err: err, state: command.ProcessState}
	})
}

// Callbacks keep lifecycle tests independent of mounted workloads; all callers
// and this helper exist only in the test binary, not the guest's exec surface.
func nativeOwnChild(start func() error, wait func() nativeChildResult) (*nativeChildOwner, error) {
	started := make(chan error, 1)
	done := make(chan nativeChildResult, 1)
	owner := &nativeChildOwner{waitGate: make(chan struct{}), done: done}
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := start()
		started <- err
		if err != nil {
			return // no child, and no Wait obligation
		}
		<-owner.waitGate
		result := wait()
		done <- result // never substitute cancellation or kill for the actual Wait
		if !result.reaped() {
			// An exceptional Wait error without ProcessState proves no reap.
			// Keep this thread reserved, just as while Wait itself is blocked.
			select {}
		}
	}()
	if err := <-started; err != nil {
		return nil, err
	}
	return owner, nil
}

func (o *nativeChildOwner) allowWait() { close(o.waitGate) }

// Closed summaries only: no argv, environment, raw paths or arbitrary error
// strings. The original error objects are retained by each caller separately.
func nativeChildError(err error) string { return nativeChildErrorDepth(err, 0) }

func nativeChildErrorDepth(err error, depth int) string {
	if err == nil {
		return "nil"
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		if depth >= 2 {
			return "join-bound"
		}
		parts := joined.Unwrap()
		out := "join"
		for _, part := range parts[:min(len(parts), 4)] {
			out += ":" + nativeChildErrorDepth(part, depth+1)
		}
		return out
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, os.ErrClosed) {
		return "closed"
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nativeChildState(exit.ProcessState)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("errno=%d", uint64(errno))
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return "wait-delay"
	}
	switch err.Error() {
	case "sparse child profile", "sparse child mount descriptor", "sparse child attributes", "sparse mounted model", "fsx immutable file profile", "fsx child profile", "fsx mount descriptor", "fsx capabilities survived", "fsx bounding capabilities survived", "fsx binary pin", "fsx ELF profile", "fsx dynamic ELF", "fsx missing load segment", "child Wait without reap", "sparse control packet", "short sparse control packet", "sparse process birth", "sparse child lineage", "sparse child pidfd unavailable", "fsx child lineage", "fsx positive pidfd required", "fsx diagnostic observer unjoined", "fsx completion proof":
		return fmt.Sprintf("%q", err.Error())
	}
	return fmt.Sprintf("type=%T", err)
}

func nativeChildStage(output io.Writer, stage string, work func() error) error {
	fmt.Fprintf(output, "D child-stage=%s begin\n", stage)
	err := work()
	fmt.Fprintf(output, "D child-stage=%s end error=%s\n", stage, nativeChildError(err))
	return err
}

func nativeChildState(state *os.ProcessState) string {
	if state == nil {
		return "absent"
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok {
		return fmt.Sprintf("exit=%d,signal=%d,core=%t,status=%d", status.ExitStatus(), status.Signal(), status.CoreDump(), uint32(status))
	}
	return fmt.Sprintf("exit=%d", state.ExitCode())
}

func nativeChildWaitSummary(result nativeChildResult, received bool) string {
	if !received {
		return "unreceived"
	}
	return fmt.Sprintf("received,reaped=%t,state=%s,error=%s", result.reaped(), nativeChildState(result.state), nativeChildError(result.err))
}
