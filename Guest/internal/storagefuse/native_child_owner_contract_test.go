package storagefuse

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func nativeOwnerAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("child owner unit-test join exceeded")
		var zero T
		return zero
	}
}

func TestNativeChildOwnerGateAndActualWait(t *testing.T) {
	// Host-only shell unit workload, never a mounted fixture or production entry.
	limit, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	command := exec.CommandContext(limit, "/bin/sh", "-c", "exit 23")
	entered, release := make(chan struct{}), make(chan struct{})
	releaseWait := sync.OnceFunc(func() { close(release) })
	var waits atomic.Int32
	var actual error
	owner, err := nativeOwnChild(command.Start, func() nativeChildResult {
		waits.Add(1)
		close(entered)
		<-release
		actual = command.Wait()
		return nativeChildResult{actual, command.ProcessState}
	})
	if err != nil {
		t.Fatal(err)
	}
	gateOpen, joined := false, false
	defer func() {
		if !gateOpen {
			owner.allowWait()
		}
		releaseWait()
		if !joined {
			nativeOwnerAwait(t, owner.done)
		}
	}()
	// Start has completed, but only the parent can open the birth-pin gate.
	if command.Process == nil || command.ProcessState != nil || waits.Load() != 0 {
		t.Fatal("Wait ran before the parent's birth-pin gate")
	}
	owner.allowWait()
	gateOpen = true
	nativeOwnerAwait(t, entered)
	// Caller cancellation is not a Wait result and cannot release the owner.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	<-ctx.Done()
	select {
	case result := <-owner.done:
		t.Fatalf("synthetic/early result: %+v", result)
	default:
	}
	// Release the bounded fake blocking section, then consume the real sole Wait.
	releaseWait()
	result := nativeOwnerAwait(t, owner.done)
	joined = true
	if waits.Load() != 1 || result.err != actual || result.state != command.ProcessState || !result.reaped() || result.state.ExitCode() != 23 {
		t.Fatalf("lost actual Wait: waits=%d result=%+v", waits.Load(), result)
	}
	var exit *exec.ExitError
	if !errors.As(result.err, &exit) || exit.ExitCode() != 23 {
		t.Fatal("actual exit error replaced", result.err)
	}
	if got := nativeChildWaitSummary(result, true); !strings.Contains(got, "state=exit=23,signal=-1,core=false,status=5888") {
		t.Fatal("actual wait status omitted", got)
	}
}

func TestNativeChildOwnerStartupFailure(t *testing.T) {
	failure := errors.New("start sentinel")
	var waits atomic.Int32
	owner, err := nativeOwnChild(func() error { return failure }, func() nativeChildResult {
		waits.Add(1)
		return nativeChildResult{}
	})
	if owner != nil || err != failure || waits.Load() != 0 {
		t.Fatal("startup failure lost or Wait attempted", owner, err, waits.Load())
	}
	command := exec.Command("/nonexistent-native-child-owner-unit-test")
	owner, err = nativeStartChild(command)
	if owner != nil || err == nil || command.Process != nil {
		t.Fatal("actual failed Start was not returned", owner, err)
	}
}

func TestNativeChildFailureDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "nil"},
		{context.DeadlineExceeded, "deadline"},
		{&os.PathError{Op: "open", Path: "/secret/path", Err: syscall.ENOENT}, "errno=2"},
		{errors.New("sparse control packet"), `"sparse control packet"`},
		{errors.New("secret payload"), "type=*errors.errorString"},
	} {
		if got := nativeChildError(tc.err); got != tc.want {
			t.Fatalf("summary: got %q want %q", got, tc.want)
		}
	}
	var output bytes.Buffer
	actual := errors.New("sparse control packet")
	if got := nativeChildStage(&output, "sparse-ready-receive", func() error { return actual }); got != actual {
		t.Fatal("stage replaced actual error")
	}
	if got := output.String(); got != "D child-stage=sparse-ready-receive begin\nD child-stage=sparse-ready-receive end error=\"sparse control packet\"\n" {
		t.Fatal("stage diagnostics", got)
	}
	nested := errors.New("secret payload")
	for i := 0; i < 100; i++ {
		nested = errors.Join(nested, nested)
	}
	if got := nativeChildError(nested); len(got) > 256 || strings.Contains(got, "secret") || !strings.Contains(got, "join-bound") {
		t.Fatal("unbounded joined summary", len(got))
	}
	if got := nativeChildWaitSummary(nativeChildResult{}, false); got != "unreceived" {
		t.Fatal("missing Wait fabricated", got)
	}
	if got := nativeChildWaitSummary(nativeChildResult{err: syscall.ECHILD}, true); !strings.Contains(got, "reaped=false,state=absent,error=errno=") {
		t.Fatal("Wait error fabricated reap", got)
	}
}
