package storagefuse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const nativeChildOutputLimit = 64 << 10

// Keep a bounded tail for failure reports, and optionally stream a bounded prefix
// to the fixture receipt so an outer watchdog still sees the last reached phase.
type nativeChildOutput struct {
	mu    sync.Mutex
	data  []byte
	total int
	live  chan []byte
}

func newNativeChildOutput(live io.Writer) *nativeChildOutput {
	b := &nativeChildOutput{}
	if live != nil {
		b.live = make(chan []byte, 8)
		go func(queue <-chan []byte) {
			for p := range queue {
				_, _ = live.Write(p)
			}
		}(b.live)
	}
	return b
}

func (b *nativeChildOutput) closeLive() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live != nil {
		close(b.live)
		b.live = nil
	}
}

func (b *nativeChildOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.live != nil && b.total < nativeChildOutputLimit {
		// Receipt backpressure must never hold the capture mutex or deadline
		// controller. At most one relay can remain blocked on an outer sink.
		chunk := append([]byte(nil), p[:min(len(p), nativeChildOutputLimit-b.total)]...)
		select {
		case b.live <- chunk:
		default:
		}
	}
	b.total += n
	if len(p) >= nativeChildOutputLimit {
		b.data = append(b.data[:0], p[len(p)-nativeChildOutputLimit:]...)
	} else {
		if excess := len(b.data) + len(p) - nativeChildOutputLimit; excess > 0 {
			b.data = append(b.data[:0], b.data[excess:]...)
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func (b *nativeChildOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total > len(b.data) {
		return fmt.Sprintf("[truncated %d output bytes]\n%s", b.total-len(b.data), b.data)
	}
	return string(b.data)
}

// Unlike CommandContext/CombinedOutput, this bounds Wait even if SIGKILL cannot
// yet reap a task in uninterruptible kernel sleep. The caller must preserve its
// fixture on !joined. No shell, process-name kill, or unrelated FUSE abort.
func nativeRunChild(cmd *exec.Cmd, timeout time.Duration, output *nativeChildOutput, diagnose func(int) string, abort func()) (joined bool, err error) {
	defer output.closeLive()
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = time.Second // a leaked descendant pipe cannot hold Wait forever
	if err := cmd.Start(); err != nil {
		return true, err // no process exists to join
	}
	fmt.Fprintf(output, "child started pid=%d deadline=%s\n", cmd.Process.Pid, timeout)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return true, err
	case <-timer.C:
	}
	fmt.Fprintln(output, "child deadline exceeded; collecting diagnostics before exact-mount abort")
	if diagnose != nil {
		diagnostic := make(chan string, 1)
		go func() { diagnostic <- diagnose(cmd.Process.Pid) }()
		select {
		case text := <-diagnostic:
			fmt.Fprintln(output, text)
		case <-time.After(time.Second):
			fmt.Fprintln(output, "child diagnostics exceeded 1s budget")
		}
	}
	// Ask the Go child for stacks before aborting its mount. Its runtime can also
	// be stuck in a page fault, so this is diagnostic only, never our sole timeout.
	_ = cmd.Process.Signal(syscall.SIGQUIT)
	select {
	case <-done:
		if abort != nil {
			abort()
		}
		return true, context.DeadlineExceeded
	case <-time.After(time.Second):
	}
	if abort != nil {
		abort()
	} // must only signal the already-owned mount
	_ = cmd.Process.Kill()
	select {
	case <-done:
		return true, context.DeadlineExceeded
	case <-time.After(3 * time.Second):
		return false, fmt.Errorf("%w: child pid=%d not reaped after SIGKILL", context.DeadlineExceeded, cmd.Process.Pid)
	}
}

func TestNativeChildRunner(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "failure", "timeout", "timeout-kill", "timeout-diagnostics", "timeout-output", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(executable, "-test.run=^TestNativeChildRunnerHelper$", "-test.v")
			cmd.Env = []string{"STORAGEFUSE_RUNNER_CHILD=" + mode, "GORACE=atexit_sleep_ms=0"}
			releaseOutput := make(chan struct{})
			defer close(releaseOutput)
			out := newNativeChildOutput(nil)
			if mode == "timeout-output" {
				out = newNativeChildOutput(nativeBlockedWriter{releaseOutput})
			}
			duration := 5 * time.Second
			timedOut := strings.HasPrefix(mode, "timeout")
			if timedOut {
				duration = time.Second
			}
			releaseDiagnostics := make(chan struct{})
			defer close(releaseDiagnostics)
			diagnose := func(int) string {
				if mode == "timeout-diagnostics" {
					<-releaseDiagnostics
				}
				return "diagnostic-marker"
			}
			aborted := false
			start := time.Now()
			joined, err := nativeRunChild(cmd, duration, out, diagnose, func() { aborted = true })
			if time.Since(start) > 7*time.Second {
				t.Fatal("child runner exceeded bounded wait")
			}
			if !joined {
				t.Fatal("child leaked", err)
			}
			switch mode {
			case "success", "overflow":
				if err != nil {
					t.Fatal(err, out.String())
				}
			case "failure":
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal("failure hidden", err)
				}
			case "timeout", "timeout-kill", "timeout-diagnostics", "timeout-output":
				marker := "diagnostic-marker"
				if mode == "timeout-diagnostics" {
					marker = "diagnostics exceeded 1s budget"
				}
				if !errors.Is(err, context.DeadlineExceeded) || !aborted || !strings.Contains(out.String(), marker) {
					t.Fatal("deadline/diagnostics/abort lost", err, out.String())
				}
			}
			if !timedOut && aborted {
				t.Fatal("aborted a completed child")
			}
			if !strings.Contains(out.String(), "phase-marker") {
				t.Fatal("child output lost", out.String())
			}
			if mode == "overflow" && (len(out.String()) > nativeChildOutputLimit+100 || !strings.Contains(out.String(), "[truncated")) {
				t.Fatal("unbounded capture")
			}
		})
	}
}

type nativeBlockedWriter struct{ release <-chan struct{} }

func (w nativeBlockedWriter) Write(p []byte) (int, error) { <-w.release; return len(p), nil }

func TestNativeChildRunnerHelper(t *testing.T) {
	mode := os.Getenv("STORAGEFUSE_RUNNER_CHILD")
	if mode == "" {
		t.Skip("internal runner subprocess only")
	}
	if mode == "overflow" {
		fmt.Print(strings.Repeat("x", 2*nativeChildOutputLimit))
	}
	if mode == "timeout-kill" {
		signal.Ignore(syscall.SIGQUIT)
	}
	fmt.Println("phase-marker")
	switch mode {
	case "success", "overflow":
	case "failure":
		t.Fatal("deliberate child failure")
	case "timeout", "timeout-kill", "timeout-diagnostics", "timeout-output":
		time.Sleep(time.Minute)
	default:
		t.Fatal("unknown child mode")
	}
}
