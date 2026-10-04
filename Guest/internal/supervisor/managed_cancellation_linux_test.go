//go:build linux

package supervisor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

// The subprocess genuinely blocks opening a FIFO before stage-2 readiness. It
// uses no namespaces, VM, FUSE or root mounts. Only launch/placement are replaced;
// StartManagedContext's locking, pipe I/O, cancellation and reap are production.
func TestManagedStartupCancellationChild(t *testing.T) {
	fifo := os.Getenv("CENGINE_TEST_STARTUP_FIFO")
	if fifo == "" {
		return
	}
	entered := os.NewFile(6, "entered")
	if _, err := entered.Write([]byte{1}); err != nil {
		os.Exit(2)
	}
	entered.Close()
	if _, err := os.OpenFile(fifo, os.O_WRONLY, 0600); err != nil {
		os.Exit(3)
	}
	os.Exit(4) // No reader should ever unblock the FIFO.
}

func TestManagedStartCancellationKillsAndReapsUnpublishedChild(t *testing.T) {
	s := New()
	if err := s.RequireManagedBoot(); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureManaged(); err != nil {
		t.Fatal(err)
	}
	// A zero-attachment launch is important: FUSE abort cannot unblock this child.
	s.spec = &protocol.WorkloadSpec{ID: "cancel-test", Arguments: []string{"unused"}}
	s.managed.prepared = true
	s.status = protocol.ProcessStatus{Status: "prepared"}
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	s.processIO = &pinnedProcessIO{stdout: output, stderr: output}
	t.Cleanup(s.processIO.close)
	fifo := filepath.Join(t.TempDir(), "network-file")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	enteredReader, enteredWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer enteredReader.Close()
	defer enteredWriter.Close()
	commands := make(chan *exec.Cmd, 1)
	s.startProcess = func(command *exec.Cmd) error {
		command.Args = []string{command.Path, "-test.run=^TestManagedStartupCancellationChild$"}
		command.Env = append(os.Environ(), "CENGINE_TEST_STARTUP_FIFO="+fifo)
		command.SysProcAttr = nil
		command.ExtraFiles = append(command.ExtraFiles, enteredWriter)
		err := command.Start()
		if err == nil {
			commands <- command
		}
		return err
	}
	placed := make(chan struct{})
	s.placeProcess = func(*exec.Cmd, *os.File) error { close(placed); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := s.StartManagedContext(ctx, nil); result <- err }()
	var command *exec.Cmd
	select {
	case command = <-commands:
	case err := <-result:
		t.Fatalf("start failed before subprocess: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("subprocess did not start")
	}
	// Failure cleanup must also unblock and join the launched production worker.
	joined := false
	defer func() {
		cancel()
		_ = command.Process.Kill()
		if !joined {
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Error("startup worker did not join")
			}
		}
	}()
	if err := enteredReader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var entered [1]byte
	if _, err := io.ReadFull(enteredReader, entered[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-placed:
	case <-time.After(5 * time.Second):
		t.Fatal("parent did not reach readiness wait")
	}
	// A deadline does not pretend the unpublished child has been reaped, nor
	// release lifecycle ownership while startup still owns it.
	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := s.StopManaged(deadlineCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("in-flight startup was falsely reported stopped: %v", err)
	}
	deadlineCancel()
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("deadline discarded startup child: %v", err)
	}
	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := s.StopManaged(stopCtx); err != nil {
		t.Fatalf("stop remained blocked behind unpublished child: %v", err)
	}
	select {
	case err := <-result:
		joined = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("start cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not return after stop")
	}
	if command.ProcessState == nil {
		t.Fatal("startup returned without reaping its child")
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(command.Process.Pid, &status, unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("child was not already reaped: %v", err)
	}
	if s.command != nil || s.status.Status == "running" || s.processIO != nil || !s.managed.stopped {
		t.Fatal("canceled launch published state or retained completed I/O")
	}
	if _, err := s.StartManaged(nil); err == nil {
		t.Fatal("canceled launch was restartable")
	}
}

func TestManagedContextEntrypointsHonorBusyLifecycleDeadline(t *testing.T) {
	for _, operation := range []string{"prepare", "start", "stop-before-configure"} {
		t.Run(operation, func(t *testing.T) {
			s := New()
			if err := s.RequireManagedBoot(); err != nil {
				t.Fatal(err)
			}
			s.lifecycleMu.Lock()
			s.mu.Lock() // Deadline paths must not attempt Status either.
			defer s.lifecycleMu.Unlock()
			defer s.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			var err error
			switch operation {
			case "prepare":
				err = s.PrepareManagedContext(ctx, protocol.WorkloadSpec{}, ManagedPlan{})
			case "start":
				_, err = s.StartManagedContext(ctx, nil)
			default:
				err = s.StopManaged(ctx)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("busy lifecycle ignored deadline: %v", err)
			}
		})
	}
}

func TestManagedCanceledPrepareDoesNotConsumePlanOrTouchFilesystems(t *testing.T) {
	s := New()
	if err := s.ConfigureManaged(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spec, plan := managedFixture()
	if err := s.PrepareManagedContext(ctx, spec, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prepare: %v", err)
	}
	if s.managed.attempted || s.managed.prepared || s.spec != nil || s.processIO != nil {
		t.Fatal("canceled prepare consumed plan or published prepared state")
	}
}

func TestManagedStopBeforeConfigureSealsTrustedBoot(t *testing.T) {
	s := New()
	if err := s.RequireManagedBoot(); err != nil {
		t.Fatal(err)
	}
	if err := s.StopManaged(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.ConfigureManaged() == nil {
		t.Fatal("configuration accepted after pre-configure stop")
	}
	if s.WithRootFSPreparation(func() error { t.Fatal("rootfs callback after stop"); return nil }) == nil {
		t.Fatal("rootfs mutation accepted after stop")
	}
	if s.Prepare(protocol.WorkloadSpec{}) == nil {
		t.Fatal("generic preparation accepted after stop")
	}
	if _, err := s.Start(); err == nil {
		t.Fatal("generic start accepted after stop")
	}
	if err := New().StopManaged(context.Background()); err == nil {
		t.Fatal("untrusted legacy supervisor accepted managed stop")
	}
}

func TestStartupCancellationWatcherJoinsBeforeOwnershipTransfer(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exec sleep 60")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	ctx, cancel := context.WithCancel(context.Background())
	join := watchStartupCancellation(ctx, command.Process)
	join()
	join() // The explicit publication join and deferred failure join may coincide.
	cancel()
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("joined startup watcher killed transferred process: %v", err)
	}
}
