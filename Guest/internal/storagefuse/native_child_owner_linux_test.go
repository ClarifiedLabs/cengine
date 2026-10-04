//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeChildOwnerLiveCreatingThread(t *testing.T) {
	input, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer release.Close()
	pidFD := -1
	command := exec.Command("/bin/sh", "-c", "read value; exit 23")
	command.Stdin = input
	// Like the mounted sparse/fsx children, create a private process group: the
	// cengine workload init can otherwise have pgrp 0, which proc stat records
	// as a valid but non-positive birth group.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidFD}
	startedTID := 0
	waiting := make(chan int, 1)
	owner, err := nativeOwnChild(func() error {
		startedTID = unix.Gettid()
		return command.Start()
	}, func() nativeChildResult {
		waiting <- unix.Gettid()
		err := command.Wait()
		return nativeChildResult{err, command.ProcessState}
	})
	if err != nil {
		t.Fatal(err)
	}
	// Every failure path has an exact pidfd kill and bounded receive, never an
	// unbounded host Wait or a synthetic reap. No fixture workload is launched.
	gateOpen, received, reaped := false, false, false
	defer func() {
		if !gateOpen {
			owner.allowWait()
		}
		if !received {
			if pidFD >= 0 {
				_ = unix.PidfdSendSignal(pidFD, unix.SIGKILL, nil, 0)
			}
			result := nativeOwnerAwait(t, owner.done)
			reaped = result.reaped()
			if !reaped {
				t.Error("unit child unreaped; owner remains reserved")
			}
		}
		if reaped && pidFD >= 0 {
			unix.Close(pidFD)
		}
	}()
	if pidFD < 0 {
		t.Fatal("pidfd unavailable")
	}
	pin, err := sparsePinProcess(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pin.fd)
	owner.allowWait()
	gateOpen = true
	if waitTID := nativeOwnerAwait(t, waiting); waitTID != startedTID {
		t.Fatalf("Start thread %d != Wait thread %d", startedTID, waitTID)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/self/task/%d", startedTID)); err != nil {
		t.Fatal("creating OS thread no longer live", err)
	}
	if err := unix.PidfdSendSignal(pidFD, 0, nil, 0); err != nil {
		t.Fatal("child did not survive owner gate", err)
	}
	if _, err := release.WriteString("done\n"); err != nil {
		t.Fatal(err)
	}
	result := nativeOwnerAwait(t, owner.done)
	received, reaped = true, result.reaped()
	if !reaped || result.state != command.ProcessState || result.state.ExitCode() != 23 {
		t.Fatal("actual child exit lost", nativeChildWaitSummary(result, true))
	}
}
