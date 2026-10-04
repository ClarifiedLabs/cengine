//go:build linux

package storageworker

import (
	"bytes"
	"os"
	"strconv"
	"testing"
	"time"
)

// Compile-only in the macOS engine-free matrix. On Linux this uses the real
// owned child and protected channel; no EOF or mock WaitResult proves its exit.
func TestWorkerExitACKChild(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	parent, err := strconv.Atoi(os.Args[len(os.Args)-1])
	if err != nil {
		os.Exit(81)
	}
	child, err := accept(parent)
	if err != nil {
		os.Exit(82)
	}
	payload, err := child.Receive()
	if err != nil {
		os.Exit(83)
	}
	if err := child.Send(payload); err != nil {
		os.Exit(84)
	}
	os.Exit(74)
}
func TestWorkerExitACKSurvivesImmediateOwnedExit(t *testing.T) {
	requireRoot(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for i := 0; i < 10; i++ {
		owner, err := start(root, []string{"-test.run=^TestWorkerExitACKChild$", "--", strconv.Itoa(os.Getpid())}, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		pid := owner.PID()
		payload := []byte("fixed-exit-74-ack")
		got, err := owner.Exchange(payload, time.Now().Add(5*time.Second))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatal("lost authenticated final ACK", err)
		}
		result := awaitResult(t, owner)
		if !result.State.Exited() || result.State.ExitCode() != 74 || result.State.Pid() != pid {
			t.Fatal("not owned actual exit 74", result)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
