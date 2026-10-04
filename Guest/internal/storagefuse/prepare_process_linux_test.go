//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests exercise real procfs/pidfds without a FUSE mount. They are only
// cross-compiled on unsupported hosts; fake gate tests are not native proof.
func TestPrepareProcessLinuxThreadMembership(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uint32(unix.Gettid())
	owner, err := pinPrepareProcess(tid)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	if !owner.matches(tid) || !owner.matches(uint32(os.Getpid())) || owner.matches(0) {
		t.Fatal("invalid owner membership")
	}
	result := make(chan bool, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		other := uint32(unix.Gettid())
		result <- other != tid && owner.matches(other)
	}()
	if !<-result {
		t.Fatal("different live thread rejected")
	}
	p := owner.(*linuxPrepareProcess)
	p.start++
	if p.matches(tid) {
		t.Fatal("changed starttime accepted")
	}
	if p.lastMatchFailure().stage != matchLeaderStart {
		t.Fatal(p.lastMatchFailure())
	}
	p.start--
	if !p.matches(tid) || p.lastMatchFailure() != (processMatchFailure{}) {
		t.Fatal("stale failure")
	}
}

func TestPrepareProcessLinuxChild(t *testing.T) {
	if os.Getenv("CENGINE_PREPARE_PROCESS_CHILD") != "1" {
		t.Skip("private subprocess")
	}
	fmt.Fprintln(os.Stdout, "ready")
	bufio.NewReader(os.Stdin).ReadByte()
}

func TestPrepareProcessLinuxDeathRetainsDeadOwner(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestPrepareProcessLinuxChild$")
	cmd.Env = append(os.Environ(), "CENGINE_PREPARE_PROCESS_CHILD=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal(line, err)
	}
	pid := uint32(cmd.Process.Pid)
	owner, err := pinPrepareProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	if !owner.matches(pid) || owner.matches(uint32(os.Getpid())) {
		t.Fatal("cross-process identity")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	waited = true
	if owner.matches(pid) {
		t.Fatal("dead owner accepted")
	}
	owner.close()
	if owner.matches(pid) {
		t.Fatal("closed owner accepted")
	}
	if owner.(*linuxPrepareProcess).lastMatchFailure().stage != matchClosed {
		t.Fatal("missing closed stage")
	}
}
