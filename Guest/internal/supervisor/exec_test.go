//go:build linux

package supervisor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestExecStageExitCodeDistinguishesMissingExecutable(t *testing.T) {
	if code := ExecStageExitCode(fmt.Errorf("look up command: %w", os.ErrNotExist)); code != 127 {
		t.Fatalf("missing executable exit code is %d, want 127", code)
	}
	if code := ExecStageExitCode(errors.New("exec format error")); code != 126 {
		t.Fatalf("non-missing exec failure exit code is %d, want 126", code)
	}
	err := exec.Command("sh", "-c", "exit 23").Run()
	if code := ExecStageExitCode(err); code != 23 {
		t.Fatalf("target process exit code is %d, want 23", code)
	}
	err = exec.Command("sh", "-c", "kill -TERM $$").Run()
	if code := ExecStageExitCode(err); code != 128+int(syscall.SIGTERM) {
		t.Fatalf("signaled target process exit code is %d, want 143", code)
	}
}

func TestExecStageForwardsSignalsUntilItsChildExits(t *testing.T) {
	signals := make(chan os.Signal, 1)
	wait := make(chan error, 1)
	forwarded := make(chan syscall.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- forwardExecSignalsUntilWait(signals, wait, func(value syscall.Signal) error {
			forwarded <- value
			return nil
		})
	}()
	signals <- syscall.SIGTERM
	if value := <-forwarded; value != syscall.SIGTERM {
		t.Fatalf("forwarded signal is %d, want SIGTERM", value)
	}
	wait <- nil
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUncatchableExecSignalsTargetTheFinalStagedChild(t *testing.T) {
	for _, signal := range []unix.Signal{unix.SIGKILL, unix.SIGSTOP} {
		target := execSignalTarget(123, 789, signal)
		if target != 789 {
			t.Fatalf("signal %d target is %d, want final child 789", signal, target)
		}
	}
	target := execSignalTarget(123, 789, unix.SIGTERM)
	if target != 123 {
		t.Fatalf("SIGTERM target is %d, want stage process 123", target)
	}
}

func TestExecTargetPIDIsPublishedAcrossStageDescriptors(t *testing.T) {
	pid, err := readExecTargetPID(bytes.NewBufferString("789\n"))
	if err != nil {
		t.Fatal(err)
	}
	if pid != 789 {
		t.Fatalf("published target PID is %d, want 789", pid)
	}
}

func TestExecInspectPIDUsesWorkloadNamespaceIdentity(t *testing.T) {
	status := []byte("Name:\tsh\nNSpid:\t162\t15\n")
	if pid := execInspectPIDFromStatus(status, 162); pid != 15 {
		t.Fatalf("exec inspect PID is %d, want workload namespace PID 15", pid)
	}
	if pid := execInspectPIDFromStatus([]byte("Name:\tsh\n"), 162); pid != 162 {
		t.Fatalf("exec inspect PID fallback is %d, want 162", pid)
	}
}

func TestExecStartReservationExcludesAttachedAndDetachedLaunches(t *testing.T) {
	supervisor := New()
	supervisor.execStatus["exec-id"] = protocol.ProcessStatus{Status: "created"}

	supervisor.mu.Lock()
	if err := supervisor.reserveExecStartLocked("exec-id"); err != nil {
		supervisor.mu.Unlock()
		t.Fatal(err)
	}
	if err := supervisor.reserveExecStartLocked("exec-id"); err == nil {
		supervisor.mu.Unlock()
		t.Fatal("attached start acquired a detached start reservation")
	}
	supervisor.mu.Unlock()

	supervisor.rollbackExecStart("exec-id")
	supervisor.mu.Lock()
	err := supervisor.reserveExecStartLocked("exec-id")
	supervisor.mu.Unlock()
	if err != nil {
		t.Fatalf("reservation did not roll back after launch failure: %v", err)
	}
}

func TestDiscardExecRemovesOnlyUnstartedPreparation(t *testing.T) {
	supervisor := New()
	supervisor.execStatus["prepared"] = protocol.ProcessStatus{Status: "created"}
	if err := supervisor.DiscardExec("prepared"); err != nil {
		t.Fatal(err)
	}
	if status := supervisor.ExecStatus("prepared"); status.Status != "" {
		t.Fatalf("discarded exec status is %#v, want empty", status)
	}

	supervisor.execStatus["running"] = protocol.ProcessStatus{Status: "running"}
	if err := supervisor.DiscardExec("running"); err == nil {
		t.Fatal("discarded an exec that had already started")
	}
	if status := supervisor.ExecStatus("running"); status.Status != "running" {
		t.Fatalf("running exec status changed to %#v", status)
	}
}

func TestAttachedExecLaunchFailureBecomesTerminalAfterUpgrade(t *testing.T) {
	supervisor := New()
	supervisor.execStatus["missing"] = protocol.ProcessStatus{Status: "starting"}
	supervisor.failAttachedExecStart("missing", os.ErrNotExist)

	status := supervisor.ExecStatus("missing")
	if status.Status != "exited" || status.ExitCode == nil || *status.ExitCode != 127 {
		t.Fatalf("attached launch failure status is %#v, want exited with code 127", status)
	}
}

func TestRapidAttachedExecExitRetainsPublishedTargetPID(t *testing.T) {
	supervisor := New()
	code := 23
	supervisor.execStatus["fast"] = protocol.ProcessStatus{Status: "exited", ExitCode: &code}

	status := supervisor.publishExecTargetPID("fast", &exec.Cmd{}, 789)
	if status.Status != "exited" || status.PID != 789 || status.ExitCode == nil || *status.ExitCode != code {
		t.Fatalf("rapid attached exec status is %#v, want exited PID 789 code 23", status)
	}
	if persisted := supervisor.ExecStatus("fast"); persisted.PID != 789 {
		t.Fatalf("persisted rapid attached exec PID is %d, want 789", persisted.PID)
	}
}

func TestWaitExecTreatsStartingAndRunningAsNonterminalStates(t *testing.T) {
	for _, test := range []struct {
		status  string
		pending bool
	}{
		{status: "created", pending: false},
		{status: "starting", pending: true},
		{status: "running", pending: true},
		{status: "exited", pending: false},
	} {
		if actual := execWaitPending(test.status); actual != test.pending {
			t.Fatalf("exec status %q pending = %t, want %t", test.status, actual, test.pending)
		}
	}
}

func TestSignalExecKillsItsDedicatedCgroupSubtree(t *testing.T) {
	cgroup := t.TempDir()
	killFile := filepath.Join(cgroup, "cgroup.kill")
	if err := os.WriteFile(killFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	supervisor := New()
	supervisor.execs["healthcheck"] = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	supervisor.execTargets["healthcheck"] = os.Getpid()
	supervisor.execCgroups["healthcheck"] = cgroup

	if err := supervisor.SignalExec("healthcheck", int(unix.SIGKILL)); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(killFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "1" {
		t.Fatalf("cgroup.kill = %q, want 1", value)
	}
}

type testReadWriter struct {
	io.ReadWriter
}

func TestAttachedExecStdinCanBeReopenedThroughDevStdin(t *testing.T) {
	stream := testReadWriter{ReadWriter: struct {
		io.Reader
		io.Writer
	}{Reader: bytes.NewBufferString("pipe-stdin"), Writer: io.Discard}}
	stdin, cancel, err := attachedExecStdin(stream)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer stdin.Close()
	command := exec.Command("sh", "-c", "cat /dev/stdin")
	command.Stdin = stdin
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "pipe-stdin" {
		t.Fatalf("unexpected reopened stdin %q", output)
	}
}

func TestDockerStreamMuxFramesAttachedExecOutput(t *testing.T) {
	var output bytes.Buffer
	mux := &dockerStreamMux{writer: &output}
	payload := bytes.Repeat([]byte("x"), 256*1024)

	written, err := mux.stream(2).Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(payload) {
		t.Fatalf("wrote %d bytes, want %d", written, len(payload))
	}
	framed := output.Bytes()
	if len(framed) != len(payload)+8 {
		t.Fatalf("framed output is %d bytes, want %d", len(framed), len(payload)+8)
	}
	if framed[0] != 2 || !bytes.Equal(framed[1:4], []byte{0, 0, 0}) {
		t.Fatalf("invalid Docker stream header %v", framed[:4])
	}
	if size := binary.BigEndian.Uint32(framed[4:8]); size != uint32(len(payload)) {
		t.Fatalf("framed payload size is %d, want %d", size, len(payload))
	}
	if !bytes.Equal(framed[8:], payload) {
		t.Fatal("framed payload was corrupted")
	}
}

func TestDockerStreamMuxLeavesTerminalOutputUnframed(t *testing.T) {
	var output bytes.Buffer
	mux := &dockerStreamMux{writer: &output, terminal: true}
	payload := []byte("terminal output")

	if _, err := mux.stream(1).Write(payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("terminal output was framed: %q", output.Bytes())
	}
}

func TestExecLeavesMountNamespaceUntilAfterStage2Starts(t *testing.T) {
	var calls []string
	operations := namespaceOperations{
		unshare: func(flag int) error { calls = append(calls, fmt.Sprintf("unshare:%d", flag)); return nil },
		open: func(path string, _ int, _ uint32) (int, error) {
			calls = append(calls, "open:"+path)
			return len(calls), nil
		},
		setns: func(_ int, flag int) error { calls = append(calls, fmt.Sprintf("setns:%d", flag)); return nil },
		close: func(_ int) error { return nil },
	}
	if err := joinWorkloadNamespacesExceptMountAndPID(42, operations); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		fmt.Sprintf("unshare:%d", unix.CLONE_FS),
		"open:/proc/42/ns/uts", fmt.Sprintf("setns:%d", unix.CLONE_NEWUTS),
		"open:/proc/42/ns/ipc", fmt.Sprintf("setns:%d", unix.CLONE_NEWIPC),
		"open:/proc/42/ns/net", fmt.Sprintf("setns:%d", unix.CLONE_NEWNET),
		"open:/proc/42/ns/cgroup", fmt.Sprintf("setns:%d", unix.CLONE_NEWCGROUP),
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected namespace sequence %#v", calls)
	}
}

func TestExecStage2JoinsWorkloadMountNamespace(t *testing.T) {
	var calls []string
	err := enterExecMountNamespace(5, func(flag int) error {
		calls = append(calls, fmt.Sprintf("unshare:%d", flag))
		return nil
	}, func(fd, flag int) error {
		calls = append(calls, fmt.Sprintf("setns:%d:%d", fd, flag))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		fmt.Sprintf("unshare:%d", unix.CLONE_FS),
		fmt.Sprintf("setns:5:%d", unix.CLONE_NEWNS),
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected mount namespace sequence %#v", calls)
	}
}

func TestExecEntersRootThroughDescriptorCapturedBeforeNamespaceChanges(t *testing.T) {
	var calls []string
	err := enterExecRoot(4, func(fd int) error {
		calls = append(calls, fmt.Sprintf("fchdir:%d", fd))
		return nil
	}, func(path string) error {
		calls = append(calls, "chroot:"+path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"fchdir:4", "chroot:."}) {
		t.Fatalf("unexpected root entry sequence %#v", calls)
	}
}

func TestExecStage2InheritsRootAndMountNamespaceDescriptors(t *testing.T) {
	spec, err := os.CreateTemp(t.TempDir(), "exec-spec")
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Close()
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	mountNamespace, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer mountNamespace.Close()
	pidNamespace, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	defer pidNamespace.Close()
	cgroup, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	targetPID, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer targetPID.Close()

	command := execStage2Command(spec, root, mountNamespace, pidNamespace, cgroup, targetPID)
	if command.Path != "/proc/self/exe" {
		t.Fatalf("exec stage 2 path is %q", command.Path)
	}
	if !reflect.DeepEqual(command.Args, []string{"/proc/self/exe", execStage2Argument}) {
		t.Fatalf("unexpected exec stage 2 arguments %#v", command.Args)
	}
	if !reflect.DeepEqual(command.ExtraFiles, []*os.File{spec, root, mountNamespace, pidNamespace, cgroup, targetPID}) {
		t.Fatalf("unexpected exec stage 2 descriptors %#v", command.ExtraFiles)
	}
}

func TestExecStage3ReceivesOnlySpecAndRootAndJoinsTheExecCgroup(t *testing.T) {
	spec, err := os.CreateTemp(t.TempDir(), "exec-spec")
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Close()
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cgroup, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()

	command := execStage3Command(spec, root, cgroup)
	if !reflect.DeepEqual(command.Args, []string{"/proc/self/exe", execStage3Argument}) {
		t.Fatalf("unexpected exec stage 3 arguments %#v", command.Args)
	}
	if !reflect.DeepEqual(command.ExtraFiles, []*os.File{spec, root}) {
		t.Fatalf("unexpected exec stage 3 descriptors %#v", command.ExtraFiles)
	}
	if command.SysProcAttr == nil || !command.SysProcAttr.UseCgroupFD ||
		command.SysProcAttr.CgroupFD != int(cgroup.Fd()) {
		t.Fatalf("exec stage 3 did not target cgroup fd %d: %#v", cgroup.Fd(), command.SysProcAttr)
	}
}

func TestExecUsesWorkloadUserAndSupplementaryGroupResolution(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000:app:/home/app:/bin/sh\n")
	groups := []byte("app:x:1000:\nlogs:x:2000:app\nstaff:x:3000:\n")

	uid, gid, additional, err := resolveUserFromData(
		protocol.User{Username: "app:staff"}, passwd, groups,
	)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1000 || gid != 3000 || !reflect.DeepEqual(additional, []int{2000}) {
		t.Fatalf("resolved identity is %d:%d groups=%v", uid, gid, additional)
	}

	uid, gid, additional, err = resolveUserFromData(
		protocol.User{UID: 1000, GID: 1000, Username: "1000:staff"}, passwd, groups,
	)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1000 || gid != 3000 || len(additional) != 0 {
		t.Fatalf("resolved numeric identity is %d:%d groups=%v", uid, gid, additional)
	}
}

func TestExecAppliesNoNewPrivilegesWhenRequested(t *testing.T) {
	var calls [][]uintptr
	prctl := func(option int, arg2, arg3, arg4, arg5 uintptr) error {
		calls = append(calls, []uintptr{uintptr(option), arg2, arg3, arg4, arg5})
		return nil
	}
	if err := applyNoNewPrivileges(false, prctl); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("disabled no-new-privileges made calls: %v", calls)
	}
	if err := applyNoNewPrivileges(true, prctl); err != nil {
		t.Fatal(err)
	}
	want := [][]uintptr{{uintptr(unix.PR_SET_NO_NEW_PRIVS), 1, 0, 0, 0}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("no-new-privileges calls are %v, want %v", calls, want)
	}
}

func TestWorkloadRootBecomesMountNamespaceRoot(t *testing.T) {
	var calls []string
	operations := rootSwitchOperations{
		chdir: func(path string) error {
			calls = append(calls, "chdir:"+path)
			return nil
		},
		mount: func(source, target, kind string, flags uintptr, data string) error {
			calls = append(calls, fmt.Sprintf("mount:%s:%s:%s:%d:%s", source, target, kind, flags, data))
			return nil
		},
		chroot: func(path string) error {
			calls = append(calls, "chroot:"+path)
			return nil
		},
	}

	if err := switchWorkloadRoot("/run/cengine/rootfs", operations); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"chdir:/run/cengine/rootfs",
		fmt.Sprintf("mount:/run/cengine/rootfs:/::%d:", unix.MS_MOVE),
		"chroot:.",
		"chdir:/",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected root switch sequence %#v", calls)
	}
}
