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
	"reflect"
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
	if err := joinWorkloadNonMountNamespaces(42, operations); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		fmt.Sprintf("unshare:%d", unix.CLONE_FS),
		"open:/proc/42/ns/uts", fmt.Sprintf("setns:%d", unix.CLONE_NEWUTS),
		"open:/proc/42/ns/ipc", fmt.Sprintf("setns:%d", unix.CLONE_NEWIPC),
		"open:/proc/42/ns/net", fmt.Sprintf("setns:%d", unix.CLONE_NEWNET),
		"open:/proc/42/ns/cgroup", fmt.Sprintf("setns:%d", unix.CLONE_NEWCGROUP),
		"open:/proc/42/ns/pid", fmt.Sprintf("setns:%d", unix.CLONE_NEWPID),
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

	command := execStage2Command(spec, root, mountNamespace)
	if command.Path != "/proc/self/exe" {
		t.Fatalf("exec stage 2 path is %q", command.Path)
	}
	if !reflect.DeepEqual(command.Args, []string{"/proc/self/exe", execStage2Argument}) {
		t.Fatalf("unexpected exec stage 2 arguments %#v", command.Args)
	}
	if !reflect.DeepEqual(command.ExtraFiles, []*os.File{spec, root, mountNamespace}) {
		t.Fatalf("unexpected exec stage 2 descriptors %#v", command.ExtraFiles)
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
