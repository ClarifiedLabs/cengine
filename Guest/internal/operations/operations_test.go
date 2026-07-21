//go:build linux

package operations

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestContainerRootUsesRunningProcessRoot(t *testing.T) {
	pid := os.Getpid()
	got, err := containerRoot(pid)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("/proc/%d/root", pid)
	if got != want {
		t.Fatalf("containerRoot(%d) = %q, want %q", pid, got, want)
	}
}

func TestReadCgroupStatsUsesWorkloadWideAccounting(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"cpu.stat":       "usage_usec 123\nuser_usec 80\nsystem_usec 43\nnr_periods 9\nnr_throttled 2\nthrottled_usec 7\n",
		"memory.current": "4096\n",
		"memory.peak":    "8192\n",
		"memory.stat":    "anon 2048\nfile 1024\n",
		"pids.current":   "5\n",
		"io.stat":        "254:0 rbytes=100 wbytes=200 rios=3 wios=4\n254:1 rbytes=7 wbytes=11\n",
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var result Statistics
	if err := readCgroupStats(root, &result); err != nil {
		t.Fatal(err)
	}
	if result.CPUTotalNanoseconds != 123000 || result.CPUUserNanoseconds != 80000 ||
		result.CPUSystemNanoseconds != 43000 || result.CPUPeriods != 9 ||
		result.CPUThrottledPeriods != 2 || result.CPUThrottledNS != 7000 {
		t.Fatalf("unexpected CPU accounting: %#v", result)
	}
	if result.MemoryUsage != 4096 || result.MemoryPeak != 8192 ||
		result.MemoryCache != 1024 || result.PIDs != 5 {
		t.Fatalf("unexpected memory/PID accounting: %#v", result)
	}
	if result.BlockReadBytes != 107 || result.BlockWriteBytes != 211 || len(result.BlockIO) != 2 {
		t.Fatalf("unexpected block-I/O accounting: %#v", result)
	}
	if result.BlockIO[1].Major != 254 || result.BlockIO[1].Minor != 1 ||
		result.BlockIO[1].ReadBytes != 7 || result.BlockIO[1].WriteBytes != 11 {
		t.Fatalf("unexpected per-device block-I/O accounting: %#v", result.BlockIO)
	}
}

type freezeTestState struct {
	state               string
	descendantState     string
	readErr             error
	freezeWriteErr      error
	waitFrozenErr       error
	unfreezeWriteErrors []error
	waitRunningErrors   []error
	writes              []string
	waits               []bool
}

func (state *freezeTestState) operations() workloadFreezeOperations {
	return workloadFreezeOperations{
		cgroupPath: func(pid int) (string, error) {
			if pid != 42 {
				return "", fmt.Errorf("unexpected pid %d", pid)
			}
			return "/sys/fs/cgroup/cengine/workload", nil
		},
		readFile: func(path string) ([]byte, error) {
			if path != "/sys/fs/cgroup/cengine/workload/cgroup.freeze" {
				return nil, fmt.Errorf("unexpected read %s", path)
			}
			if state.readErr != nil {
				return nil, state.readErr
			}
			return []byte(state.state), nil
		},
		writeFile: func(path string, data []byte, _ os.FileMode) error {
			if path != "/sys/fs/cgroup/cengine/workload/cgroup.freeze" {
				return fmt.Errorf("unexpected write %s", path)
			}
			value := string(data)
			state.writes = append(state.writes, value)
			switch value {
			case "1":
				if state.freezeWriteErr != nil {
					return state.freezeWriteErr
				}
				state.state = "1"
				state.descendantState = "1"
			case "0":
				if len(state.unfreezeWriteErrors) != 0 {
					err := state.unfreezeWriteErrors[0]
					state.unfreezeWriteErrors = state.unfreezeWriteErrors[1:]
					if err != nil {
						return err
					}
				}
				state.state = "0"
				state.descendantState = "0"
			default:
				return fmt.Errorf("unexpected freeze value %q", value)
			}
			return nil
		},
		wait: func(path string, frozen bool) error {
			if path != "/sys/fs/cgroup/cengine/workload" {
				return fmt.Errorf("unexpected wait path %s", path)
			}
			state.waits = append(state.waits, frozen)
			if frozen {
				if state.waitFrozenErr != nil {
					return state.waitFrozenErr
				}
				if state.state != "1" || state.descendantState != "1" {
					return errors.New("workload descendants are not frozen")
				}
				return nil
			}
			if len(state.waitRunningErrors) != 0 {
				err := state.waitRunningErrors[0]
				state.waitRunningErrors = state.waitRunningErrors[1:]
				if err != nil {
					return err
				}
			}
			if state.state != "0" || state.descendantState != "0" {
				return errors.New("workload descendants remain frozen")
			}
			return nil
		},
	}
}

func TestCopyFreezeReadFailureDoesNotAttemptStateChange(t *testing.T) {
	readErr := errors.New("freeze state read failed")
	state := &freezeTestState{state: "0", descendantState: "0", readErr: readErr}
	copyCalled := false
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error {
		copyCalled = true
		return nil
	})
	if !errors.Is(err, readErr) {
		t.Fatalf("copy freeze error = %v, want read failure", err)
	}
	if copyCalled {
		t.Fatal("copy ran without acquiring the freeze guard")
	}
	if len(state.writes) != 0 {
		t.Fatalf("freeze writes after read failure = %v, want none", state.writes)
	}
}

func TestCopyFreezeWriteFailureRestoresPriorRunningState(t *testing.T) {
	writeErr := errors.New("freeze write failed")
	state := &freezeTestState{
		state: "0", descendantState: "0", freezeWriteErr: writeErr,
	}
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error {
		t.Fatal("copy ran after freeze write failure")
		return nil
	})
	if !errors.Is(err, writeErr) {
		t.Fatalf("copy freeze error = %v, want write failure", err)
	}
	if state.state != "0" || state.descendantState != "0" {
		t.Fatal("freeze write failure did not restore the running state")
	}
	if fmt.Sprint(state.writes) != "[1 0]" {
		t.Fatalf("freeze writes = %v, want [1 0]", state.writes)
	}
}

func TestCopyFreezeWaitFailureRestoresPriorRunningState(t *testing.T) {
	waitErr := errors.New("freeze event read failed")
	state := &freezeTestState{
		state: "0", descendantState: "0", waitFrozenErr: waitErr,
	}
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error {
		t.Fatal("copy ran after freeze wait failure")
		return nil
	})
	if !errors.Is(err, waitErr) {
		t.Fatalf("copy freeze error = %v, want wait failure", err)
	}
	if state.state != "0" || state.descendantState != "0" {
		t.Fatal("freeze wait failure did not restore the running state")
	}
	if fmt.Sprint(state.writes) != "[1 0]" {
		t.Fatalf("freeze writes = %v, want [1 0]", state.writes)
	}
}

func TestCopyFreezeAcquisitionAndRestorationFailuresAreJoined(t *testing.T) {
	acquireErr := errors.New("freeze confirmation failed")
	firstRestoreErr := errors.New("first unfreeze failed")
	retryRestoreErr := errors.New("retry unfreeze failed")
	state := &freezeTestState{
		state: "0", descendantState: "0", waitFrozenErr: acquireErr,
		unfreezeWriteErrors: []error{firstRestoreErr, retryRestoreErr},
	}
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error {
		t.Fatal("copy ran after failed freeze acquisition")
		return nil
	})
	for _, want := range []error{acquireErr, firstRestoreErr, retryRestoreErr} {
		if !errors.Is(err, want) {
			t.Fatalf("joined freeze error %v does not include %v", err, want)
		}
	}
	if state.state != "1" || state.descendantState != "1" {
		t.Fatal("failed restoration did not retain the fail-closed frozen state")
	}
	if fmt.Sprint(state.writes) != "[1 0 0]" {
		t.Fatalf("freeze writes = %v, want [1 0 0]", state.writes)
	}
}

func TestCopyAndRestorationFailuresAreJoined(t *testing.T) {
	copyErr := errors.New("copy failed")
	restoreErr := errors.New("unfreeze failed")
	state := &freezeTestState{
		state: "0", descendantState: "0",
		unfreezeWriteErrors: []error{restoreErr},
	}
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error {
		return copyErr
	})
	if !errors.Is(err, copyErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("copy result %v does not preserve copy and restoration failures", err)
	}
	if state.state != "0" || state.descendantState != "0" {
		t.Fatal("restoration retry did not return the workload to running")
	}
	if fmt.Sprint(state.writes) != "[1 0 0]" {
		t.Fatalf("freeze writes = %v, want [1 0 0]", state.writes)
	}
}

func TestCopyResumeConfirmationFailureRemainsReportedAfterSuccessfulRetry(t *testing.T) {
	confirmErr := errors.New("resume event read failed")
	state := &freezeTestState{
		state: "0", descendantState: "0",
		waitRunningErrors: []error{confirmErr},
	}
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error { return nil })
	if !errors.Is(err, confirmErr) {
		t.Fatalf("copy result %v does not report resume confirmation failure", err)
	}
	if state.state != "0" || state.descendantState != "0" {
		t.Fatal("resume confirmation retry did not establish the running state")
	}
	if fmt.Sprint(state.writes) != "[1 0 0]" {
		t.Fatalf("freeze writes = %v, want [1 0 0]", state.writes)
	}
}

func TestCopyPreservesPreviouslyFrozenWorkloadState(t *testing.T) {
	state := &freezeTestState{state: "1", descendantState: "1"}
	copyCalled := false
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error {
		copyCalled = true
		if state.state != "1" || state.descendantState != "1" {
			t.Fatal("previously frozen workload resumed during copy")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !copyCalled {
		t.Fatal("copy did not run for a previously frozen workload")
	}
	if state.state != "1" || state.descendantState != "1" {
		t.Fatal("previously frozen workload was resumed after copy")
	}
	if len(state.writes) != 0 {
		t.Fatalf("previously frozen workload writes = %v, want none", state.writes)
	}
}

func TestCopyFreezeCoversDescendantCgroups(t *testing.T) {
	state := &freezeTestState{state: "0", descendantState: "0"}
	err := withWorkloadFrozenForCopy(42, state.operations(), func() error {
		if state.state != "1" || state.descendantState != "1" {
			t.Fatal("copy ran before the workload and descendants were frozen")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.state != "0" || state.descendantState != "0" {
		t.Fatal("workload descendants did not resume after copy")
	}
	if fmt.Sprint(state.waits) != "[true false]" {
		t.Fatalf("freeze waits = %v, want [true false]", state.waits)
	}
}

func TestArchivePathResolvesRelativeEntries(t *testing.T) {
	root := "/container/tmp"

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "entry", path: "a.txt", want: filepath.Join(root, "a.txt")},
		{name: "dot entry", path: "./a.txt", want: filepath.Join(root, "a.txt")},
		{name: "archive root", path: ".", want: root},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := archivePath(root, test.path)
			if err != nil {
				t.Fatalf("archivePath(%q): %v", test.path, err)
			}
			if got != test.want {
				t.Fatalf("archivePath(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

func TestArchivePathRejectsPathsOutsideDestination(t *testing.T) {
	tests := []struct {
		path string
		want error
	}{
		{path: "", want: syscall.EINVAL},
		{path: "/etc/passwd", want: syscall.EINVAL},
		{path: "../etc/passwd", want: syscall.EPERM},
		{path: "directory/../../etc/passwd", want: syscall.EPERM},
	}

	for _, test := range tests {
		_, err := archivePath("/container/tmp", test.path)
		if !errors.Is(err, test.want) {
			t.Fatalf("archivePath(%q) error = %v, want %v", test.path, err, test.want)
		}
	}
}

func TestTransferDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "transfer")); err != nil {
		t.Fatal(err)
	}

	if transfer, err := openTransferDirectory(root, "transfer"); err == nil {
		transfer.close()
		t.Fatal("openTransferDirectory followed a symbolic link")
	}
}

func TestCopyOutRetainsTransferDirectoryAcrossNameReplacement(t *testing.T) {
	ioRoot := t.TempDir()
	transferPath := filepath.Join(ioRoot, "transfer")
	detachedPath := filepath.Join(ioRoot, "detached")
	outside := t.TempDir()
	if err := os.Mkdir(transferPath, 0o755); err != nil {
		t.Fatal(err)
	}
	transfer, err := openTransferDirectory(ioRoot, "transfer")
	if err != nil {
		t.Fatal(err)
	}
	defer transfer.close()

	sourceRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceRoot, "payload"), []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	if err := os.Rename(transferPath, detachedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, transferPath); err != nil {
		t.Fatal(err)
	}
	if err := copyEntryAt(
		int(source.Fd()), "payload", int(transfer.directory.Fd()), "payload",
	); err != nil {
		t.Fatal(err)
	}
	if err := transfer.validate(); err == nil {
		t.Fatal("replaced copy-out transfer directory was accepted")
	}
	if _, err := os.Lstat(filepath.Join(outside, "payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copy escaped through replacement: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(detachedPath, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("detached payload = %q, want safe", data)
	}
}

func TestCopyInRejectsSubstitutedTransferDirectoryWithoutReadingIt(t *testing.T) {
	ioRoot := t.TempDir()
	transferPath := filepath.Join(ioRoot, "transfer")
	detachedPath := filepath.Join(ioRoot, "detached")
	if err := os.Mkdir(transferPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transferPath, "payload"), []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	transfer, err := openTransferDirectory(ioRoot, "transfer")
	if err != nil {
		t.Fatal(err)
	}
	defer transfer.close()

	if err := os.Rename(transferPath, detachedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(transferPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transferPath, "payload"), []byte("substitute"), 0o644); err != nil {
		t.Fatal(err)
	}
	destinationPath := t.TempDir()
	destination, err := os.Open(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()

	if err := copyDirectoryContents(transfer.directory, destination); err != nil {
		t.Fatal(err)
	}
	if err := transfer.validate(); err == nil {
		t.Fatal("substituted copy-in transfer directory was accepted")
	}
	data, err := os.ReadFile(filepath.Join(destinationPath, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("copied payload = %q, want retained safe content", data)
	}
}

func TestDescriptorTransferCopiesSymlinkWithoutFollowingIt(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.Symlink("../../outside", filepath.Join(sourcePath, "link")); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.Open(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()

	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(destinationPath, "link"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symbolic link was followed during transfer")
	}
	target, err := os.Readlink(filepath.Join(destinationPath, "link"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "../../outside" {
		t.Fatalf("copied link target = %q", target)
	}
}

func TestDescriptorTransferPinsSymlinkAcrossTargetABA(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	linkPath := filepath.Join(sourcePath, "link")
	retainedPath := filepath.Join(sourcePath, "retained")
	if err := os.Symlink("safe-target", linkPath); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	defer source.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()

	err := copyEntryAtWithHooks(
		int(source.Fd()), "link", int(destination.Fd()), "link",
		func() error {
			if err := os.Rename(linkPath, retainedPath); err != nil {
				return err
			}
			if err := os.Symlink("attacker-target", linkPath); err != nil {
				return err
			}
			if err := os.Remove(linkPath); err != nil {
				return err
			}
			return os.Rename(retainedPath, linkPath)
		},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(destinationPath, "link"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "safe-target" {
		t.Fatalf("copied symlink target = %q, want safe-target", target)
	}
}

func TestDescriptorTransferRejectsDestinationReplacementWithoutWritingIt(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "payload"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	defer source.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	targetPath := filepath.Join(destinationPath, "payload")
	retainedPath := filepath.Join(destinationPath, "retained")
	replacement := []byte("replacement")

	err := copyEntryAtWithHooks(
		int(source.Fd()), "payload", int(destination.Fd()), "payload", nil,
		func() error {
			if err := os.Rename(targetPath, retainedPath); err != nil {
				return err
			}
			return os.WriteFile(targetPath, replacement, 0o600)
		},
		nil,
	)
	if err == nil {
		t.Fatal("destination replacement was accepted")
	}
	data, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(data, replacement) {
		t.Fatalf("replacement was modified: %q", data)
	}
	retained, readErr := os.ReadFile(retainedPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(retained) != "safe" {
		t.Fatalf("retained destination = %q, want safe", retained)
	}
}

func TestDescriptorTransferAcceptsDestinationABAOnlyWhenCreatedInodeReturns(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "payload"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	defer source.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	targetPath := filepath.Join(destinationPath, "payload")
	retainedPath := filepath.Join(destinationPath, "retained")
	replacementPath := filepath.Join(destinationPath, "replacement")
	replacement := []byte("replacement")
	if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}

	err := copyEntryAtWithHooks(
		int(source.Fd()), "payload", int(destination.Fd()), "payload", nil,
		func() error {
			if err := os.Rename(targetPath, retainedPath); err != nil {
				return err
			}
			if err := os.Rename(replacementPath, targetPath); err != nil {
				return err
			}
			if err := os.Rename(targetPath, replacementPath); err != nil {
				return err
			}
			return os.Rename(retainedPath, targetPath)
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("created destination = %q, want safe", data)
	}
	data, err = os.ReadFile(replacementPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, replacement) {
		t.Fatalf("replacement was modified: %q", data)
	}
}

func TestStagedReplacementRejectsDestinationSwapAndRestoresReplacement(t *testing.T) {
	destinationPath := t.TempDir()
	targetPath := filepath.Join(destinationPath, "payload")
	retainedPath := filepath.Join(destinationPath, "retained")
	replacementPath := filepath.Join(destinationPath, "replacement")
	temporaryPath := filepath.Join(destinationPath, "staged")
	for path, contents := range map[string]string{
		targetPath: "original", replacementPath: "attacker", temporaryPath: "created",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	existingIdentity, exists, err := optionalIdentityAt(int(destination.Fd()), "payload")
	if err != nil || !exists {
		t.Fatalf("capture existing destination: exists=%v err=%v", exists, err)
	}
	temporaryIdentity, exists, err := optionalIdentityAt(int(destination.Fd()), "staged")
	if err != nil || !exists {
		t.Fatalf("capture staged destination: exists=%v err=%v", exists, err)
	}
	err = installStagedEntryWithHook(
		int(destination.Fd()), "staged", "payload", temporaryIdentity,
		existingIdentity, true,
		func() error {
			if err := os.Rename(targetPath, retainedPath); err != nil {
				return err
			}
			return os.Rename(replacementPath, targetPath)
		},
	)
	if err == nil {
		t.Fatal("destination replacement between identity check and exchange was accepted")
	}
	for path, want := range map[string]string{
		targetPath: "attacker", retainedPath: "original", temporaryPath: "created",
	} {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(data) != want {
			t.Fatalf("%s = %q, want %q", filepath.Base(path), data, want)
		}
	}
}

func TestClaimedRemovalPreservesRegularReplacementAfterValidation(t *testing.T) {
	destinationPath := t.TempDir()
	targetPath := filepath.Join(destinationPath, "payload")
	if err := os.WriteFile(targetPath, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned, err := os.Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	expected, exists, err := optionalIdentityAt(int(destination.Fd()), "payload")
	if err != nil || !exists {
		t.Fatalf("capture removal identity: exists=%v err=%v", exists, err)
	}
	hookCalled := false
	err = removeExactEntryAtWithHook(
		int(destination.Fd()), "payload", expected,
		func(_ int, name string, _ unix.Stat_t) error {
			if name != "payload" {
				return nil
			}
			hookCalled = true
			return os.WriteFile(targetPath, []byte("foreign"), 0o600)
		},
	)
	if err == nil {
		t.Fatal("replacement created after removal validation was accepted")
	}
	if !hookCalled {
		t.Fatal("removal race hook was not called")
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "foreign" {
		t.Fatalf("foreign replacement = %q, want foreign", data)
	}
	var removed unix.Stat_t
	if err := unix.Fstat(int(owned.Fd()), &removed); err != nil {
		t.Fatal(err)
	}
	if removed.Nlink != 0 {
		t.Fatalf("owned displaced file link count = %d, want 0", removed.Nlink)
	}
}

func TestClaimedRemovalPreservesEmptyDirectoryReplacementAfterValidation(t *testing.T) {
	destinationPath := t.TempDir()
	targetPath := filepath.Join(destinationPath, "entry")
	if err := os.Mkdir(targetPath, 0o700); err != nil {
		t.Fatal(err)
	}
	owned := openTestDirectory(t, targetPath)
	defer owned.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	expected, exists, err := optionalIdentityAt(int(destination.Fd()), "entry")
	if err != nil || !exists {
		t.Fatalf("capture removal identity: exists=%v err=%v", exists, err)
	}
	hookCalled := false
	err = removeExactEntryAtWithHook(
		int(destination.Fd()), "entry", expected,
		func(_ int, name string, _ unix.Stat_t) error {
			if name != "entry" {
				return nil
			}
			hookCalled = true
			return os.Mkdir(targetPath, 0o755)
		},
	)
	if err == nil {
		t.Fatal("directory replacement created after removal validation was accepted")
	}
	if !hookCalled {
		t.Fatal("removal race hook was not called")
	}
	replacement, err := os.Lstat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !replacement.IsDir() {
		t.Fatal("foreign directory replacement was removed")
	}
	replacementStat := replacement.Sys().(*syscall.Stat_t)
	if uint64(replacementStat.Ino) == expected.Ino && uint64(replacementStat.Dev) == expected.Dev {
		t.Fatal("original directory remained at the public name")
	}
	var removed unix.Stat_t
	if err := unix.Fstat(int(owned.Fd()), &removed); err != nil {
		t.Fatal(err)
	}
	if removed.Nlink != 0 {
		t.Fatalf("owned displaced directory link count = %d, want 0", removed.Nlink)
	}
}

func TestRemovalNamespaceCreationPreservesSwapBeforeOpen(t *testing.T) {
	parentPath := t.TempDir()
	foreignPath := filepath.Join(parentPath, "foreign")
	retainedPath := filepath.Join(parentPath, "retained-owned")
	if err := os.Mkdir(foreignPath, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := openTestDirectory(t, foreignPath)
	defer foreign.Close()
	var foreignIdentity unix.Stat_t
	if err := unix.Fstat(int(foreign.Fd()), &foreignIdentity); err != nil {
		t.Fatal(err)
	}
	parent := openTestDirectory(t, parentPath)
	defer parent.Close()
	createdName := ""
	createdIdentity := unix.Stat_t{}
	namespace, err := createRemovalNamespaceAtWithHook(
		int(parent.Fd()),
		func(_ int, name string, expected unix.Stat_t) error {
			createdName = name
			createdIdentity = expected
			createdPath := filepath.Join(parentPath, name)
			if err := os.Rename(createdPath, retainedPath); err != nil {
				return err
			}
			return os.Rename(foreignPath, createdPath)
		},
	)
	if namespace != nil {
		namespace.directory.Close()
		t.Fatal("substituted removal namespace was adopted")
	}
	if err == nil {
		t.Fatal("removal namespace swap between mkdir and open was accepted")
	}
	if createdName == "" {
		t.Fatal("namespace creation race hook was not called")
	}
	current, exists, statErr := optionalIdentityAt(int(parent.Fd()), createdName)
	if statErr != nil || !exists {
		t.Fatalf("foreign namespace replacement: exists=%v err=%v", exists, statErr)
	}
	if !sameIdentity(current, foreignIdentity) {
		t.Fatal("foreign namespace replacement was removed or changed")
	}
	retained, exists, statErr := optionalIdentityAt(int(parent.Fd()), filepath.Base(retainedPath))
	if statErr != nil || !exists {
		t.Fatalf("retained owned namespace: exists=%v err=%v", exists, statErr)
	}
	if !sameIdentity(retained, createdIdentity) {
		t.Fatal("created removal namespace was not safely retained")
	}
}

func TestRemovalNamespaceTeardownPreservesSwapAfterValidation(t *testing.T) {
	parentPath := t.TempDir()
	parent := openTestDirectory(t, parentPath)
	defer parent.Close()
	namespace, err := createRemovalNamespaceAt(int(parent.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	foreignPath := filepath.Join(parentPath, "foreign")
	retainedPath := filepath.Join(parentPath, "retained-owned")
	if err := os.Mkdir(foreignPath, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := openTestDirectory(t, foreignPath)
	defer foreign.Close()
	var foreignIdentity unix.Stat_t
	if err := unix.Fstat(int(foreign.Fd()), &foreignIdentity); err != nil {
		t.Fatal(err)
	}
	hookCalled := false
	err = namespace.closeWithHook(func(_ int, name string, _ unix.Stat_t) error {
		hookCalled = true
		namespacePath := filepath.Join(parentPath, name)
		if err := os.Rename(namespacePath, retainedPath); err != nil {
			return err
		}
		return os.Rename(foreignPath, namespacePath)
	})
	if err == nil {
		t.Fatal("removal namespace swap before teardown was accepted")
	}
	if !hookCalled {
		t.Fatal("namespace teardown race hook was not called")
	}
	current, exists, statErr := optionalIdentityAt(int(parent.Fd()), namespace.name)
	if statErr != nil || !exists {
		t.Fatalf("foreign namespace replacement: exists=%v err=%v", exists, statErr)
	}
	if !sameIdentity(current, foreignIdentity) {
		t.Fatal("foreign namespace replacement was removed or changed")
	}
	retained, exists, statErr := optionalIdentityAt(int(parent.Fd()), filepath.Base(retainedPath))
	if statErr != nil || !exists {
		t.Fatalf("retained owned namespace: exists=%v err=%v", exists, statErr)
	}
	if !sameIdentity(retained, namespace.identity) {
		t.Fatal("owned removal namespace was not safely retained")
	}
}

func TestDescriptorTransferRejectsSymlinkDestinationSwapAfterIdentityCheck(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.Symlink("safe-target", filepath.Join(sourcePath, "link")); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	defer source.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	targetPath := filepath.Join(destinationPath, "link")
	retainedPath := filepath.Join(destinationPath, "retained")

	err := copyEntryAtWithHooks(
		int(source.Fd()), "link", int(destination.Fd()), "link", nil, nil,
		func() error {
			if err := os.Rename(targetPath, retainedPath); err != nil {
				return err
			}
			return os.Symlink("attacker-target", targetPath)
		},
	)
	if err == nil {
		t.Fatal("destination symlink replacement was accepted")
	}
	target, readErr := os.Readlink(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if target != "attacker-target" {
		t.Fatalf("replacement target = %q, want attacker-target", target)
	}
	target, readErr = os.Readlink(retainedPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if target != "safe-target" {
		t.Fatalf("retained created target = %q, want safe-target", target)
	}
}

func TestDescriptorTransferPreservesDirectoryAndFileModes(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	nested := filepath.Join(sourcePath, "nested")
	destinationNested := filepath.Join(destinationPath, "nested")
	defer func() {
		for _, path := range []string{nested, destinationNested} {
			if err := os.Chmod(path, 0o700); err != nil && !os.IsNotExist(err) {
				t.Errorf("restore directory mode for cleanup: %v", err)
			}
		}
	}()
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(nested, "payload")
	if err := os.WriteFile(payload, []byte("mode"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nested, 0o510); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(payload, 0o400); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.Open(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()

	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		destinationNested: 0o510,
		filepath.Join(destinationNested, "payload"): 0o400,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("mode for %s = %o, want %o", path, got, want)
		}
	}
}

func TestDescriptorTransferOverwritesExistingRegularFile(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	sourceFile := filepath.Join(sourcePath, "payload")
	destinationFile := filepath.Join(destinationPath, "payload")
	if err := os.WriteFile(sourceFile, []byte("first"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destinationFile, []byte("stale-longer-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	destination := openTestDirectory(t, destinationPath)
	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	source.Close()
	destination.Close()
	if err := os.WriteFile(sourceFile, []byte("second"), 0o604); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sourceFile, 0o604); err != nil {
		t.Fatal(err)
	}
	source = openTestDirectory(t, sourcePath)
	defer source.Close()
	destination = openTestDirectory(t, destinationPath)
	defer destination.Close()
	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destinationFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Fatalf("overwritten payload = %q, want second", data)
	}
	info, err := os.Lstat(destinationFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o604 {
		t.Fatalf("overwritten payload mode = %o, want 604", info.Mode().Perm())
	}
}

func TestDescriptorTransferReplacesSymlinksAndFilesWithoutFollowingTargets(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	outsidePath := t.TempDir()
	outsideFile := filepath.Join(outsidePath, "victim")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceFile := filepath.Join(sourcePath, "payload")
	destinationFile := filepath.Join(destinationPath, "payload")
	if err := os.WriteFile(sourceFile, []byte("regular"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, destinationFile); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	destination := openTestDirectory(t, destinationPath)
	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	source.Close()
	destination.Close()
	data, err := os.ReadFile(destinationFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "regular" {
		t.Fatalf("symlink-to-file replacement = %q, want regular", data)
	}
	outside, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(outside) != "outside" {
		t.Fatalf("outside symlink target changed to %q", outside)
	}

	if err := os.Remove(sourceFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../replacement-target", sourceFile); err != nil {
		t.Fatal(err)
	}
	source = openTestDirectory(t, sourcePath)
	defer source.Close()
	destination = openTestDirectory(t, destinationPath)
	defer destination.Close()
	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(destinationFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("regular file was not replaced by a symbolic link")
	}
	target, err := os.Readlink(destinationFile)
	if err != nil {
		t.Fatal(err)
	}
	if target != "../replacement-target" {
		t.Fatalf("replacement symlink target = %q", target)
	}
}

func TestDescriptorTransferMergesExistingDirectories(t *testing.T) {
	sourcePath := t.TempDir()
	destinationPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(sourcePath, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "nested", "incoming"), []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "nested", "shared"), []byte("updated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(destinationPath, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destinationPath, "nested", "retained"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destinationPath, "nested", "shared"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	defer source.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"incoming": "new", "retained": "keep", "shared": "updated",
	} {
		data, err := os.ReadFile(filepath.Join(destinationPath, "nested", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("merged %s = %q, want %q", name, data, want)
		}
	}
}

func TestDescriptorTransferReplacesDirectoryAndNonDirectoryTypes(t *testing.T) {
	t.Run("file with directory", func(t *testing.T) {
		sourcePath := t.TempDir()
		destinationPath := t.TempDir()
		if err := os.Mkdir(filepath.Join(sourcePath, "entry"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sourcePath, "entry", "payload"), []byte("inside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destinationPath, "entry"), []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		source := openTestDirectory(t, sourcePath)
		defer source.Close()
		destination := openTestDirectory(t, destinationPath)
		defer destination.Close()
		if err := copyDirectoryContents(source, destination); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(destinationPath, "entry", "payload"))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "inside" {
			t.Fatalf("replacement directory payload = %q", data)
		}
	})

	t.Run("directory with file", func(t *testing.T) {
		sourcePath := t.TempDir()
		destinationPath := t.TempDir()
		outsidePath := t.TempDir()
		outsideFile := filepath.Join(outsidePath, "victim")
		if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sourcePath, "entry"), []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(destinationPath, "entry"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideFile, filepath.Join(destinationPath, "entry", "outside-link")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destinationPath, "entry", "old"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		source := openTestDirectory(t, sourcePath)
		defer source.Close()
		destination := openTestDirectory(t, destinationPath)
		defer destination.Close()
		if err := copyDirectoryContents(source, destination); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(destinationPath, "entry"))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "file" {
			t.Fatalf("replacement file = %q", data)
		}
		outside, err := os.ReadFile(outsideFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(outside) != "outside" {
			t.Fatalf("outside symlink target changed to %q", outside)
		}
	})
}

func TestDescriptorTransferRetainsDestinationParentAcrossPathReplacement(t *testing.T) {
	base := t.TempDir()
	sourcePath := filepath.Join(base, "source")
	destinationPath := filepath.Join(base, "destination")
	detachedPath := filepath.Join(base, "detached")
	outsidePath := filepath.Join(base, "outside")
	for _, path := range []string{sourcePath, destinationPath, outsidePath} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "payload"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := openTestDirectory(t, sourcePath)
	defer source.Close()
	destination := openTestDirectory(t, destinationPath)
	defer destination.Close()
	if err := os.Rename(destinationPath, detachedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsidePath, destinationPath); err != nil {
		t.Fatal(err)
	}
	if err := copyDirectoryContents(source, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(detachedPath, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("detached payload = %q", data)
	}
	if _, err := os.Lstat(filepath.Join(outsidePath, "payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copy escaped through replacement parent: %v", err)
	}
}

func TestCopyIntoRootConfinesIntermediateSymlinks(t *testing.T) {
	for _, test := range []struct {
		name   string
		target func(root, outside string) string
	}{
		{
			name: "absolute",
			target: func(_, outside string) string {
				return outside
			},
		},
		{
			name: "relative",
			target: func(root, outside string) string {
				relative, err := filepath.Rel(root, outside)
				if err != nil {
					t.Fatal(err)
				}
				return relative
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			rootPath := filepath.Join(base, "root")
			outsidePath := filepath.Join(base, "outside")
			sourcePath := filepath.Join(base, "source")
			for _, path := range []string{rootPath, outsidePath, sourcePath} {
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(test.target(rootPath, outsidePath), filepath.Join(rootPath, "escape")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sourcePath, "payload"), []byte("inside"), 0o644); err != nil {
				t.Fatal(err)
			}
			root := openTestDirectory(t, rootPath)
			defer root.Close()
			source := openTestDirectory(t, sourcePath)
			defer source.Close()

			if err := copyIntoRoot(root, source, "/escape/nested", nil); err == nil {
				t.Fatal("copy-in escaped through an intermediate symbolic link")
			}
			if _, err := os.Lstat(filepath.Join(outsidePath, "nested", "payload")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("copy-in wrote outside the container root: %v", err)
			}
		})
	}
}

func TestCopyIntoRootAllowsInternalIntermediateSymlinks(t *testing.T) {
	for _, target := range []string{"/inside", "inside"} {
		t.Run(target, func(t *testing.T) {
			rootPath := t.TempDir()
			insidePath := filepath.Join(rootPath, "inside")
			if err := os.Mkdir(insidePath, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(rootPath, "redirect")); err != nil {
				t.Fatal(err)
			}
			sourcePath := t.TempDir()
			if err := os.WriteFile(filepath.Join(sourcePath, "payload"), []byte("inside"), 0o644); err != nil {
				t.Fatal(err)
			}
			root := openTestDirectory(t, rootPath)
			defer root.Close()
			source := openTestDirectory(t, sourcePath)
			defer source.Close()

			if err := copyIntoRoot(root, source, "/redirect/nested", nil); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(insidePath, "nested", "payload"))
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "inside" {
				t.Fatalf("payload = %q, want inside", data)
			}
		})
	}
}

func TestCopyOutOfRootConfinesIntermediateSymlinks(t *testing.T) {
	for _, test := range []struct {
		name   string
		target func(root, outside string) string
	}{
		{name: "absolute", target: func(_, outside string) string { return outside }},
		{name: "relative", target: func(root, outside string) string {
			relative, err := filepath.Rel(root, outside)
			if err != nil {
				t.Fatal(err)
			}
			return relative
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			rootPath := filepath.Join(base, "root")
			outsidePath := filepath.Join(base, "outside")
			targetPath := filepath.Join(base, "target")
			for _, path := range []string{rootPath, outsidePath, targetPath} {
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(outsidePath, "secret"), []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(test.target(rootPath, outsidePath), filepath.Join(rootPath, "escape")); err != nil {
				t.Fatal(err)
			}
			root := openTestDirectory(t, rootPath)
			defer root.Close()
			target := openTestDirectory(t, targetPath)
			defer target.Close()

			if err := copyOutOfRoot(root, "/escape/secret", target); err == nil {
				t.Fatal("copy-out escaped through an intermediate symbolic link")
			}
			if _, err := os.Lstat(filepath.Join(targetPath, "secret")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("copy-out exposed an outside file: %v", err)
			}
		})
	}
}

func TestCopyOutOfRootAllowsInternalIntermediateSymlinks(t *testing.T) {
	for _, linkTarget := range []string{"/inside", "inside"} {
		t.Run(linkTarget, func(t *testing.T) {
			rootPath := t.TempDir()
			insidePath := filepath.Join(rootPath, "inside")
			if err := os.Mkdir(insidePath, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(insidePath, "payload"), []byte("inside"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(linkTarget, filepath.Join(rootPath, "redirect")); err != nil {
				t.Fatal(err)
			}
			targetPath := t.TempDir()
			root := openTestDirectory(t, rootPath)
			defer root.Close()
			target := openTestDirectory(t, targetPath)
			defer target.Close()

			if err := copyOutOfRoot(root, "/redirect/payload", target); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(targetPath, "payload"))
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "inside" {
				t.Fatalf("payload = %q, want inside", data)
			}
		})
	}
}

func TestOwnershipConfinesIntermediateSymlinks(t *testing.T) {
	for _, test := range []struct {
		name   string
		target func(root, outside string) string
	}{
		{name: "absolute", target: func(_, outside string) string { return outside }},
		{name: "relative", target: func(root, outside string) string {
			relative, err := filepath.Rel(root, outside)
			if err != nil {
				t.Fatal(err)
			}
			return relative
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			rootPath := filepath.Join(base, "root")
			outsidePath := filepath.Join(base, "outside")
			for _, path := range []string{rootPath, outsidePath} {
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			victimPath := filepath.Join(outsidePath, "victim")
			if err := os.WriteFile(victimPath, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(test.target(rootPath, outsidePath), filepath.Join(rootPath, "escape")); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(victimPath)
			if err != nil {
				t.Fatal(err)
			}
			beforeStat := before.Sys().(*syscall.Stat_t)
			root := openTestDirectory(t, rootPath)
			defer root.Close()

			if err := applyOwnership(root, []Ownership{{
				Path: "escape/victim", User: beforeStat.Uid ^ 1, Group: beforeStat.Gid,
			}}); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(victimPath)
			if err != nil {
				t.Fatal(err)
			}
			afterStat := after.Sys().(*syscall.Stat_t)
			if afterStat.Uid != beforeStat.Uid || afterStat.Gid != beforeStat.Gid {
				t.Fatalf("outside ownership changed from %d:%d to %d:%d", beforeStat.Uid, beforeStat.Gid, afterStat.Uid, afterStat.Gid)
			}
		})
	}
}

func TestOwnershipAllowsInternalIntermediateSymlink(t *testing.T) {
	rootPath := t.TempDir()
	insidePath := filepath.Join(rootPath, "inside")
	if err := os.Mkdir(insidePath, 0o755); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(insidePath, "payload")
	if err := os.WriteFile(payloadPath, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/inside", filepath.Join(rootPath, "redirect")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	root := openTestDirectory(t, rootPath)
	defer root.Close()
	if err := applyOwnership(root, []Ownership{{
		Path: "redirect/payload", User: stat.Uid, Group: stat.Gid,
	}}); err != nil {
		t.Fatal(err)
	}
}

func openTestDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
