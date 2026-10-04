//go:build linux && (amd64 || arm64)

package storageidentity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

const leaderProbeEnv = "CENGINE_STORAGEIDENTITY_LEADER_PROBE"

// init is guaranteed to execute on m0. Only the subprocess keeps this lock;
// normal package tests release it before m.Run, so their leader stays eligible
// for ordinary Go scheduling and Worker.Do must protect it itself.
func init() { runtime.LockOSThread() }

func TestMain(m *testing.M) {
	if os.Getenv(leaderProbeEnv) == "1" {
		if err := probeLeaderHandoff(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	runtime.UnlockOSThread()
	os.Exit(m.Run())
}

func TestLeaderHandoffPreservesProcessAndCleanThreads(t *testing.T) {
	requireRoot(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestLeaderHandoffPreservesProcessAndCleanThreads$")
	cmd.Env = append(os.Environ(), leaderProbeEnv+"=1")
	cmd.WaitDelay = 10 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("leader handoff: %v\n%s", err, output)
	}
}

type rawThreadState struct {
	UID, GID     [3]uint32
	FSUID, FSGID uint32
	Groups       []uint32
	Caps         [2]unix.CapUserData
	Proc, CWD    string
}

// The caller holds its OS thread while this reads actual syscall credentials,
// separately from the leader-oriented /proc/self measurement.
func currentThreadState() (s rawThreadState, err error) {
	if s.UID, err = getIDs(unix.SYS_GETRESUID); err != nil {
		return
	}
	if s.GID, err = getIDs(unix.SYS_GETRESGID); err != nil {
		return
	}
	uid, _, _ := unix.RawSyscall(unix.SYS_SETFSUID, uintptr(^uint32(0)), 0, 0)
	gid, _, _ := unix.RawSyscall(unix.SYS_SETFSGID, uintptr(^uint32(0)), 0, 0)
	s.FSUID, s.FSGID = uint32(uid), uint32(gid)
	if s.Groups, err = getGroups(); err != nil {
		return
	}
	if s.Caps, err = getCaps(); err != nil {
		return
	}
	if s.Proc, err = credentialStatus("/proc/thread-self/status"); err != nil {
		return
	}
	s.CWD, err = os.Readlink("/proc/thread-self/cwd")
	return
}

func credentialStatus(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var fields []string
	for _, line := range strings.Split(string(data), "\n") {
		for _, prefix := range []string{"Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "Umask:"} {
			if strings.HasPrefix(line, prefix) {
				fields = append(fields, line)
			}
		}
	}
	return strings.Join(fields, "\n"), nil
}

func probeLeaderHandoff() error {
	if !isLeader() || os.Geteuid() != 0 {
		return errors.New("probe must start on actual Linux root leader")
	}
	before, err := currentThreadState()
	if err != nil {
		return err
	}
	leaderBefore, err := credentialStatus("/proc/self/status")
	if err != nil {
		return err
	}
	if leaderBefore != before.Proc {
		return errors.New("leader and current thread already differ")
	}
	id := storagewire.Caller{FSUID: 32001, FSGID: 32002, Groups: []uint32{32003}}
	// The installer's independent guard must fail before even unshare/umask.
	if err := install(id, 077); !errors.Is(err, unix.EINVAL) || !strings.Contains(err.Error(), "leader") {
		return fmt.Errorf("leader install was not rejected: %v", err)
	}
	if after, err := currentThreadState(); err != nil || !reflect.DeepEqual(after, before) {
		return fmt.Errorf("leader guard mutated state: %+v %v", after, err)
	}

	file, err := os.CreateTemp("", "storageidentity-procfd-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0644); err != nil {
		return err
	}
	procFD := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	reopen := func() error {
		f, err := os.Open(procFD)
		if err != nil {
			return err
		}
		return f.Close()
	}
	if err := reopen(); err != nil {
		return fmt.Errorf("proc fd before: %w", err)
	}

	entered, result := make(chan int, 1), make(chan error, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWorker()
	// Invoke the exact production dispatch on m0, deterministically exercising
	// its handoff rather than relying on scheduler luck to select the leader.
	dispatch(func() {
		if isLeader() {
			result <- errors.New("callback selected leader")
			return
		}
		if err := install(id, 077); err != nil {
			result <- err
			return
		}
		entered <- unix.Gettid()
		<-release
		result <- reopen() // Proc descriptor reopen under the nonroot identity.
	})
	var workerTID int
	select {
	case workerTID = <-entered:
	case err := <-result:
		return fmt.Errorf("handoff setup: %w", err)
	case <-time.After(10 * time.Second):
		return errors.New("handoff stalled")
	}
	if workerTID == os.Getpid() {
		return errors.New("worker mutated leader")
	}

	// Spawn outside the credentialed callback, after its identity is installed.
	// Holding these clean threads concurrently forces new runtime thread creation.
	const count = 16
	states := make(chan error, count)
	cleanRelease := make(chan struct{})
	var wg sync.WaitGroup
	defer func() { close(cleanRelease); wg.Wait() }()
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread() // Read-only clean observer, never an identity worker.
			got, err := currentThreadState()
			if err == nil && !reflect.DeepEqual(got, before) {
				err = fmt.Errorf("new goroutine inherited request credentials/fs: %+v", got)
			}
			states <- err
			<-cleanRelease
		}()
	}
	for i := 0; i < count; i++ {
		select {
		case err := <-states:
			if err != nil {
				return err
			}
		case <-time.After(10 * time.Second):
			return errors.New("clean thread observer stalled")
		}
	}
	// Include runtime/template threads, not just the test's observed goroutines.
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if task.Name() == strconv.Itoa(workerTID) {
			continue
		}
		got, err := credentialStatus(filepath.Join("/proc/self/task", task.Name(), "status"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} // Runtime thread exited during enumeration.
		if err != nil {
			return err
		}
		if got != leaderBefore {
			return fmt.Errorf("active clean thread %s contaminated:\n%s", task.Name(), got)
		}
	}
	releaseWorker()
	if err := <-result; err != nil {
		return fmt.Errorf("nonroot proc fd after handoff: %w", err)
	}
	if err := reopen(); err != nil {
		return fmt.Errorf("service proc fd after handoff: %w", err)
	}
	if after, err := currentThreadState(); err != nil || !reflect.DeepEqual(after, before) {
		return fmt.Errorf("executing leader changed: %+v %v", after, err)
	}
	if after, err := credentialStatus("/proc/self/status"); err != nil || after != leaderBefore {
		return fmt.Errorf("canonical leader changed: %s %v", after, err)
	}
	return nil
}
