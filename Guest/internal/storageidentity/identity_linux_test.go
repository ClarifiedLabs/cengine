//go:build linux && (amd64 || arm64)

package storageidentity

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires actual Linux root with identity setup capabilities")
	}
}

func serviceState(t *testing.T) string {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, line := range strings.Split(string(status), "\n") {
		for _, prefix := range []string{"Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "Umask:"} {
			if strings.HasPrefix(line, prefix) {
				fields = append(fields, line)
			}
		}
	}
	cwd, err := os.Readlink("/proc/self/cwd")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(fields, "\n") + "\n" + cwd
}

func run(t *testing.T, w *Worker, id storagewire.Caller, mask uint32, fn func() error) {
	t.Helper()
	if err := w.Do(id, mask, fn); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxKernelIdentity(t *testing.T) {
	requireRoot(t)
	before := serviceState(t)
	mask, err := kernelCaps()
	if err != nil {
		t.Fatal(err)
	}
	caps, err := getCaps()
	if err != nil {
		t.Fatal(err)
	}
	available := (uint64(caps[0].Permitted) | uint64(caps[1].Permitted)<<32) & mask
	var w Worker
	for name, id := range map[string]storagewire.Caller{
		"root-zero":       {Groups: []uint32{}},
		"root-real-caps":  {Groups: []uint32{0}, EffectiveCaps: available},
		"nonroot-zero":    {FSUID: 21001, FSGID: 21002, Groups: []uint32{31, 7, 31}},
		"nonroot-cap":     {FSUID: 21001, FSGID: 21002, Groups: []uint32{}, EffectiveCaps: 1 << unix.CAP_DAC_OVERRIDE},
		"large-valid-ids": {FSUID: ^uint32(0) - 1, FSGID: ^uint32(0) - 1, Groups: []uint32{^uint32(0) - 1}},
	} {
		t.Run(name, func(t *testing.T) {
			want := id
			want.Groups = slices.Clone(id.Groups)
			slices.Sort(want.Groups)
			run(t, &w, id, 027, func() error { return verify(want, mask) })
		})
	}
	// Actual setgroups boundary, not just codec acceptance. Duplicate entries
	// are legal in Linux's sorted group_info and must not be deduplicated.
	groups := make([]uint32, storagewire.MaxGroups)
	for i := range groups {
		groups[i] = uint32(30000 + i/2)
	}
	id := storagewire.Caller{FSUID: 21001, FSGID: 21002, Groups: groups}
	run(t, &w, id, 0, func() error { return verify(id, mask) })
	for _, invalid := range []uint64{^uint64(0), uint64(1) << 63} {
		if invalid & ^mask == 0 {
			continue
		}
		err := w.Do(storagewire.Caller{Groups: []uint32{}, EffectiveCaps: invalid}, 0, func() error { return errors.New("must not run") })
		if !errors.Is(err, unix.EINVAL) {
			t.Fatalf("unsupported caps accepted: %v", err)
		}
	}
	if after := serviceState(t); after != before {
		t.Fatalf("service identity/fs changed:\nbefore %s\nafter %s", before, after)
	}
}

func fixtureDir(t *testing.T) (string, int) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return root, fd
}

func openRead(dir int, name string) error {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func TestDroppedCapabilitiesDenyRealFileAccess(t *testing.T) {
	requireRoot(t)
	root, dir := fixtureDir(t)
	path := filepath.Join(root, "secret")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 22001, 22002); err != nil {
		t.Fatal(err)
	}
	var w Worker
	for _, uid := range []uint32{0, 23001} {
		for _, capabilities := range []uint64{0, 1 << unix.CAP_DAC_OVERRIDE} {
			id := storagewire.Caller{FSUID: uid, FSGID: 23002, Groups: []uint32{}, EffectiveCaps: capabilities}
			run(t, &w, id, 0, func() error {
				err := openRead(dir, "secret")
				if capabilities == 0 && !errors.Is(err, unix.EACCES) {
					return fmt.Errorf("uid %d without caps: %v", uid, err)
				}
				if capabilities != 0 && err != nil {
					return err
				}
				return nil
			})
		}
	}
}

func TestMoreThan16GroupsGrantActualACLAccess(t *testing.T) {
	requireRoot(t)
	root, dir := fixtureDir(t)
	path := filepath.Join(root, "acl")
	if err := os.WriteFile(path, []byte("acl"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 24001, 24002); err != nil {
		t.Fatal(err)
	}
	const aclGroup uint32 = 25039
	// Linux POSIX ACL xattr v2: user_obj, group_obj, named group, mask, other.
	entries := []struct {
		tag, perm uint16
		id        uint32
	}{
		{1, 0, ^uint32(0)}, {4, 0, ^uint32(0)}, {8, 4, aclGroup}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)},
	}
	acl := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(acl, 2)
	for i, entry := range entries {
		p := acl[4+i*8:]
		binary.LittleEndian.PutUint16(p, entry.tag)
		binary.LittleEndian.PutUint16(p[2:], entry.perm)
		binary.LittleEndian.PutUint32(p[4:], entry.id)
	}
	if err := unix.Setxattr(path, "system.posix_acl_access", acl, 0); err != nil {
		t.Fatalf("real POSIX ACL required (run on ext4): %v", err)
	}
	groups := make([]uint32, 40)
	for i := range groups {
		groups[i] = 25000 + uint32(i)
	}
	groups = append(groups, groups[0]) // Real Linux permits duplicates too.
	original := slices.Clone(groups)
	var w Worker
	for _, count := range []int{16, len(groups)} {
		id := storagewire.Caller{FSUID: 24003, FSGID: 24004, Groups: groups[:count]}
		run(t, &w, id, 0, func() error {
			err := openRead(dir, "acl")
			if count == 16 && !errors.Is(err, unix.EACCES) {
				return fmt.Errorf("truncated groups granted ACL access: %v", err)
			}
			if count > 16 && err != nil {
				return fmt.Errorf("full groups denied ACL access: %w", err)
			}
			return nil
		})
	}
	if !slices.Equal(groups, original) {
		t.Fatal("caller group slice was mutated")
	}
}

func TestUmaskCWDAndConcurrentIdentityIsolation(t *testing.T) {
	requireRoot(t)
	before := serviceState(t)
	root, dir := fixtureDir(t)
	var w Worker
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := storagewire.Caller{FSUID: uint32(26000 + i), FSGID: uint32(27000 + i), Groups: []uint32{uint32(28000 + i)}}
			mask := uint32(0077)
			if i%2 != 0 {
				mask = 0027
			}
			errs <- w.Do(id, mask, func() error {
				if _, _, errno := unix.RawSyscall(unix.SYS_FCHDIR, uintptr(dir), 0, 0); errno != 0 {
					return errno
				}
				fd, err := unix.Openat(unix.AT_FDCWD, fmt.Sprintf("file-%d", i), unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC, 0666)
				if err != nil {
					return err
				}
				defer unix.Close(fd)
				var stat unix.Stat_t
				if err := unix.Fstat(fd, &stat); err != nil {
					return err
				}
				if stat.Uid != id.FSUID || stat.Gid != id.FSGID || stat.Mode&0777 != 0666 & ^mask {
					return fmt.Errorf("wrong create identity/mode: %+v", stat)
				}
				groups, err := getGroups()
				if err != nil {
					return err
				}
				if !slices.Equal(groups, id.Groups) {
					return fmt.Errorf("groups leaked: %v", groups)
				}
				return nil
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 24 {
		t.Fatalf("files = %d, error %v", len(files), err)
	}
	if after := serviceState(t); after != before {
		t.Fatalf("process umask/cwd/identity changed:\n%s\n%s", before, after)
	}
}

func TestBoundedSynchronousWorkersAndRetirement(t *testing.T) {
	requireRoot(t)
	before := serviceState(t)
	var w Worker
	// A smaller private semaphore makes exhaustion deterministic without making
	// production capacity or syscall behavior configurable.
	w.once.Do(func() { w.slots = make(chan struct{}, 2) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	results := make(chan error, 8)
	var active, maximum atomic.Int32
	for i := 0; i < 8; i++ {
		go func() {
			results <- w.Do(storagewire.Caller{FSUID: 29001, FSGID: 29002, Groups: []uint32{}}, 0, func() error {
				n := active.Add(1)
				defer active.Add(-1)
				for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
				}
				entered <- struct{}{}
				<-release
				return ctx.Err()
			})
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case err := <-results:
			t.Fatalf("setup: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("worker did not enter")
		}
	}
	cancel()
	select {
	case <-entered:
		t.Error("semaphore admitted third callback")
	case err := <-results:
		t.Errorf("returned before callback completion: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	for i := 0; i < 8; i++ {
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}
	if maximum.Load() != 2 {
		t.Fatalf("active max = %d", maximum.Load())
	}
	for _, callback := range []func() error{
		func() error { panic("private request data") },
		func() error { runtime.Goexit(); return nil },
	} {
		if err := w.Do(storagewire.Caller{FSUID: 29003, FSGID: 29004, Groups: []uint32{7}}, 077, callback); err == nil || strings.Contains(err.Error(), "private request") {
			t.Fatalf("abnormal callback: %v", err)
		}
	}
	run(t, &w, storagewire.Caller{Groups: []uint32{}}, 0, func() error {
		ids, err := getIDs(unix.SYS_GETRESUID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(ids, [3]uint32{}) {
			return fmt.Errorf("retired credentials reused: %v", ids)
		}
		return nil
	})
	if after := serviceState(t); after != before {
		t.Fatal("service identity changed")
	}
}

func TestRealSetupFailureRetiresThread(t *testing.T) {
	requireRoot(t)
	before := serviceState(t)
	var w Worker
	const setupCaps = uint64(1)<<unix.CAP_SETUID | uint64(1)<<unix.CAP_SETGID
	// Intentionally reduce authority on an already disposable thread, then run
	// the real installer again. No syscall mocks or process-wide mutation: even
	// a host with all capabilities gets deterministic partial-install failures.
	for _, stage := range []string{"setresuid", "capset"} {
		t.Run(stage, func(t *testing.T) {
			var tid int
			err := w.Do(storagewire.Caller{Groups: []uint32{}, EffectiveCaps: setupCaps}, 0, func() error {
				tid = unix.Gettid()
				keep := uint32(setupCaps)
				if stage == "setresuid" {
					keep = 1 << unix.CAP_SETGID
				}
				if err := setCaps([2]unix.CapUserData{{Effective: keep, Permitted: keep}, {}}); err != nil {
					return err
				}
				return install(storagewire.Caller{FSUID: 30001, FSGID: 30002, Groups: []uint32{30003}, EffectiveCaps: 1 << unix.CAP_DAC_OVERRIDE}, 077)
			})
			if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), stage) {
				t.Fatalf("partial %s failure: %v", stage, err)
			}
			waitForRetirement(t, tid)
		})
	}
	run(t, &w, storagewire.Caller{FSUID: 30004, FSGID: 30005, Groups: []uint32{}}, 0, func() error { return nil })
	if after := serviceState(t); after != before {
		t.Fatal("failed setup leaked identity or umask")
	}
}

func waitForRetirement(t *testing.T, tid int) {
	t.Helper()
	if tid == 0 {
		t.Fatal("worker never acquired a Linux thread")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := os.Stat(fmt.Sprintf("/proc/self/task/%d", tid))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("credentialed thread %d was reused instead of retired", tid)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAsyncSnapshotAndThreadRetirement(t *testing.T) {
	requireRoot(t)
	var w Worker
	caller := storagewire.Caller{FSUID: 31001, FSGID: 31002, Groups: []uint32{9, 2, 9}}
	entered, resume := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	var tid int
	go func() {
		result <- w.Do(caller, 0, func() error {
			tid = unix.Gettid()
			close(entered)
			<-resume
			groups, err := getGroups()
			if err != nil {
				return err
			}
			if !slices.Equal(groups, []uint32{2, 9, 9}) {
				return fmt.Errorf("async groups changed: %v", groups)
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("setup: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not enter")
	}
	if !slices.Equal(caller.Groups, []uint32{9, 2, 9}) {
		t.Error("Do sorted caller's slice in place")
	}
	caller.Groups[0] = 99 // After synchronized copy; no concurrent initial-copy race.
	close(resume)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	waitForRetirement(t, tid)
}
