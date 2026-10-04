//go:build linux && (amd64 || arm64)

package storageidentity

import (
	"fmt"
	"runtime"
	"slices"
	"unsafe"

	"dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func isLeader() bool {
	tid, _, tidErr := unix.RawSyscall(unix.SYS_GETTID, 0, 0, 0)
	pid, _, pidErr := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
	// An unavailable thread identity is not permission to mutate it.
	return tidErr != 0 || pidErr != 0 || tid == pid
}

// install is only called on a locked, disposable thread. Every credential and
// fs_struct mutation uses a raw syscall, never Go/libc's process-wide wrappers.
func install(id storagewire.Caller, umask uint32) error {
	// Defense in depth: m0 is not disposable (Go parks it in runtime.mexit).
	if isLeader() {
		return fmt.Errorf("refusing thread-group leader: %w", unix.EINVAL)
	}
	mask, err := kernelCaps()
	if err != nil {
		return err
	}
	if id.EffectiveCaps & ^mask != 0 {
		return fmt.Errorf("unsupported capability bits: %w", unix.EINVAL)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_UNSHARE, unix.CLONE_FS, 0, 0); errno != 0 {
		return fmt.Errorf("unshare CLONE_FS: %w", errno)
	}
	// From here cwd/root/umask belong only to this disposable thread.
	if _, _, errno := unix.RawSyscall(unix.SYS_UMASK, uintptr(umask), 0, 0); errno != 0 {
		return fmt.Errorf("umask: %w", errno)
	}
	if _, err := prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); err != nil {
		return fmt.Errorf("clear ambient: %w", err)
	}
	keep := uintptr(0)
	if id.FSUID != 0 && id.EffectiveCaps != 0 {
		keep = 1
	}
	if _, err := prctl(unix.PR_SET_KEEPCAPS, keep, 0); err != nil {
		return fmt.Errorf("set keepcaps: %w", err)
	}
	var groups unsafe.Pointer
	if len(id.Groups) > 0 {
		groups = unsafe.Pointer(&id.Groups[0])
	}
	_, _, errno := unix.RawSyscall(unix.SYS_SETGROUPS, uintptr(len(id.Groups)), uintptr(groups), 0)
	runtime.KeepAlive(id.Groups)
	if errno != 0 {
		return fmt.Errorf("setgroups: %w", errno)
	}
	gid, uid := uintptr(id.FSGID), uintptr(id.FSUID)
	if _, _, errno := unix.RawSyscall(unix.SYS_SETRESGID, gid, gid, gid); errno != 0 {
		return fmt.Errorf("setresgid: %w", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, uid, uid, uid); errno != 0 {
		return fmt.Errorf("setresuid: %w", errno)
	}
	// Explicitly establish fs IDs before capset: changing fsuid can itself alter
	// effective filesystem capabilities. Query afterwards; setters fail silently.
	unix.RawSyscall(unix.SYS_SETFSGID, gid, 0, 0)
	unix.RawSyscall(unix.SYS_SETFSUID, uid, 0, 0)
	data := [2]unix.CapUserData{
		{Effective: uint32(id.EffectiveCaps), Permitted: uint32(id.EffectiveCaps)},
		{Effective: uint32(id.EffectiveCaps >> 32), Permitted: uint32(id.EffectiveCaps >> 32)},
	}
	if err := setCaps(data); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	if _, err := prctl(unix.PR_SET_KEEPCAPS, 0, 0); err != nil {
		return fmt.Errorf("clear keepcaps: %w", err)
	}
	return verify(id, mask)
}

func prctl(option, arg2, arg3 uintptr) (uintptr, error) {
	r, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, option, arg2, arg3, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

// PR_CAPBSET_READ distinguishes unsupported bits (EINVAL) from supported bits
// absent from this service's bounding set (0). Never mask away requested bits.
func kernelCaps() (uint64, error) {
	var mask uint64
	for bit := uintptr(0); bit < 64; bit++ {
		if _, err := prctl(unix.PR_CAPBSET_READ, bit, 0); err != nil {
			if err == unix.EINVAL && bit != 0 {
				return mask, nil
			}
			return 0, fmt.Errorf("kernel capability mask: %w", err)
		}
		mask |= uint64(1) << bit
	}
	return mask, nil
}

func setCaps(data [2]unix.CapUserData) error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	_, _, errno := unix.RawSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func getCaps() ([2]unix.CapUserData, error) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	_, _, errno := unix.RawSyscall(unix.SYS_CAPGET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return data, errno
	}
	return data, nil
}

func getIDs(trap uintptr) ([3]uint32, error) {
	var ids [3]uint32
	_, _, errno := unix.RawSyscall(trap, uintptr(unsafe.Pointer(&ids[0])), uintptr(unsafe.Pointer(&ids[1])), uintptr(unsafe.Pointer(&ids[2])))
	if errno != 0 {
		return ids, errno
	}
	return ids, nil
}

func getGroups() ([]uint32, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_GETGROUPS, 0, 0, 0)
	if errno != 0 {
		return nil, errno
	}
	if n > storagewire.MaxGroups {
		return nil, unix.EOVERFLOW
	}
	groups := make([]uint32, int(n))
	if n != 0 {
		got, _, errno := unix.RawSyscall(unix.SYS_GETGROUPS, n, uintptr(unsafe.Pointer(&groups[0])), 0)
		if errno != 0 {
			return nil, errno
		}
		if got != n {
			return nil, unix.EIO
		}
	}
	return groups, nil
}

func verify(id storagewire.Caller, mask uint64) error {
	for _, pair := range []struct {
		trap uintptr
		id   uint32
	}{{unix.SYS_GETRESUID, id.FSUID}, {unix.SYS_GETRESGID, id.FSGID}} {
		ids, err := getIDs(pair.trap)
		if err != nil {
			return err
		}
		if ids != [3]uint32{pair.id, pair.id, pair.id} {
			return fmt.Errorf("real/effective/saved IDs differ: %w", unix.EPERM)
		}
	}
	uid, _, _ := unix.RawSyscall(unix.SYS_SETFSUID, uintptr(^uint32(0)), 0, 0)
	gid, _, _ := unix.RawSyscall(unix.SYS_SETFSGID, uintptr(^uint32(0)), 0, 0)
	if uint32(uid) != id.FSUID || uint32(gid) != id.FSGID {
		return fmt.Errorf("fs IDs differ: %w", unix.EPERM)
	}
	groups, err := getGroups()
	if err != nil {
		return err
	}
	if !slices.Equal(groups, id.Groups) {
		return fmt.Errorf("supplementary groups differ: %w", unix.EPERM)
	}
	data, err := getCaps()
	if err != nil {
		return err
	}
	for i, word := range data {
		want := uint32(id.EffectiveCaps >> (32 * i))
		if word.Effective != want || word.Permitted != want || word.Inheritable != 0 {
			return fmt.Errorf("capability sets differ: %w", unix.EPERM)
		}
	}
	for bit := uintptr(0); bit < 64 && mask&(uint64(1)<<bit) != 0; bit++ {
		ambient, err := prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, bit)
		if err != nil {
			return err
		}
		if ambient != 0 {
			return fmt.Errorf("ambient capabilities remain: %w", unix.EPERM)
		}
	}
	keep, err := prctl(unix.PR_GET_KEEPCAPS, 0, 0)
	if err != nil {
		return err
	}
	if keep != 0 {
		return fmt.Errorf("keepcaps remains enabled: %w", unix.EPERM)
	}
	return nil
}
