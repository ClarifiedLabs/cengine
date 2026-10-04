//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
	"runtime"
	"unsafe"
)

// Wire bits use Linux generic numbers; arm64 O_DIRECT/O_DIRECTORY/O_NOFOLLOW
// differ. APPEND is deliberately not put on the open description: all FUSE writes
// are offset-addressed, and Linux pwrite otherwise ignores their supplied offset.
func openFlags(flags uint32) int {
	result := int(flags&w.OpenAccessMask) | unix.O_CLOEXEC | unix.O_NONBLOCK
	for _, p := range []struct {
		wire uint32
		host int
	}{
		{w.OpenCreate, unix.O_CREAT}, {w.OpenExclusive, unix.O_EXCL}, {w.OpenNoCTTY, unix.O_NOCTTY},
		{w.OpenTruncate, unix.O_TRUNC}, {w.OpenDSync, unix.O_DSYNC}, {w.OpenAsync, unix.O_ASYNC},
		{w.OpenDirect, unix.O_DIRECT}, {w.OpenLargeFile, unix.O_LARGEFILE}, {w.OpenDirectory, unix.O_DIRECTORY},
		{w.OpenNoFollow, unix.O_NOFOLLOW}, {w.OpenNoATime, unix.O_NOATIME},
	} {
		if flags&p.wire != 0 {
			result |= p.host
		}
	}
	if flags&w.OpenSync == w.OpenSync {
		result |= unix.O_SYNC
	}
	return result
}

// FD-grant I/O needs no caller identity. A disposable thread with ZERO effective
// capabilities ensures data writes cannot borrow service/opener CAP_FSETID. No
// pathname, metadata mutation or arbitrary callback is exposed through this scope.
func grantIO(call func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlock; retire the capability-modified thread
		err := error(unix.EIO)
		defer func() {
			if recover() != nil {
				err = unix.EIO
			}
			done <- err
		}()
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		_, _, e := unix.RawSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
		if e != 0 {
			err = e
			return
		}
		err = call()
	}()
	return <-done
}
