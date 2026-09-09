//go:build linux

package storage

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

	nfs "github.com/willscott/go-nfs"
	"golang.org/x/sys/unix"
)

// WithIdentity uses a disposable OS thread, never process-wide set*id wrappers.
// LockOSThread arranges Go's clean template thread before credentials change.
// Per runtime.LockOSThread's contract, exiting without UnlockOSThread terminates
// the thread. Even setup failures cannot return a credentialed thread to Go's
// scheduler. There is deliberately no fallible credential restoration path.
// The callback must stay synchronous: Go-created goroutines do not inherit this
// identity. All NFS handlers and filesystem operations obey that restriction.
func (handler *volumeNFSHandler) WithIdentity(ctx context.Context, id nfs.Identity, call func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case handler.identitySlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-handler.identitySlots }()
	groups := append([]uint32(nil), id.Groups...)
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // NEVER unlock this disposable thread.
		var resultErr error
		defer func() {
			if recover() != nil {
				// Do not expose panic values (which may contain request data).
				resultErr = fmt.Errorf("NFS identity callback panicked")
			}
			result <- resultErr
		}()
		if err := installNFSIdentity(id.UID, id.GID, groups); err != nil {
			resultErr = fmt.Errorf("install NFS identity: %w", err)
			return
		}
		resultErr = call()
	}()
	// Do not return on cancellation before the callback finishes using the RPC.
	return <-result
}

func installNFSIdentity(uid, gid uint32, groups []uint32) error {
	if uid == ^uint32(0) || gid == ^uint32(0) || len(groups) > 16 {
		return unix.EINVAL
	}
	for _, group := range groups {
		if group == ^uint32(0) {
			return unix.EINVAL
		}
	}
	var pointer uintptr
	if len(groups) != 0 {
		pointer = uintptr(unsafe.Pointer(&groups[0]))
	}
	_, _, errno := unix.RawSyscall(unix.SYS_SETGROUPS, uintptr(len(groups)), pointer, 0)
	runtime.KeepAlive(groups)
	if errno != 0 {
		return errno
	}
	if _, _, errno = unix.RawSyscall(unix.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); errno != 0 {
		return errno
	}
	if _, _, errno = unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); errno != 0 {
		return errno
	}
	if uid != 0 {
		// Explicitly clear effective, permitted and inheritable capabilities even
		// when the service was launched with KEEP_CAPS or unusual securebits.
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		data := [2]unix.CapUserData{}
		if _, _, errno = unix.RawSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
			return errno
		}
	}
	return nil
}
