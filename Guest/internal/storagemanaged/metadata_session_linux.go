//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Mint before entering any identity worker. The patched kernel checks CURRENT
// init-userns CAP_SYS_ADMIN and returns a CLOEXEC anonymous capability. There is
// no mount, live source request, saved-root identity, or old-ABI fallback here.
func platformMetadataSession() (*os.File, error) {
	device, err := os.OpenFile("/dev/fuse", os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fd, _, errno := unix.RawSyscall(unix.SYS_IOCTL, device.Fd(), storageSessionIOCTL, 0)
	closeErr := device.Close()
	if errno != 0 {
		return nil, errors.Join(errno, closeErr)
	}
	session := os.NewFile(fd, "storage-metadata-session")
	if closeErr != nil {
		return nil, errors.Join(closeErr, session.Close())
	}
	return session, nil
}

// Only called inside Worker.Do under session/namespace locks. RawSyscall keeps
// the actual ioctl on that locked, fully installed identity thread. No retry:
// notify_change can have applied implicit killpriv before reporting an error.
func platformApplyMetadata(sessionFD int, attr *storageAttr) error {
	_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(sessionFD), storageApplyAttrIOCTL, uintptr(unsafe.Pointer(attr)))
	runtime.KeepAlive(attr)
	if errno != 0 {
		return errno
	}
	return nil
}
