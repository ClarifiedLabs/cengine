//go:build linux && (arm64 || amd64)

package storageclient

import (
	"runtime"
	"syscall"
	"unsafe"
)

// _IOWR(229, 240, struct fuse_request_cred), generic Linux ABI (arm64).
const requestCredentialIOCTL = 0xc040e5f0

func nativeCredentialQuery(fd int, h *credentialHeader, groups []uint32) error {
	if len(groups) != 0 {
		h.Groups = uint64(uintptr(unsafe.Pointer(&groups[0])))
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), requestCredentialIOCTL, uintptr(unsafe.Pointer(h)))
	runtime.KeepAlive(groups)
	runtime.KeepAlive(h)
	if errno != 0 {
		return errno
	}
	return nil
}
