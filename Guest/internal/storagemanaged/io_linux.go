//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	w "dev.cengine/guest/internal/storagewire"
	"unsafe"
)

// The serialized client's buffer alignment is not retained by JSON decoding.
// ext4 O_DIRECT needs a suitably aligned service buffer, while the kernel still
// checks the actual request's length and offset. Page alignment covers ext4's
// supported sector and filesystem block alignments on amd64/arm64.
func ioBuffer(size int, flags uint32) []byte {
	if size == 0 || flags&w.OpenDirect == 0 {
		return make([]byte, size)
	}
	const alignment = 65536
	raw := make([]byte, size+alignment-1)
	start := int((-uintptr(unsafe.Pointer(&raw[0]))) & (alignment - 1))
	return raw[start : start+size]
}
