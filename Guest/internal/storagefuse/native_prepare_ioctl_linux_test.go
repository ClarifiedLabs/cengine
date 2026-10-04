//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// nativePrepareControl issues the real descriptor-rooted PREPARE ioctl on an
// opened mount root. It exercises the same process gate as the mounted DATA
// path instead of injecting a client request.
func nativePrepareControl(t *testing.T, root string, action w.PrepareAction, intent a.ID) w.PrepareReply {
	t.Helper()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open native PREPARE mount root: %v", err)
	}
	defer unix.Close(fd)
	buffer, err := w.EncodePrepareIoctl(w.PrepareRequest{Action: action, Intent: intent})
	if err != nil {
		t.Fatalf("encode native PREPARE request: %v", err)
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(w.PrepareIoctl), uintptr(unsafe.Pointer(&buffer[0])))
	runtime.KeepAlive(buffer)
	if errno != 0 {
		t.Fatalf("native PREPARE ioctl action=%d: %v", action, errno)
	}
	reply, err := w.DecodePrepareIoctlReply(buffer)
	if err != nil {
		t.Fatalf("decode native PREPARE reply action=%d: %v", action, err)
	}
	return reply
}

// nativeCopyDeviceID returns the canonical FS_IOC_GETFSUUID identity required by
// the real authority copy root. Synthetic test names are not valid PREPARE roots.
func nativeCopyDeviceID(t *testing.T, path string) string {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open native PREPARE device root: %v", err)
	}
	defer unix.Close(fd)
	var value [17]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x80111500), uintptr(unsafe.Pointer(&value[0])))
	if errno != 0 {
		t.Fatalf("read native PREPARE FS UUID: %v", errno)
	}
	if value[0] != 16 {
		t.Fatalf("unsupported native PREPARE FS UUID length: %d", value[0])
	}
	b := value[1:]
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// nativeBeginNoopPrepare starts the fenced no-op PREPARE lifecycle for tests
// that exercise ordinary metadata after lawful admission. Finish is mandatory
// even without a transaction: retirement is never completion.
func nativeBeginNoopPrepare(t *testing.T, root string) func() error {
	t.Helper()
	reply := nativePrepareControl(t, root, w.BeginCopy, "")
	if reply.Pending != 0 || reply.Intent.Phase != a.CopyBegun || reply.Intent.ID == "" {
		t.Fatalf("invalid native PREPARE begin: %+v", reply)
	}
	intent := reply.Intent.ID
	return func() error {
		finish := nativePrepareControl(t, root, w.FinishCopy, intent)
		if finish.Pending != 0 || finish.Intent.Phase != a.CopyCompleted {
			return errors.New("native PREPARE finish was not persisted")
		}
		return nil
	}
}
