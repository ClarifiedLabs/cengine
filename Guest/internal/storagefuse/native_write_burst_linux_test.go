//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Real Mount, authority, DATA server, credentials and ext4; never a substitute
// for replaying the unchanged fsx seed-1/1000 corpus in the managed runtime.
func TestNativeMountedManagedV3WriteBurstGraceful(t *testing.T) {
	nativeMountedManagedV3(t, "write-burst")
}

func nativeWriteBurst(t *testing.T, root, backing string) {
	t.Helper()
	path := filepath.Join(root, "write-burst")
	nativePhase("open", 0, false)
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	nativePhase("open", 0, true)
	nativeMust(t, err)
	defer func() {
		if fd >= 0 {
			nativePhase("defer-close", 0, false)
			_ = unix.Close(fd)
			nativePhase("defer-close", 0, true)
		}
	}()
	model := make([]byte, 4096)
	nativePhase("size", 0, false)
	err = unix.Ftruncate(fd, int64(len(model)))
	nativePhase("size", 0, true)
	nativeMust(t, err)
	for i := 0; i < 1000; i++ {
		offset := (i * 37) % len(model)
		value := []byte{byte(i)}
		nativePhase("write", i, false)
		n, err := unix.Pwrite(fd, value, int64(offset))
		nativePhase("write", i, true)
		nativeMust(t, err)
		if n != len(value) {
			t.Fatal("short write", i, n)
		}
		model[offset] = value[0]
		if i%10 == 0 {
			nativePhase("shrink", i, false)
			err = unix.Ftruncate(fd, int64(len(model)-1))
			nativePhase("shrink", i, true)
			nativeMust(t, err)
			nativePhase("grow", i, false)
			err = unix.Ftruncate(fd, int64(len(model)))
			nativePhase("grow", i, true)
			nativeMust(t, err)
			model[len(model)-1] = 0
		}
	}
	nativePhase("sync", 0, false)
	err = unix.Fsync(fd)
	nativePhase("sync", 0, true)
	nativeMust(t, err)
	nativePhase("close", 0, false)
	err = unix.Close(fd)
	nativePhase("close", 0, true)
	nativeMust(t, err)
	fd = -1
	for index, name := range []string{path, filepath.Join(backing, "write-burst")} {
		nativePhase("readback", index, false)
		err := nativeReadback(name, model)
		nativePhase("readback", index, true)
		nativeMust(t, err)
	}
	// The shared native fixture requires graceful local close, real authority
	// retirement/barrier receipt and exact mount/descriptor cleanup afterward.
}
