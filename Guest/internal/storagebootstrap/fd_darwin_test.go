//go:build darwin

package storagebootstrap

import (
	"encoding/binary"
	"net"
	"os"
	"syscall"
	"testing"
)

func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	check(t, err)
	result := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "test-socket")
		c, e := net.FileConn(f)
		f.Close()
		check(t, e)
		result[i] = c.(*net.UnixConn)
		t.Cleanup(func() { c.Close() })
	}
	return result[0], result[1]
}
func TestCredentialStreamRejectsAndConsumesUnsuitableFD(t *testing.T) {
	file, err := os.Open(os.DevNull)
	check(t, err)
	defer file.Close()
	duplicate, err := syscall.Dup(int(file.Fd()))
	check(t, err)
	if conn, err := consumeConnectedStream(duplicate); err == nil || conn != nil {
		t.Fatal("regular file accepted")
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(duplicate), syscall.F_GETFD, 0); errno != syscall.EBADF {
		t.Fatal("rejected descriptor leaked")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("borrowed descriptor closed")
	}
	unconnected, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	check(t, err)
	if conn, err := consumeConnectedStream(unconnected); err == nil || conn != nil {
		t.Fatal("unconnected socket accepted")
	}
}
func TestPrivateFrameDescriptorOwnership(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			left, right := unixPair(t)
			file, err := os.Open(os.DevNull)
			check(t, err)
			defer file.Close()
			var h [4]byte
			binary.BigEndian.PutUint32(h[:], 2)
			fds := make([]int, count)
			for i := range fds {
				fds[i] = int(file.Fd())
			}
			var control []byte
			if count > 0 {
				control = syscall.UnixRights(fds...)
			}
			_, _, err = left.WriteMsgUnix(h[:], control, nil)
			check(t, err)
			_, err = left.Write([]byte("{}"))
			check(t, err)
			payload, fd, err := readPrivateFrame(right)
			if count == 2 {
				if err == nil || fd != -1 {
					t.Fatal("extra rights accepted")
				}
				return
			}
			check(t, err)
			if string(payload) != "{}" {
				t.Fatal("payload")
			}
			if count == 0 && fd != -1 || count == 1 && fd < 0 {
				t.Fatal("descriptor count")
			}
			if fd >= 0 {
				defer syscall.Close(fd)
				flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
				if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
					t.Fatal("not CLOEXEC")
				}
			}
		})
	}
}

// Both lifecycle stream operations use the same closed marker and exactly one
// inherited right. No stream-bearing generic command or missing right is legal.
func TestLifecycleWorkloadDescriptorMarkers(t *testing.T) {
	for _, operation := range []string{"connect-boot", "stage-service-rebind", "attachment-certificate", "connect-workload", "workload-command", "proof"} {
		for _, count := range []int{0, 1, 2} {
			left, right := unixPair(t)
			file, err := os.Open(os.DevNull)
			check(t, err)
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], 2)
			fds := make([]int, count)
			for i := range fds {
				fds[i] = int(file.Fd())
			}
			var ancillary []byte
			if count > 0 {
				ancillary = syscall.UnixRights(fds...)
			}
			_, _, err = left.WriteMsgUnix(header[:], ancillary, nil)
			check(t, err)
			_, err = left.Write([]byte("{}"))
			check(t, err)
			_, fd, err := readPrivateFrameLimit(right, lifecycleWorkloadRequestLimit)
			file.Close()
			valid := err == nil && (fd >= 0) == lifecycleStreamOperation(operation)
			expected := count == 1 && lifecycleStreamOperation(operation) || count == 0 && !lifecycleStreamOperation(operation)
			if valid != expected {
				t.Fatalf("%s rights=%d: admitted=%v", operation, count, valid)
			}
			if fd >= 0 {
				// Neither operation can install a regular file as its TLS stream.
				if stream, err := consumeConnectedStream(fd); err == nil || stream != nil {
					t.Fatal("regular file installed")
				}
			}
		}
	}
}
