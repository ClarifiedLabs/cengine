//go:build linux

package vsock

import (
	"errors"
	"io"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLocalCIDUsesVsockCharacterDevice(t *testing.T) {
	closed := false
	cid, err := localCID(
		func(path string, flags int, permissions uint32) (int, error) {
			if path != "/dev/vsock" {
				t.Fatalf("opened %q instead of /dev/vsock", path)
			}
			if flags != unix.O_RDONLY|unix.O_CLOEXEC || permissions != 0 {
				t.Fatalf("unexpected open arguments flags=%d permissions=%d", flags, permissions)
			}
			return 42, nil
		},
		func(fd int) error {
			if fd != 42 {
				return errors.New("closed the wrong descriptor")
			}
			closed = true
			return nil
		},
		func(fd int, request uint) (uint32, error) {
			if fd != 42 || request != unix.IOCTL_VM_SOCKETS_GET_LOCAL_CID {
				t.Fatalf("unexpected ioctl fd=%d request=%d", fd, request)
			}
			return 7, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cid != 7 || !closed {
		t.Fatalf("unexpected CID/close state: cid=%d closed=%t", cid, closed)
	}
}

func TestRawConnectionCarriesStreamDataWithoutNetFileConversion(t *testing.T) {
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	left := newConn(descriptors[0], Addr{CID: 3, Port: 100}, Addr{CID: 2, Port: 200})
	right := newConn(descriptors[1], Addr{CID: 2, Port: 200}, Addr{CID: 3, Port: 100})
	defer left.Close()
	defer right.Close()

	written := make(chan error, 1)
	go func() {
		_, err := left.Write([]byte("cengine-vsock"))
		written <- err
	}()
	data := make([]byte, len("cengine-vsock"))
	if _, err := io.ReadFull(right, data); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if string(data) != "cengine-vsock" {
		t.Fatalf("unexpected payload %q", data)
	}
	if left.LocalAddr().Network() != "vsock" || left.RemoteAddr().String() != "2:200" {
		t.Fatalf("unexpected addresses %s -> %s", left.LocalAddr(), left.RemoteAddr())
	}
}
