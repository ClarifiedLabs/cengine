//go:build linux

package vsock

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	left, right := socketPair(t)

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

func socketPair(t *testing.T) (*conn, *conn) {
	t.Helper()
	// Start with blocking descriptors, just like a completed blocking Dial.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	left, err := newConn(fds[0], Addr{CID: 3, Port: 100}, Addr{CID: 2, Port: 200})
	if err != nil {
		_ = unix.Close(fds[1])
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close() })
	right, err := newConn(fds[1], Addr{CID: 2, Port: 200}, Addr{CID: 3, Port: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = right.Close() })
	return left.(*conn), right.(*conn)
}

func controlSocket(t *testing.T, value *conn, operation func(int) error) {
	t.Helper()
	raw, err := value.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var operationErr error
	if err := raw.Control(func(fd uintptr) { operationErr = operation(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if operationErr != nil {
		t.Fatal(operationErr)
	}
}

func requireNonblocking(t *testing.T, value *conn) {
	t.Helper()
	var flags int
	controlSocket(t, value, func(fd int) (err error) {
		flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		return err
	})
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatal("socket reverted to blocking mode")
	}
}

func waitOperation(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("socket operation did not unblock")
		return nil
	}
}

func requireBlocked(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("operation unexpectedly completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestConnectionWritesStorageFrameWithDeadline(t *testing.T) {
	left, right := socketPair(t)
	requireNonblocking(t, left)
	if err := left.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := right.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Match storage session.write's length-prefixed JSON and separate writes.
	payload := []byte(`{"version":2,"type":"response","reply":{"id":1}}`)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := left.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := left.Write(payload); err != nil {
		t.Fatal(err)
	}
	var receivedHeader [4]byte
	if _, err := io.ReadFull(right, receivedHeader[:]); err != nil {
		t.Fatal(err)
	}
	if receivedHeader != header {
		t.Fatalf("frame header = %v, want %v", receivedHeader, header)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(right, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("frame payload = %q, want %q", received, payload)
	}
}

func TestConnectionReadDeadlineAndReset(t *testing.T) {
	left, right := socketPair(t)
	if err := left.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := left.Read(make([]byte, 1)); done <- err }()
	if err := waitOperation(t, done); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read error = %v, want deadline exceeded", err)
	}
	if err := left.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := left.Read(make([]byte, 1)); done <- err }()
	requireBlocked(t, done)
	if _, err := right.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := waitOperation(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionStalledWriteDeadline(t *testing.T) {
	left, _ := socketPair(t)
	testStalledWriteDeadline(t, left)
}

func testStalledWriteDeadline(t *testing.T, value *conn) {
	t.Helper()
	controlSocket(t, value, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096)
	})
	if err := value.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := value.Write(make([]byte, 1<<20)); done <- err }()
	if err := waitOperation(t, done); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write error = %v, want deadline exceeded", err)
	}
}

func TestConnectionCloseReadPreservesWriteDeadline(t *testing.T) {
	left, _ := socketPair(t)
	done := make(chan error, 1)
	go func() { _, err := left.Read(make([]byte, 1)); done <- err }()
	requireBlocked(t, done)
	if err := left.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if err := waitOperation(t, done); !errors.Is(err, io.EOF) {
		t.Fatalf("read after CloseRead = %v, want EOF", err)
	}
	requireNonblocking(t, left)
	testStalledWriteDeadline(t, left)
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if err := left.CloseRead(); err == nil {
		t.Fatal("CloseRead on closed connection succeeded")
	}
}

func TestConnectionCancellationCloseInterruptsIO(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			left, _ := socketPair(t)
			controlSocket(t, left, func(fd int) error {
				return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096)
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			closed := make(chan error, 1)
			stop := context.AfterFunc(ctx, func() { closed <- left.Close() })
			defer stop()
			done := make(chan error, 1)
			go func() {
				var err error
				if operation == "read" {
					_, err = left.Read(make([]byte, 1))
				} else {
					_, err = left.Write(make([]byte, 1<<20))
				}
				done <- err
			}()
			requireBlocked(t, done)
			cancel()
			if err := waitOperation(t, closed); err != nil {
				t.Fatal(err)
			}
			if err := waitOperation(t, done); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("%s after cancellation = %v, want closed", operation, err)
			}
		})
	}
}

func TestNewConnectionClosesDescriptorOnSetupFailure(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags int
		want  error
	}{
		{"nonblocking setup", unix.O_PATH, unix.EBADF},
		{"poller setup", unix.O_RDONLY, os.ErrNoDeadline},
	} {
		t.Run(test.name, func(t *testing.T) {
			fd, err := unix.Open(t.TempDir(), test.flags|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			value, err := newConn(fd, Addr{}, Addr{})
			if value != nil {
				_ = value.Close()
				t.Fatal("setup unexpectedly returned a connection")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("setup error = %v, want %v", err, test.want)
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				_ = unix.Close(fd)
				t.Fatalf("descriptor was not closed: %v", err)
			}
		})
	}
	if value, err := newConn(-1, Addr{}, Addr{}); value != nil || !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid descriptor: connection=%v error=%v", value, err)
	}
}

func TestListenerAcceptAndClose(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "socket")
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	file, err := newSocketFile(fd, "test-vsock-listener")
	if err != nil {
		t.Fatal(err)
	}
	value := &listener{file: file, address: Addr{CID: 3, Port: 100}}
	t.Cleanup(func() { _ = value.Close() })
	done := make(chan error, 1)
	go func() {
		accepted, err := value.Accept()
		if err == nil {
			err = accepted.SetDeadline(time.Now().Add(time.Second))
			_ = accepted.Close()
		}
		done <- err
	}()
	requireBlocked(t, done)
	peer, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := waitOperation(t, done); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := value.Accept(); done <- err }()
	requireBlocked(t, done)
	if err := value.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitOperation(t, done); err == nil {
		t.Fatal("blocked Accept succeeded after Close")
	}
	if _, err := value.Accept(); err == nil {
		t.Fatal("Accept on closed listener succeeded")
	}
}
