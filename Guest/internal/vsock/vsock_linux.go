//go:build linux

package vsock

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type Addr struct {
	CID  uint32
	Port uint32
}

func (address Addr) Network() string { return "vsock" }
func (address Addr) String() string  { return fmt.Sprintf("%d:%d", address.CID, address.Port) }

type listener struct {
	file    *os.File
	address Addr
}

func LocalCID() (uint32, error) {
	return localCID(unix.Open, unix.Close, unix.IoctlGetUint32)
}

func localCID(
	openDevice func(string, int, uint32) (int, error),
	closeDevice func(int) error,
	ioctl func(int, uint) (uint32, error),
) (uint32, error) {
	fd, err := openDevice("/dev/vsock", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer closeDevice(fd)
	return ioctl(fd, unix.IOCTL_VM_SOCKETS_GET_LOCAL_CID)
}

func Listen(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Listen(fd, 128); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &listener{
		file:    os.NewFile(uintptr(fd), "cengine-vsock-listener"),
		address: Addr{CID: unix.VMADDR_CID_ANY, Port: port},
	}, nil
}

func (value *listener) Accept() (net.Conn, error) {
	for {
		fd, remote, err := unix.Accept4(int(value.file.Fd()), unix.SOCK_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		return newConn(fd, value.address, addressFromSockaddr(remote)), nil
	}
}

func (value *listener) Close() error   { return value.file.Close() }
func (value *listener) Addr() net.Addr { return value.address }

func Dial(port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	remote := Addr{CID: unix.VMADDR_CID_HOST, Port: port}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: remote.CID, Port: remote.Port}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return newConn(fd, Addr{CID: unix.VMADDR_CID_ANY}, remote), nil
}

type conn struct {
	file   *os.File
	local  Addr
	remote Addr
}

func newConn(fd int, local, remote Addr) net.Conn {
	return &conn{
		file:   os.NewFile(uintptr(fd), "cengine-vsock-connection"),
		local:  local,
		remote: remote,
	}
}

func (value *conn) Read(data []byte) (int, error)        { return value.file.Read(data) }
func (value *conn) Write(data []byte) (int, error)       { return value.file.Write(data) }
func (value *conn) Close() error                         { return value.file.Close() }
func (value *conn) LocalAddr() net.Addr                  { return value.local }
func (value *conn) RemoteAddr() net.Addr                 { return value.remote }
func (value *conn) SetDeadline(deadline time.Time) error { return value.file.SetDeadline(deadline) }
func (value *conn) SetReadDeadline(deadline time.Time) error {
	return value.file.SetReadDeadline(deadline)
}
func (value *conn) SetWriteDeadline(deadline time.Time) error {
	return value.file.SetWriteDeadline(deadline)
}

func addressFromSockaddr(value unix.Sockaddr) Addr {
	if address, ok := value.(*unix.SockaddrVM); ok {
		return Addr{CID: address.CID, Port: address.Port}
	}
	return Addr{}
}
