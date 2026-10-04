//go:build darwin

package storagebootstrap

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"syscall"
)

// Every frame begins with one four-byte sendmsg header. At most one descriptor
// is accepted, only by lifecycleStreamOperation. Close every right on rejection.
// consumeConnectedStream takes ownership even when the descriptor is unsuitable.
func consumeConnectedStream(fd int) (net.Conn, error) {
	if fd < 0 {
		return nil, ErrProtocol
	}
	file := os.NewFile(uintptr(fd), "private-attachment-credential")
	defer file.Close()
	kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil || kind != syscall.SOCK_STREAM {
		return nil, ErrProtocol
	}
	if _, err = syscall.Getpeername(fd); err != nil {
		return nil, ErrProtocol
	}
	syscall.CloseOnExec(fd)
	return net.FileConn(file)
}

func readPrivateFrame(c *net.UnixConn) (payload []byte, descriptor int, err error) {
	return readPrivateFrameLimit(c, MaximumPayload)
}
func readPrivateFrameLimit(c *net.UnixConn, limit uint32) (payload []byte, descriptor int, err error) {
	descriptor = -1
	var header [4]byte
	ancillary := make([]byte, syscall.CmsgSpace(4*4))
	n, oob, flags, _, err := c.ReadMsgUnix(header[:], ancillary)
	var rights []int
	if oob > 0 {
		messages, e := syscall.ParseSocketControlMessage(ancillary[:oob])
		if e != nil {
			err = ErrProtocol
		}
		for _, message := range messages {
			fds, e := syscall.ParseUnixRights(&message)
			if e != nil {
				err = ErrProtocol
			} else {
				rights = append(rights, fds...)
			}
		}
	}
	defer func() {
		if err != nil {
			for _, fd := range rights {
				syscall.Close(fd)
			}
			descriptor = -1
		}
	}()
	if err != nil {
		return nil, -1, err
	}
	if n != 4 || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 || len(rights) > 1 {
		return nil, -1, ErrProtocol
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > limit {
		return nil, -1, ErrProtocol
	}
	if len(rights) == 1 {
		descriptor = rights[0]
		syscall.CloseOnExec(descriptor)
	}
	payload = make([]byte, length)
	_, err = io.ReadFull(c, payload)
	return payload, descriptor, err
}
