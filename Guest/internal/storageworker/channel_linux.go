//go:build linux

// Package storageworker owns a single same-executable worker and its private
// credential-authenticated transport. It does not grant storage authority.
package storageworker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const MaxPayload = 65536

var (
	ErrProtocol = errors.New("storageworker: invalid private packet")
	ErrUnreaped = errors.New("storageworker: child has not been reaped")
)

// Channel carries nonempty packets, each at most MaxPayload bytes. One reader
// and one writer may run concurrently. Close interrupts blocked I/O. Deadlines,
// EOF and transport closure say nothing about whether a process was reaped.
// It must not be copied. There is deliberately no descriptor-passing API.
type Channel struct {
	file      *os.File
	raw       syscall.RawConn
	peer      int32
	sendMu    sync.Mutex
	recvMu    sync.Mutex
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

// newChannel consumes f, including on failure. SO_PASSCRED must already be set:
// enabling it here would allow unauthenticated traffic to precede validation.
func newChannel(f *os.File, peer int) (*Channel, error) {
	fail := func(err error) (*Channel, error) { _ = f.Close(); return nil, err }
	fd := int(f.Fd())
	unix.CloseOnExec(fd)
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typ != unix.SOCK_SEQPACKET {
		return fail(fmt.Errorf("%w: not seqpacket", ErrProtocol))
	}
	sa, err := unix.Getsockname(fd)
	if _, ok := sa.(*unix.SockaddrUnix); err != nil || !ok {
		return fail(fmt.Errorf("%w: not Unix", ErrProtocol))
	}
	if _, err := unix.Getpeername(fd); err != nil {
		return fail(fmt.Errorf("%w: not connected", ErrProtocol))
	}
	pass, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED)
	if err != nil || pass != 1 {
		return fail(fmt.Errorf("%w: missing SO_PASSCRED", ErrProtocol))
	}
	// Re-wrap after setting nonblocking so os.NewFile registers with netpoll.
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 5)
	if err != nil {
		return fail(err)
	}
	_ = f.Close()
	if err := unix.SetNonblock(dup, true); err != nil {
		_ = unix.Close(dup)
		return nil, err
	}
	f = os.NewFile(uintptr(dup), "storageworker-channel")
	raw, err := f.SyscallConn()
	if err != nil {
		return fail(err)
	}
	return &Channel{file: f, raw: raw, peer: int32(peer)}, nil
}

func (c *Channel) SetDeadline(t time.Time) error { return c.file.SetDeadline(t) }

func (c *Channel) Send(payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxPayload {
		return ErrProtocol
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.closed.Load() {
		return os.ErrClosed
	}
	var callErr error
	var n int
	err := c.raw.Write(func(fd uintptr) bool {
		for {
			n, callErr = unix.SendmsgN(int(fd), payload, nil, nil, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT)
			if callErr != unix.EINTR {
				break
			}
		}
		return callErr != unix.EAGAIN && callErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return err
	}
	if callErr != nil {
		return callErr
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func (c *Channel) Receive() ([]byte, error) { return c.receive(nil) }

// wouldBlock is a private test-only observation of an actual EAGAIN recvmsg.
func (c *Channel) receive(wouldBlock chan<- struct{}) ([]byte, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if c.closed.Load() {
		return nil, os.ErrClosed
	}
	payload := make([]byte, MaxPayload)
	// Linux permits at most 253 rights per sendmsg. Even rejected/truncated
	// packets must dispose of every descriptor actually installed by recvmsg.
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(253*4))
	var n, oobn, flags int
	var callErr error
	err := c.raw.Read(func(fd uintptr) bool {
		for {
			n, oobn, flags, _, callErr = unix.Recvmsg(int(fd), payload, oob, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
			if wouldBlock != nil && (callErr == unix.EAGAIN || callErr == unix.EWOULDBLOCK) {
				select {
				case wouldBlock <- struct{}{}:
				default:
				}
			}
			if callErr != unix.EINTR {
				break
			}
		}
		return callErr != unix.EAGAIN && callErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return nil, err
	}
	if callErr != nil {
		return nil, callErr
	}
	credErr := validateControl(oob[:oobn], c.peer)
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return nil, ErrProtocol
	}
	if n == 0 && oobn == 0 {
		return nil, io.EOF
	}
	if credErr != nil {
		return nil, credErr
	}
	if n == 0 {
		return nil, ErrProtocol
	}
	if c.closed.Load() {
		return nil, os.ErrClosed
	}
	return payload[:n], nil
}

// validateControl deliberately processes all cmsgs even after rejection, so a
// credential mismatch cannot hide SCM_RIGHTS needing cleanup. Kernel-generated
// control buffers are structurally valid; malformed buffers also fail closed.
func validateControl(oob []byte, peer int32) error {
	creds := 0
	bad := false
	for len(oob) > 0 {
		if len(oob) < unix.CmsgLen(0) {
			return ErrProtocol
		}
		h, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return ErrProtocol
		}
		m := unix.SocketControlMessage{Header: h, Data: data}
		switch {
		case h.Level == unix.SOL_SOCKET && h.Type == unix.SCM_RIGHTS:
			bad = true
			// ParseUnixRights assumes a multiple of four; kernel cmsgs satisfy
			// that, but reject malformed synthetic control buffers safely too.
			m.Data = data[:len(data)/4*4]
			fds, _ := unix.ParseUnixRights(&m)
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		case h.Level == unix.SOL_SOCKET && h.Type == unix.SCM_CREDENTIALS:
			creds++
			if len(data) != unix.SizeofUcred {
				bad = true
				oob = rest
				continue
			}
			cred, err := unix.ParseUnixCredentials(&m)
			if err != nil || cred.Pid != peer || cred.Uid != 0 || cred.Gid != 0 {
				bad = true
			}
		default:
			bad = true
		}
		oob = rest
	}
	if bad || creds != 1 {
		return ErrProtocol
	}
	return nil
}

func (c *Channel) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = c.file.Close()
		// Join complete credential checks, not just the recvmsg syscall. The
		// owner may reap (and thus permit PID reuse) only after this fence.
		c.sendMu.Lock()
		c.sendMu.Unlock()
		c.recvMu.Lock()
		c.recvMu.Unlock()
	})
	return c.closeErr
}
