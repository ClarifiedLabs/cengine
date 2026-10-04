package storagebootstrap

import (
	"context"
	c "dev.cengine/guest/internal/storagecontrol"
	"errors"
	"io"
	"net"
	"syscall"
)

// Deliberately closed transport classification: malformed/truncated framing,
// TLS identity failures and arbitrary net.Error wrappers are not availability.
func ordinaryServiceLoss(err error) bool {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	for _, loss := range []error{io.EOF, io.ErrClosedPipe, net.ErrClosed, c.ErrClosed, context.Canceled, context.DeadlineExceeded, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.ENOTCONN, syscall.ETIMEDOUT} {
		if errors.Is(err, loss) {
			return true
		}
	}
	var timeout *net.OpError
	return errors.As(err, &timeout) && timeout.Timeout()
}
