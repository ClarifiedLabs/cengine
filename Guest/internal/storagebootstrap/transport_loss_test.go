package storagebootstrap

import (
	"context"
	c "dev.cengine/guest/internal/storagecontrol"
	"errors"
	"io"
	"net"
	"testing"
)

func TestOrdinaryServiceLossRejectsCorruption(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrClosedPipe, net.ErrClosed, context.DeadlineExceeded} {
		if !ordinaryServiceLoss(err) {
			t.Fatal(err)
		}
	}
	for _, err := range []error{io.ErrUnexpectedEOF, ErrProtocol, c.ErrProtocol, &net.OpError{Op: "read", Err: io.ErrUnexpectedEOF}, errors.New("tls: bad certificate")} {
		if ordinaryServiceLoss(err) {
			t.Fatal("corruption classified as availability", err)
		}
	}
}
