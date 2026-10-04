package storagebootstrap

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"

	c "dev.cengine/guest/internal/storagecontrol"
)

// Diagnostic only: never a receipt, authority result, or permission to retry.
// Do not include err.Error(), request bodies, certificates, paths or key material.
func lifecycleTerminalFailureCode(err error) string {
	var remote *c.RemoteError
	if errors.As(err, &remote) {
		switch remote.Code {
		case c.Invalid, c.Unauthorized, c.Conflict, c.Unknown, c.Blocked, c.Limit,
			c.Busy, c.Closed, c.Timeout, c.RepairRequired, c.Internal:
			return "fatal-remote-" + string(remote.Code)
		default:
			return "fatal-internal"
		}
	}
	var record tls.RecordHeaderError
	var verification *tls.CertificateVerificationError
	var transport *net.OpError
	switch {
	case errors.Is(err, errLifecycleSession):
		return "fatal-session"
	case errors.Is(err, context.Canceled):
		return "fatal-canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "fatal-timeout"
	case errors.Is(err, ErrProtocol), errors.Is(err, c.ErrProtocol):
		return "fatal-protocol"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "fatal-truncated"
	case errors.Is(err, io.EOF):
		return "fatal-eof"
	case errors.As(err, &record), errors.As(err, &verification):
		return "fatal-tls"
	case errors.As(err, &transport):
		if transport.Timeout() {
			return "fatal-timeout"
		}
		return "fatal-transport"
	case errors.Is(err, net.ErrClosed), errors.Is(err, c.ErrClosed):
		return "fatal-transport"
	default:
		return "fatal-internal"
	}
}

type lifecyclePrivateErrorReply struct {
	Error     string `json:"error"`
	RequestID uint64 `json:"request_id"`
	Version   string `json:"version"`
}

func lifecycleTerminalReply(request lifecyclePrivateRequest, err error) (any, error) {
	return lifecyclePrivateErrorReply{lifecycleTerminalFailureCode(err), request.RequestID, request.Version}, err
}
