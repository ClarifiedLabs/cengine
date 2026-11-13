package storageserver

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

type handshakePhase uint8

const (
	handshakeDeadline handshakePhase = iota
	handshakeTLS
	handshakeTLSState
	handshakeServerHelloWrite
	handshakeClientHelloRead
	handshakePeerPolicy
	handshakeAuthenticate
	handshakeBinding
	handshakeAdmission
	handshakeRootFactory
	handshakeRootReplyQueue
	handshakeRootReplyWrite
)

func (p handshakePhase) diagnostic() string {
	switch p {
	case handshakeDeadline:
		return "deadline"
	case handshakeTLS:
		return "tls"
	case handshakeTLSState:
		return "tls-state"
	case handshakeServerHelloWrite:
		return "server-hello-write"
	case handshakeClientHelloRead:
		return "client-hello-read"
	case handshakePeerPolicy:
		return "peer-policy"
	case handshakeAuthenticate:
		return "authenticate"
	case handshakeBinding:
		return "binding"
	case handshakeAdmission:
		return "admission"
	case handshakeRootFactory:
		return "root-factory"
	case handshakeRootReplyQueue:
		return "root-reply-queue"
	case handshakeRootReplyWrite:
		return "root-reply-write"
	default:
		return "unknown"
	}
}

// Constructed once at the failure boundary; neither phase nor cause is mutated.
// Error deliberately does not expose even the underlying error's type or text.
type handshakeFailure struct {
	phase handshakePhase
	cause error
}

func (*handshakeFailure) Error() string   { return "storageserver: DATA handshake failed" }
func (e *handshakeFailure) Unwrap() error { return e.cause }

func wrapHandshakeFailure(phase handshakePhase, err error) error {
	if err == nil {
		return nil
	}
	return preserveHandshakeEnvelope(err, &handshakeFailure{phase: phase, cause: err})
}

// Keep terminal causes inside the original observation envelope: its consumers
// deliberately require a concrete outer type rather than traversing arbitrary errors.
func joinHandshakeFailure(err, terminal error) error {
	if terminal == nil || terminal == err {
		return err
	}
	return preserveHandshakeEnvelope(err, errors.Join(err, terminal))
}

func preserveHandshakeEnvelope(err, cause error) error {
	// Preserve the existing observation API's concrete outer envelopes, without
	// modifying published errors or changing the original Is/As chain.
	switch observed := err.(type) {
	case *tlsFailureError:
		return &tlsFailureError{cause: cause, snapshot: observed.snapshot}
	case *helloFailureError:
		return &helloFailureError{cause: cause, snapshot: observed.snapshot, hello: observed.hello}
	default:
		return cause
	}
}

// HandshakeFailureDiagnostic returns only closed, non-sensitive tokens, or an
// empty string if err contains no server-produced handshake failure marker.
// It never calls Error, formats an underlying value, or examines paths, peer
// certificates, keys, or payloads. Outer joined cleanup errors cannot change the
// category: only the marker's original cause is classified. No newline is added.
func HandshakeFailureDiagnostic(err error) string {
	marker := findHandshakeFailure(err)
	if marker == nil {
		return ""
	}
	return "cengine storage-data-handshake-failure phase=" + marker.phase.diagnostic() + " category=" + handshakeFailureCategory(marker.cause)
}

func findHandshakeFailure(err error) *handshakeFailure {
	if marker, ok := err.(*handshakeFailure); ok {
		return marker
	}
	// Do not use errors.As: a caller-authored As method cannot mint a marker.
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range e.Unwrap() {
			if marker := findHandshakeFailure(child); marker != nil {
				return marker
			}
		}
	case interface{ Unwrap() error }:
		return findHandshakeFailure(e.Unwrap())
	}
	return nil
}

func handshakeFailureCategory(err error) string {
	// Explicit errno allowlist: never use Errno.Error or a numeric fallback.
	for _, entry := range []struct {
		cause error
		token string
	}{
		{context.DeadlineExceeded, "deadline"},
		{os.ErrDeadlineExceeded, "deadline"},
		{context.Canceled, "cancel"},
		{syscall.ENOENT, "enoent"},
		{syscall.ENOTTY, "enotty"},
		{syscall.EPERM, "eperm"},
		{syscall.EACCES, "eacces"},
		{syscall.EINVAL, "einval"},
		{syscall.EXDEV, "exdev"},
		{syscall.EOPNOTSUPP, "eopnotsupp"},
		{syscall.ENOSYS, "enosys"},
		{syscall.EIO, "eio"},
		{syscall.ENOSPC, "enospc"},
		{syscall.EROFS, "erofs"},
		{syscall.EMFILE, "emfile"},
		{syscall.ENFILE, "enfile"},
		{syscall.ENOMEM, "enomem"},
		{syscall.EBUSY, "ebusy"},
		{syscall.EBADF, "ebadf"},
		{syscall.ENOTDIR, "enotdir"},
		{syscall.ELOOP, "eloop"},
		{syscall.EPIPE, "epipe"},
		{syscall.ECONNRESET, "econnreset"},
		{syscall.ECONNABORTED, "econnaborted"},
		{syscall.ETIMEDOUT, "deadline"},
		{a.ErrInvalid, "authority-invalid"},
		{a.ErrUnauthorized, "authority-unauthorized"},
		{a.ErrConflict, "authority-conflict"},
		{a.ErrUnknown, "authority-unknown"},
		{a.ErrBlocked, "authority-blocked"},
		{a.ErrReadOnly, "authority-read-only"},
		{a.ErrLimit, "authority-limit"},
		{a.ErrCapacityInvariant, "authority-capacity-invariant"},
		{a.ErrLocked, "authority-locked"},
		{a.ErrMissing, "authority-missing"},
		{a.ErrRepairRequired, "authority-repair-required"},
		{a.ErrBusy, "authority-busy"},
		{a.ErrClosed, "authority-closed"},
		{w.ErrInvalid, "protocol"},
		{io.EOF, "eof"},
		{io.ErrUnexpectedEOF, "eof"},
		{ErrOverload, "overload"},
	} {
		if errors.Is(err, entry.cause) {
			return entry.token
		}
	}
	return "other"
}
