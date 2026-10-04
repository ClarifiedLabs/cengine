package workloadstorage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"syscall"

	c "dev.cengine/guest/internal/storageclient"
)

// Only the existing explicit, retained observation identity enables this log.
// No caller text, identity, address, certificate or payload enters the sink.
func (o *originalConsumer) probeFailureEnabled() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.used && o.begun && (originalArmFailureEnabled(o.arm) || originalConsumerEnabled() && o.arm.valid() && o.arm.Version == 1 && o.arm.CaseName == "cross-e-old-leaf-reconnect")
}

func (o *originalConsumer) probeFailure(stage string, cause, returned error) error {
	return originalProbeFailure(o.probeFailureEnabled(), stage, cause, returned, emitOriginalProbeFailure)
}

// Arm diagnostics use the validated explicit full-profile request, before the
// retained owner exists. They expose only finite failure stages, not evidence.
func originalArmFailure(arm OriginalConsumerArm, stage string, failure error) {
	if failure == nil {
		return
	}
	originalProbeFailure(originalArmFailureEnabled(arm), stage, failure, failure, emitOriginalProbeFailure)
}

func originalArmFailureEnabled(arm OriginalConsumerArm) bool {
	return originalConsumerEnabled() && arm.valid() && (arm.Version == 5 || arm.Version == 6 || arm.Version == 7)
}

// Observation is best effort; neither classification nor the sink may replace
// the caller's exact error (including nil). No wrapping or error formatting.
func originalProbeFailure(enabled bool, stage string, cause, returned error, emit func(string)) (result error) {
	result = returned
	if !enabled {
		return
	}
	defer func() { _ = recover() }()
	switch stage {
	case "decode", "arm", "admission", "trust", "tls-config", "dial", "dial-state", "deadline", "tls-handshake", "tls-state", "read", "signature-count", "post-sign-bytes", "capture-overflow",
		"arm-session", "arm-issued-identity", "arm-root", "arm-writable",
		"root-target", "root-owners", "root-getattr", "root-open", "root-read-begin", "root-read", "root-read-trace", "root-read-witness", "root-pair", "root-return",
		"writable-owner", "writable-open", "writable-trace-begin", "writable-positive", "writable-positive-trace", "writable-return",
		"writable-probe-denied-mount-join", "root-probe-denied-mount-join", "writable-probe-positive", "writable-probe-owner", "writable-probe-begin", "writable-probe-mount-join", "writable-probe-mount-error",
		"writable-probe-execute", "writable-probe-trace", "writable-probe-context", "writable-probe-completion", "writable-probe-count", "writable-probe-write", "writable-probe-sync", "writable-probe-identity", "writable-probe-negative",
		"writable-stop-busy", "writable-stop-failed", "writable-stop-close", "root-stop-close", "root-stop-join", "root-probe-pair", "root-probe-source", "root-probe-source-outcome", "root-probe-replay", "root-probe-replay-return":
	default:
		stage = "other"
	}
	emit("cengine original-probe-failure stage=" + stage + " category=" + originalProbeCategory(cause))
	return
}

// Deliberately do not call arbitrary Error, Is, As, Unwrap or Timeout methods.
// Only concrete standard-library wrappers are traversed, with a hard bound
// for malformed/cyclic wrappers. Unknown errors always stay "other".
func originalProbeCategory(err error) string {
	for depth := 0; depth < 8; depth++ {
		switch err {
		case nil:
			return "no-error"
		case ErrInvalidFrame:
			return "invalid-frame"
		case io.EOF:
			return "eof"
		case io.ErrUnexpectedEOF:
			return "unexpected-eof"
		case context.Canceled:
			return "canceled"
		case context.DeadlineExceeded, os.ErrDeadlineExceeded:
			return "deadline"
		case net.ErrClosed:
			return "closed"
		}
		switch e := err.(type) {
		case c.OriginalReadFailure:
			switch e {
			case c.OriginalReadUnjoined:
				return "read-unjoined"
			case c.OriginalReadClosed:
				return "read-closed"
			case c.OriginalReadCacheOnly:
				return "read-cache-only"
			case c.OriginalReadTraffic:
				return "read-traffic"
			case c.OriginalReadGetAttr:
				return "read-getattr"
			case c.OriginalReadReleaseDir:
				return "read-releasedir"
			case c.OriginalReadRepeated:
				return "read-repeated"
			case c.OriginalReadShape:
				return "read-shape"
			case c.OriginalReadReply:
				return "read-reply"
			case c.OriginalReadMissingGrant:
				return "read-missing-grant"
			}
			return "other"
		case *net.OpError:
			if e == nil {
				return "other"
			}
			err = e.Err
		case *os.PathError:
			if e == nil {
				return "other"
			}
			err = e.Err
		case *os.SyscallError:
			if e == nil {
				return "other"
			}
			err = e.Err
		case *tls.CertificateVerificationError:
			if e == nil {
				return "other"
			}
			err = e.Err
		case x509.UnknownAuthorityError:
			return "unknown-authority"
		case x509.CertificateInvalidError:
			if e.Reason == x509.Expired {
				return "certificate-time"
			}
			return "certificate-invalid"
		case x509.HostnameError:
			return "certificate-name"
		case tls.RecordHeaderError:
			return "tls-record"
		case tls.AlertError:
			return "tls-alert"
		case syscall.Errno:
			switch e {
			case syscall.EIO:
				return "eio"
			case syscall.ENOTCONN:
				return "enotconn"
			case syscall.ESTALE:
				return "estale"
			case syscall.EACCES:
				return "eacces"
			case syscall.EBADF:
				return "ebadf"
			case syscall.EROFS:
				return "erofs"
			case syscall.EPERM:
				return "eperm"
			case syscall.ECONNREFUSED:
				return "refused"
			case syscall.ECONNRESET:
				return "reset"
			case syscall.EPIPE:
				return "broken-pipe"
			case syscall.ETIMEDOUT:
				return "timeout"
			case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
				return "unreachable"
			}
			return "other"
		default:
			return "other"
		}
	}
	return "other"
}
