package workloadstorage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
)

type originalProbePanicError struct{}

func (originalProbePanicError) Error() string { panic("private-error") }
func (originalProbePanicError) Unwrap() error { panic("private-unwrap") }
func (originalProbePanicError) Is(error) bool { panic("private-is") }
func (originalProbePanicError) As(any) bool   { panic("private-as") }
func (originalProbePanicError) Timeout() bool { panic("private-timeout") }

type originalProbeSliceError []byte

func (originalProbeSliceError) Error() string { panic("private-slice") }

func TestOriginalProbeCategoryClosed(t *testing.T) {
	cycle := &net.OpError{}
	cycle.Err = cycle
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "no-error"}, {ErrInvalidFrame, "invalid-frame"}, {io.EOF, "eof"}, {io.ErrUnexpectedEOF, "unexpected-eof"},
		{context.Canceled, "canceled"}, {context.DeadlineExceeded, "deadline"}, {os.ErrDeadlineExceeded, "deadline"}, {net.ErrClosed, "closed"},
		{&net.OpError{Op: "secret", Net: "secret", Err: &os.SyscallError{Syscall: "secret", Err: syscall.ECONNREFUSED}}, "refused"},
		{&os.PathError{Op: "private", Path: "private", Err: syscall.EIO}, "eio"},
		{syscall.ENOTCONN, "enotconn"}, {syscall.ESTALE, "estale"}, {syscall.EACCES, "eacces"},
		{syscall.EBADF, "ebadf"}, {syscall.EROFS, "erofs"}, {syscall.EPERM, "eperm"},
		{syscall.ECONNRESET, "reset"}, {syscall.EPIPE, "broken-pipe"}, {syscall.ETIMEDOUT, "timeout"}, {syscall.ENETUNREACH, "unreachable"},
		{&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "unknown-authority"},
		{x509.CertificateInvalidError{Reason: x509.Expired, Detail: "secret"}, "certificate-time"},
		{x509.CertificateInvalidError{}, "certificate-invalid"}, {x509.HostnameError{}, "certificate-name"},
		{tls.RecordHeaderError{Msg: "secret"}, "tls-record"}, {tls.AlertError(1), "tls-alert"},
		{errors.New("secret 192.0.2.1 certificate credentials data"), "other"}, {originalProbePanicError{}, "other"},
		{originalProbeSliceError("secret"), "other"}, {cycle, "other"}, {(*net.OpError)(nil), "other"},
	} {
		if got := originalProbeCategory(tc.err); got != tc.want {
			t.Fatalf("category=%q want=%q", got, tc.want)
		}
	}
}

func TestOriginalProbeFailurePreservesIdentityAndClosedOutput(t *testing.T) {
	cause := originalProbePanicError{}
	original := errors.New("original private error")
	for _, stage := range []string{"decode", "arm", "admission", "trust", "tls-config", "dial", "dial-state", "deadline", "tls-handshake", "tls-state", "read", "signature-count", "post-sign-bytes", "capture-overflow", "secret\naddress"} {
		calls := 0
		got := originalProbeFailure(true, stage, cause, original, func(line string) {
			calls++
			wantStage := stage
			if strings.Contains(stage, "secret") {
				wantStage = "other"
			}
			if line != "cengine original-probe-failure stage="+wantStage+" category=other" {
				t.Fatalf("unsafe line %q", line)
			}
		})
		if got != original || calls != 1 {
			t.Fatal("error identity or count changed")
		}
	}
	for _, returned := range []error{nil, original} {
		if got := originalProbeFailure(true, "read", cause, returned, func(string) { panic("sink") }); got != returned {
			t.Fatal("sink replaced result")
		}
		if got := originalProbeFailure(false, "read", cause, returned, func(string) { t.Fatal("disabled sink invoked") }); got != returned {
			t.Fatal("disabled changed result")
		}
	}
}

func TestOriginalArmFailureObservationGate(t *testing.T) {
	for _, name := range []string{"same-e-retained-fd", "cross-e-retained-fd", "cross-mount-root-grant", "retired-root-grant-replay"} {
		arm := originalTestArm()
		arm.Version = 5
		if rootOriginalCase(name) {
			arm.Version = 6
		}
		arm.CaseName = name
		if originalArmFailureEnabled(arm) != originalConsumerEnabled() {
			t.Fatal("build profile gate")
		}
		if (&originalConsumer{used: true, begun: true, arm: arm}).probeFailureEnabled() != originalConsumerEnabled() {
			t.Fatal("probe profile gate")
		}
		for _, mutate := range []func(*OriginalConsumerArm){
			func(a *OriginalConsumerArm) { a.RequestID = "private" },
			func(a *OriginalConsumerArm) { a.Profile = "ordinary" },
			func(a *OriginalConsumerArm) { a.Version = 1 },
		} {
			bad := arm
			mutate(&bad)
			if originalArmFailureEnabled(bad) {
				t.Fatal("invalid Arm enabled")
			}
		}
	}
	if originalArmFailureEnabled(originalTestArm()) || originalArmFailureEnabled(OriginalConsumerArm{}) {
		t.Fatal("unrelated observation enabled")
	}
}

func TestOriginalReadFailureCategories(t *testing.T) {
	for err, category := range map[c.OriginalReadFailure]string{
		c.OriginalReadUnjoined: "read-unjoined", c.OriginalReadClosed: "read-closed",
		c.OriginalReadCacheOnly: "read-cache-only", c.OriginalReadTraffic: "read-traffic",
		c.OriginalReadShape: "read-shape", c.OriginalReadReply: "read-reply",
		c.OriginalReadReleaseDir: "read-releasedir",
		c.OriginalReadGetAttr:    "read-getattr", c.OriginalReadRepeated: "read-repeated",
		c.OriginalReadMissingGrant: "read-missing-grant", c.OriginalReadFailure(255): "other",
	} {
		if originalProbeCategory(err) != category || !errors.Is(err, c.ErrProtocol) {
			t.Fatal("lost finite category or protocol rejection")
		}
	}
}

func TestOriginalArmFailureStagesPreserveClosedOutput(t *testing.T) {
	for _, stage := range []string{"arm-session", "arm-issued-identity", "arm-root", "arm-writable",
		"root-target", "root-owners", "root-getattr", "root-open", "root-read-begin", "root-read", "root-read-trace", "root-read-witness", "root-pair", "root-return",
		"writable-owner", "writable-open", "writable-trace-begin", "writable-positive", "writable-positive-trace", "writable-return",
		"writable-probe-denied-mount-join", "root-probe-denied-mount-join", "writable-probe-positive", "writable-probe-owner", "writable-probe-begin", "writable-probe-mount-join", "writable-probe-mount-error",
		"writable-probe-execute", "writable-probe-trace", "writable-probe-context", "writable-probe-completion", "writable-probe-count", "writable-probe-write", "writable-probe-sync", "writable-probe-identity", "writable-probe-negative",
		"writable-stop-busy", "writable-stop-failed", "writable-stop-close", "root-stop-close", "root-stop-join", "root-probe-pair", "root-probe-source", "root-probe-source-outcome", "root-probe-replay", "root-probe-replay-return"} {
		original := errors.New("private")
		calls := 0
		got := originalProbeFailure(true, stage, originalProbePanicError{}, original, func(line string) {
			calls++
			if line != "cengine original-probe-failure stage="+stage+" category=other" {
				t.Fatalf("unsafe line %q", line)
			}
		})
		if got != original || calls != 1 {
			t.Fatal("error identity or count changed")
		}
	}
}

func TestOriginalProbeFailureConcurrent(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run("report", func(t *testing.T) {
			t.Parallel()
			original := errors.New("original")
			if originalProbeFailure(true, "read", io.EOF, original, func(string) {}) != original {
				t.Fatal("identity")
			}
		})
	}
}

func TestOriginalProbeFailureObservationGate(t *testing.T) {
	newOwner := func() *originalConsumer { return &originalConsumer{used: true, begun: true, arm: originalTestArm()} }
	if newOwner().probeFailureEnabled() != originalConsumerEnabled() {
		t.Fatal("build profile gate")
	}
	for _, mutate := range []func(*originalConsumer){
		func(o *originalConsumer) { o.used = false }, func(o *originalConsumer) { o.begun = false },
		func(o *originalConsumer) { o.arm.RequestID = "invalid" }, func(o *originalConsumer) { o.arm.Profile = "ordinary" },
		func(o *originalConsumer) { o.arm.CaseName = "cross-e-existing-data" }, func(o *originalConsumer) { o.arm.Version = 3 },
	} {
		o := newOwner()
		mutate(o)
		if o.probeFailureEnabled() {
			t.Fatal("unarmed/other observation enabled")
		}
	}
	if (&originalConsumer{}).probeFailureEnabled() {
		t.Fatal("ordinary production owner enabled")
	}
}

func TestOriginalProbeFailureActualDiscardReturnsUnchangedSentinel(t *testing.T) {
	// Actual control decode and probe admission/trust boundaries, not a wrapper
	// that manufactures a different returned error. No socket or guest required.
	o := &originalConsumer{used: true, begun: true, arm: originalTestArm(), ctx: context.Background()}
	s := &Session{factory: &originalFactoryFake{observer: o}}
	if _, err := s.originalConsumerControl("original-consumer-probe", []byte("private malformed payload")); err != ErrInvalidFrame {
		t.Fatal("decode error identity changed")
	}
	if originalConsumerEnabled() && !o.stopped {
		t.Fatal("decode failed to retire")
	}
	o = &originalConsumer{used: true, begun: true, arm: originalTestArm(), ctx: context.Background()}
	if _, err := o.probe(OriginalConsumerProbe{}); err != ErrInvalidFrame {
		t.Fatal("trust error identity changed")
	}
	if o.probed || o.done != nil {
		t.Fatal("trust failure changed ownership")
	}
	o.begun = false
	if _, err := o.probe(OriginalConsumerProbe{}); err != ErrInvalidFrame {
		t.Fatal("admission error identity changed")
	}
}
