package storageserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

type handshakePanicError struct{}

func (*handshakePanicError) Error() string { panic("underlying Error must never be called") }

func TestHandshakeFailureRedactionAndIdentity(t *testing.T) {
	secret := &handshakePanicError{}
	err := wrapHandshakeFailure(handshakeRootFactory, secret)
	if err.Error() != "storageserver: DATA handshake failed" {
		t.Fatal("wrapper text is not constant")
	}
	if got := HandshakeFailureDiagnostic(err); got != "cengine storage-data-handshake-failure phase=root-factory category=other" {
		t.Fatalf("unexpected diagnostic: %q", got)
	}
	var typed *handshakePanicError
	if !errors.Is(err, secret) || !errors.As(err, &typed) || typed != secret {
		t.Fatal("lost original error identity or type")
	}
	pathErr := &os.PathError{Op: "SECRET-OP", Path: "/SECRET/path/cert/key/payload", Err: syscall.ENOTTY}
	err = wrapHandshakeFailure(handshakeRootFactory, pathErr)
	var path *os.PathError
	if !errors.Is(err, syscall.ENOTTY) || !errors.As(err, &path) || path != pathErr {
		t.Fatal("lost wrapped errno or PathError")
	}
	if got := HandshakeFailureDiagnostic(err); got != "cengine storage-data-handshake-failure phase=root-factory category=enotty" {
		t.Fatalf("path or operation escaped redaction: %q", got)
	}
	for _, unmarked := range []error{nil, secret, pathErr, errors.Join(secret, syscall.EIO)} {
		if got := HandshakeFailureDiagnostic(unmarked); got != "" {
			t.Fatalf("unmarked error produced diagnostic: %q", got)
		}
	}
	if wrapHandshakeFailure(handshakeTLS, nil) != nil {
		t.Fatal("successful handshake gained marker")
	}
}

func TestHandshakeFailureClosedPhases(t *testing.T) {
	for _, tc := range []struct {
		phase handshakePhase
		want  string
	}{
		{handshakeDeadline, "deadline"},
		{handshakeTLS, "tls"},
		{handshakeTLSState, "tls-state"},
		{handshakeServerHelloWrite, "server-hello-write"},
		{handshakeClientHelloRead, "client-hello-read"},
		{handshakePeerPolicy, "peer-policy"},
		{handshakeAuthenticate, "authenticate"},
		{handshakeBinding, "binding"},
		{handshakeAdmission, "admission"},
		{handshakeRootFactory, "root-factory"},
		{handshakeRootReplyQueue, "root-reply-queue"},
		{handshakeRootReplyWrite, "root-reply-write"},
		{handshakePhase(255), "unknown"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			want := "cengine storage-data-handshake-failure phase=" + tc.want + " category=eof"
			if got := HandshakeFailureDiagnostic(wrapHandshakeFailure(tc.phase, io.EOF)); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestHandshakeFailureClosedCategoriesAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		cause error
		want  string
	}{
		{syscall.ENOENT, "enoent"}, {syscall.ENOTTY, "enotty"},
		{syscall.EPERM, "eperm"}, {syscall.EACCES, "eacces"},
		{syscall.EINVAL, "einval"}, {syscall.EXDEV, "exdev"},
		{syscall.EOPNOTSUPP, "eopnotsupp"}, {syscall.ENOSYS, "enosys"},
		{syscall.EIO, "eio"}, {syscall.ENOSPC, "enospc"},
		{syscall.EROFS, "erofs"}, {syscall.EMFILE, "emfile"},
		{syscall.ENFILE, "enfile"}, {syscall.ENOMEM, "enomem"},
		{syscall.EBUSY, "ebusy"}, {syscall.EBADF, "ebadf"},
		{syscall.ENOTDIR, "enotdir"}, {syscall.ELOOP, "eloop"},
		{syscall.EPIPE, "epipe"}, {syscall.ECONNRESET, "econnreset"},
		{syscall.ECONNABORTED, "econnaborted"}, {syscall.ETIMEDOUT, "deadline"},
		{context.DeadlineExceeded, "deadline"}, {os.ErrDeadlineExceeded, "deadline"},
		{context.Canceled, "cancel"}, {io.EOF, "eof"}, {io.ErrUnexpectedEOF, "eof"},
		{w.ErrInvalid, "protocol"}, {ErrOverload, "overload"},
		{a.ErrInvalid, "authority-invalid"}, {a.ErrUnauthorized, "authority-unauthorized"},
		{a.ErrConflict, "authority-conflict"}, {a.ErrUnknown, "authority-unknown"},
		{a.ErrBlocked, "authority-blocked"}, {a.ErrReadOnly, "authority-read-only"},
		{a.ErrLimit, "authority-limit"}, {a.ErrCapacityInvariant, "authority-capacity-invariant"},
		{a.ErrLocked, "authority-locked"}, {a.ErrMissing, "authority-missing"},
		{a.ErrRepairRequired, "authority-repair-required"}, {a.ErrBusy, "authority-busy"},
		{a.ErrClosed, "authority-closed"},
		{syscall.Errno(0x7fffffff), "other"},
		{errors.New("/private/key certificate payload SECRET"), "other"},
		{&handshakePanicError{}, "other"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			marker := wrapHandshakeFailure(handshakeAuthenticate, tc.cause)
			want := "cengine storage-data-handshake-failure phase=authenticate category=" + tc.want
			// Both ordering directions must classify only the marker's cause,
			// even when cleanup has a higher-priority errno or panicking Error.
			for _, err := range []error{marker, errors.Join(syscall.EIO, marker), errors.Join(marker, &handshakePanicError{})} {
				if got := HandshakeFailureDiagnostic(err); got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
				if !errors.Is(err, tc.cause) {
					t.Fatal("joined error lost original cause")
				}
			}
		})
	}
}

func TestHandshakeFailurePreservesObservationEnvelopes(t *testing.T) {
	cause := &handshakePanicError{}
	tlsObserved := &tlsFailureError{cause: cause, snapshot: TLSFailureSnapshot{ByteCount: 12}}
	err := wrapHandshakeFailure(handshakeTLS, tlsObserved)
	if evidence, ok := TLSFailureEvidence(err); !ok || evidence != tlsObserved.snapshot {
		t.Fatal("TLS observation envelope changed")
	}
	if got := HandshakeFailureDiagnostic(err); got != "cengine storage-data-handshake-failure phase=tls category=other" {
		t.Fatalf("lost TLS marker: %q", got)
	}
	if !errors.Is(err, tlsObserved) || !errors.Is(err, cause) {
		t.Fatal("lost TLS observation identity")
	}
	helloObserved := &helloFailureError{cause: a.ErrUnauthorized, snapshot: TLSFailureSnapshot{ByteCount: 23}}
	err = wrapHandshakeFailure(handshakePeerPolicy, helloObserved)
	if envelope, ok := err.(*helloFailureError); !ok || envelope.snapshot != helloObserved.snapshot || envelope.hello != helloObserved.hello {
		t.Fatal("Hello observation envelope changed")
	}
	if got := HandshakeFailureDiagnostic(err); got != "cengine storage-data-handshake-failure phase=peer-policy category=authority-unauthorized" {
		t.Fatalf("lost peer-policy marker: %q", got)
	}
	if !errors.Is(err, helloObserved) || !errors.Is(err, a.ErrUnauthorized) {
		t.Fatal("lost Hello observation identity")
	}
}

func TestHandshakeFailureJoinPreservesObservationEnvelopes(t *testing.T) {
	cause := &handshakePanicError{}
	tlsObserved := &tlsFailureError{cause: cause, snapshot: TLSFailureSnapshot{ByteCount: 12}}
	helloObserved := &helloFailureError{cause: a.ErrUnauthorized, snapshot: TLSFailureSnapshot{ByteCount: 23}, hello: a.DataHello{Epoch: "observed-epoch"}}
	for _, tc := range []struct {
		name     string
		phase    handshakePhase
		observed error
		cause    error
		category string
	}{
		{"tls", handshakeTLS, tlsObserved, cause, "other"},
		{"hello", handshakePeerPolicy, helloObserved, a.ErrUnauthorized, "authority-unauthorized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marked := wrapHandshakeFailure(tc.phase, tc.observed)
			for _, terminal := range []error{context.DeadlineExceeded, context.Canceled} {
				err := joinHandshakeFailure(marked, terminal)
				if !errors.Is(err, tc.observed) || !errors.Is(err, tc.cause) || !errors.Is(err, terminal) {
					t.Fatal("join lost original observation or terminal cause")
				}
				if tc.name == "tls" {
					if evidence, ok := TLSFailureEvidence(err); !ok || evidence != tlsObserved.snapshot {
						t.Fatal("join hid the concrete TLS observation envelope")
					}
				} else if envelope, ok := err.(*helloFailureError); !ok || envelope.snapshot != helloObserved.snapshot || envelope.hello != helloObserved.hello {
					t.Fatal("join hid the concrete Hello observation envelope")
				}
				want := "cengine storage-data-handshake-failure phase=" + tc.phase.diagnostic() + " category=" + tc.category
				if got := HandshakeFailureDiagnostic(err); got != want {
					t.Fatalf("terminal cause changed boundary diagnostic: %q", got)
				}
			}
		})
	}
}

func TestHandshakeFailureRootFactoryRefusal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("authority fixture requires Linux filesystem contracts")
	}
	f := newFixture(t, DefaultLimits(), false)
	cause := &os.PathError{Op: "SECRET", Path: "/private/root", Err: syscall.EOPNOTSUPP}
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, _ a.Binding) (executor, w.Entry, error) {
		must(t, g.ValidateFor(p))
		return nil, w.Entry{}, cause
	}
	binding, key := f.binding()
	client, done := f.start(binding, key)
	defer client.NetConn().Close()
	err := wait(t, done)
	if !errors.Is(err, cause) || !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatal("Serve lost root setup refusal")
	}
	if got := HandshakeFailureDiagnostic(err); got != "cengine storage-data-handshake-failure phase=root-factory category=eopnotsupp" {
		t.Fatalf("Serve lost root-factory marker: %q", got)
	}
	if got := retired(t, f.retired); got.Binding != binding {
		t.Fatal("root refusal changed exact-binding retirement")
	}
}

// Refuse only the first root write, after real TLS and DATA authentication.
type handshakeRootWriteConn struct {
	net.Conn
	refuse atomic.Bool
}

func (c *handshakeRootWriteConn) Write(b []byte) (int, error) {
	if c.refuse.Load() {
		return 0, syscall.EPIPE
	}
	return c.Conn.Write(b)
}

func TestHandshakeFailureInitialRootWrite(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("authority fixture requires Linux filesystem contracts")
	}
	for _, tc := range []struct {
		name          string
		refuse        bool
		writerTimeout bool
		category      string
	}{
		{"refused", true, false, "epipe"},
		{"stalled-writer", false, true, "deadline"},
		{"stalled-handshake", false, false, "deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := DefaultLimits()
			if tc.writerTimeout {
				limits.HandshakeTimeout = 2 * time.Second
				limits.WriteTimeout = 100 * time.Millisecond
			} else {
				limits.HandshakeTimeout = 250 * time.Millisecond
				limits.WriteTimeout = 2 * time.Second
			}
			f := newFixture(t, limits, false)
			binding, key := f.binding()
			raw, client := f.pair(key)
			transport := &handshakeRootWriteConn{Conn: raw}
			factory := f.s.factory
			f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
				exec, root, err := factory(g, p, b)
				transport.refuse.Store(tc.refuse)
				return exec, root, err
			}
			reported := make(chan error, 1)
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var callbacks atomic.Int32
			f.s.config.RequestRetirement = func(h a.DataHello, err error) {
				callbacks.Add(1)
				f.retired <- h
				reported <- err
				<-release // Reporting must precede this possibly slow retirement join.
			}
			done := make(chan error, 1)
			go func() { done <- f.s.Serve(context.Background(), f.a, transport) }()
			var hello w.ServerHello
			must(t, w.ReadFrame(client, &hello))
			must(t, w.WriteFrame(client, &w.ClientHello{Authority: a.DataHello{Epoch: hello.Epoch, Binding: binding}, Profile: w.RequiredProfile()}))
			// Never read RootReply: net.Pipe makes the successful-write boundary exact.
			initial := wait(t, reported)
			want := "cengine storage-data-handshake-failure phase=root-reply-write category=" + tc.category
			if got := HandshakeFailureDiagnostic(initial); got != want {
				t.Fatalf("retirement callback lost initial root-write cause: %q", got)
			}
			if tc.refuse && !errors.Is(initial, syscall.EPIPE) {
				t.Fatal("retirement lost refused write cause")
			}
			if tc.writerTimeout && !errors.Is(initial, os.ErrDeadlineExceeded) {
				t.Fatal("retirement lost writer deadline")
			}
			if got := retired(t, f.retired); got.Binding != binding || got.Epoch != hello.Epoch {
				t.Fatal("root-write failure changed exact-binding retirement")
			}
			select {
			case <-done:
				t.Fatal("Serve returned before retirement callback joined")
			default:
			}
			close(release)
			err := wait(t, done)
			if got := HandshakeFailureDiagnostic(err); got != want {
				t.Fatalf("Serve lost root-write diagnostic: %q", got)
			}
			if !errors.Is(err, initial) || callbacks.Load() != 1 {
				t.Fatal("Serve lost initial cause or changed once-only retirement")
			}
		})
	}
}

func TestHandshakeFailureQueuedRootCancellationBeforeWriter(t *testing.T) {
	raw, remote := net.Pipe()
	defer raw.Close()
	defer remote.Close()
	reported := make(chan error, 1)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var callbacks atomic.Int32
	p := &peer{
		server: &Server{config: Config{Limits: DefaultLimits(), RequestRetirement: func(_ a.DataHello, err error) {
			callbacks.Add(1)
			reported <- err
			<-release
		}}},
		conn:         tls.Server(raw, &tls.Config{}),
		hello:        a.DataHello{Binding: a.Binding{Attachment: "test-attachment"}},
		inputStopped: make(chan struct{}), done: make(chan struct{}), retired: make(chan struct{}),
		wake: make(chan struct{}, 1), rootWritten: make(chan struct{}),
	}
	// Exercise the production queue handoff without starting the writer. This
	// deterministically exposes cancellation in the former post-enqueue gap.
	must(t, p.enqueueRootReply(rootEntry()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-ctx.Done(); p.fail(ctx.Err()) }()
	cancel()
	initial := wait(t, reported)
	want := "cengine storage-data-handshake-failure phase=root-reply-write category=cancel"
	if got := HandshakeFailureDiagnostic(initial); got != want {
		t.Fatalf("blocked retirement did not receive queued-root diagnostic: %q", got)
	}
	if !errors.Is(initial, context.Canceled) || p.failure() != initial {
		t.Fatal("retirement lost first cancellation cause")
	}
	// A later deadline/write failure must neither replace the already published
	// error nor issue another retirement, even while that callback is blocked.
	p.fail(context.DeadlineExceeded)
	p.fail(syscall.EPIPE)
	writerDone := make(chan error, 1)
	go func() { p.writeLoop(); writerDone <- nil }()
	must(t, wait(t, writerDone))
	select {
	case <-p.rootWritten:
		t.Fatal("canceled root was written")
	case <-p.retired:
		t.Fatal("retirement completed before callback release")
	default:
	}
	if p.failure() != initial || callbacks.Load() != 1 {
		t.Fatal("later failure replaced first cause or repeated retirement")
	}
	close(release)
	select {
	case <-p.retired:
	case <-time.After(5 * time.Second):
		t.Fatal("retirement did not join after release")
	}
}

func TestHandshakeFailureRootQueuePreservesEarlierPhase(t *testing.T) {
	for _, earlierFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "queue-refusal", true: "earlier-failure"}[earlierFailure], func(t *testing.T) {
			raw, remote := net.Pipe()
			defer raw.Close()
			defer remote.Close()
			reported := make(chan error, 1)
			p := &peer{
				server:       &Server{config: Config{Limits: DefaultLimits(), RequestRetirement: func(_ a.DataHello, err error) { reported <- err }}},
				conn:         tls.Server(raw, &tls.Config{}),
				hello:        a.DataHello{Binding: a.Binding{Attachment: "test-attachment"}},
				inputStopped: make(chan struct{}), done: make(chan struct{}), retired: make(chan struct{}),
			}
			cause := error(ErrOverload)
			if earlierFailure {
				cause = wrapHandshakeFailure(handshakeRootFactory, context.Canceled)
				p.fail(cause)
			} else {
				p.bytes = p.server.config.Limits.WriterBytes // force queue refusal
			}
			if err := p.enqueueRootReply(rootEntry()); !errors.Is(err, cause) {
				t.Fatal("queue handoff changed earlier failure cause")
			}
			initial := wait(t, reported)
			if initial != cause || HandshakeFailureDiagnostic(initial) != HandshakeFailureDiagnostic(cause) {
				t.Fatal("unsuccessful enqueue relabeled earlier phase as root write")
			}
			<-p.retired
		})
	}
}

func TestHandshakeFailureInitialWriteRetirementCause(t *testing.T) {
	for _, pending := range []bool{true, false} {
		raw, remote := net.Pipe()
		reported := make(chan error, 1)
		release := make(chan struct{})
		p := &peer{
			server: &Server{config: Config{RequestRetirement: func(_ a.DataHello, err error) {
				reported <- err
				<-release
			}}},
			conn:             tls.Server(raw, &tls.Config{}),
			hello:            a.DataHello{Binding: a.Binding{Attachment: "test-attachment"}},
			rootReplyPending: pending,
			inputStopped:     make(chan struct{}), done: make(chan struct{}), retired: make(chan struct{}),
		}
		p.fail(syscall.EPIPE)
		initial := wait(t, reported)
		got := HandshakeFailureDiagnostic(initial)
		close(release)
		<-p.retired
		raw.Close()
		remote.Close()
		want := ""
		if pending {
			want = "cengine storage-data-handshake-failure phase=root-reply-write category=epipe"
		}
		if got != want || !errors.Is(initial, syscall.EPIPE) || p.failure() != initial {
			t.Fatalf("pending=%v: callback did not receive original, correctly marked cause: %q", pending, got)
		}
	}
}
