//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
)

const tlsFailureTestEnabled = true

func TestTLSFailureOverflowPreservesActualFailure(t *testing.T) {
	s, authority, cfg, _ := tlsFailureFixture(t, true)
	raw, other := failureTCPPair(t)
	client := tls.Client(other, cfg)
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), authority, raw) }()
	must(t, client.Handshake())
	var b [1]byte
	_, _ = client.Read(b[:])
	original := wait(t, done)
	var verification *tls.CertificateVerificationError
	if !errors.As(original, &verification) {
		t.Fatalf("not actual TLS rejection: %v", original)
	}
	for _, size := range []int{0, (128 << 10) + 1} {
		peer := &failureReadResult{data: make([]byte, size)}
		transport, observer := s.observeTLSFailure(WithTLSFailureObservation(context.Background()), peer)
		_, _ = transport.Read(make([]byte, size))
		if err := observer.failure(original); err != original {
			t.Fatal("empty/overflow evidence replaced original TLS failure")
		}
	}
}

type failureReadResult struct {
	net.Conn
	data []byte
	err  error
}

func (r *failureReadResult) Read(b []byte) (int, error) { return copy(b, r.data), r.err }

func TestTLSFailureObserverTransparentBound(t *testing.T) {
	s, _, _, _ := tlsFailureFixture(t, true)
	for _, size := range []int{128 << 10, (128 << 10) + 1} {
		original := errors.New("read returned bytes and error")
		raw := &failureReadResult{data: bytes.Repeat([]byte{0xa7}, size), err: original}
		transport, o := s.observeTLSFailure(WithTLSFailureObservation(context.Background()), raw)
		b := make([]byte, size)
		n, err := transport.Read(b)
		if n != size || err != original || !bytes.Equal(b, raw.data) {
			t.Fatal("changed raw read result")
		}
		if (o.digest == nil) != (size > 128<<10) {
			t.Fatal("incorrect bound")
		}
		if got := o.failure(io.EOF); got != io.EOF {
			t.Fatal("non-verification failure changed")
		}
		if o.digest != nil {
			t.Fatal("failed handshake retained observer")
		}
		// A later read still delegates with the same buffer/result after disable.
		n, err = transport.Read(b[:1])
		if n != 1 || err != original || b[0] != 0xa7 {
			t.Fatal("disabled observer changed IO")
		}
	}
	raw := &failureReadResult{}
	transport, o := s.observeTLSFailure(context.Background(), raw)
	if transport != raw || o != nil {
		t.Fatal("unrequested recording")
	}
}
