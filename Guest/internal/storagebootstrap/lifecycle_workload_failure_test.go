package storagebootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	c "dev.cengine/guest/internal/storagecontrol"
)

func TestLifecycleWorkloadFailedWireAndClassification(t *testing.T) {
	request := lifecyclePrivateCommand("workload-command", nil)
	request.RequestID = 9007199254740993
	for _, cause := range []error{syscall.EPIPE, syscall.ECONNRESET} {
		wrapped := fmt.Errorf("wrapped: %w", &net.OpError{Op: "write", Net: "unix", Err: cause})
		if !lifecycleWorkloadPermanentTransportLoss(wrapped) || lifecycleWorkloadTransportLoss(wrapped) {
			t.Fatal("transport failure gained retry or lost classification", wrapped)
		}
		reply, err := lifecyclePrivateReply(request, []byte("must not leak"), &lifecycleWorkloadFailed{wrapped})
		check(t, err)
		var wire bytes.Buffer
		check(t, writeLifecyclePrivateReply(&wire, reply, true))
		raw, err := ReadFrame(&wire)
		check(t, err)
		if string(raw) != `{"error":"workload-failed","request_id":9007199254740993,"version":"storage-child-lifecycle.v2"}` {
			t.Fatal(string(raw))
		}
		if _, err := lifecyclePrivateReply(request, nil, wrapped); err == nil {
			t.Fatal("untyped failure continued")
		}
		for _, op := range []string{"connect-boot", "stage-service-rebind", "retire", "takeover", "controller-csr", "attachment-certificate"} {
			if _, err := lifecyclePrivateReply(lifecyclePrivateCommand(op, nil), nil, &lifecycleWorkloadFailed{wrapped}); err == nil {
				t.Fatal("nonworkload failure continued", op)
			}
		}
		for _, fatal := range []error{context.Canceled, context.DeadlineExceeded, ErrProtocol, c.ErrProtocol, c.ErrLimit} {
			if lifecycleWorkloadPermanentTransportLoss(errors.Join(wrapped, fatal)) {
				t.Fatal("fatal error treated as transport loss", fatal)
			}
		}
	}
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, &net.OpError{Op: "read", Err: io.ErrUnexpectedEOF}, io.ErrClosedPipe, net.ErrClosed, c.ErrClosed, syscall.ETIMEDOUT, syscall.ECONNABORTED, syscall.ENOTCONN,
		tls.RecordHeaderError{}, tls.AlertError(42), errors.New("tls: bad certificate")} {
		if lifecycleWorkloadPermanentTransportLoss(err) {
			t.Fatal("unclassified failure preserved ROOT", err)
		}
	}
}

func assertLifecycleWorkloadFenced(t *testing.T, s *lifecycleSession) {
	t.Helper()
	if s.revoked || !s.workloadFailed || s.workload != nil || s.workloadRaw != nil || s.client == nil {
		t.Fatal("workload loss revoked lifecycle or retained old workload")
	}
	if _, err := s.workloadCommand(t.Context(), c.Request{Query: &c.Empty{}}); !errors.Is(err, errLifecycleSession) {
		t.Fatal("fenced lane accepted command", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	check(t, left.SetReadDeadline(time.Now().Add(time.Second)))
	if err := s.connectWorkload(t.Context(), right); !errors.Is(err, errLifecycleSession) {
		t.Fatal("fenced lane accepted reconnect", err)
	}
	if _, err := left.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("rejected reconnect retained stream", err)
	}
}
