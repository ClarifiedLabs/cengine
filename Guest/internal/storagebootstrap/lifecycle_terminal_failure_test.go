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

	c "dev.cengine/guest/internal/storagecontrol"
)

func TestLifecycleTerminalFailureIsBoundedAndNeverContinues(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{errLifecycleSession, "fatal-session"},
		{ErrProtocol, "fatal-protocol"},
		{c.ErrProtocol, "fatal-protocol"},
		{context.DeadlineExceeded, "fatal-timeout"},
		{context.Canceled, "fatal-canceled"},
		{io.EOF, "fatal-eof"},
		{io.ErrUnexpectedEOF, "fatal-truncated"},
		{&net.OpError{Op: "read", Err: syscall.ECONNRESET}, "fatal-transport"},
		{tls.RecordHeaderError{}, "fatal-tls"},
		{&c.RemoteError{Code: c.Unauthorized}, "fatal-remote-UNAUTHORIZED"},
		{&c.RemoteError{Code: c.Busy}, "fatal-remote-BUSY"},
		{&c.RemoteError{Code: "secret-path"}, "fatal-internal"},
		{errors.New("secret-path and private material must not escape"), "fatal-internal"},
	} {
		t.Run(test.code, func(t *testing.T) {
			request := lifecyclePrivateCommand("takeover", nil)
			request.RequestID = 9007199254740993
			original := fmt.Errorf("private detail: %w", test.err)
			reply, err := lifecyclePrivateReply(request, []byte("must not leak"), original)
			if err != original {
				t.Fatal("fatal diagnostic must retain the original terminal error", err)
			}
			if reply == nil {
				t.Fatal("terminal failure lost its diagnostic")
			}
			var wire bytes.Buffer
			check(t, writeLifecyclePrivateReply(&wire, reply, false))
			raw, e := ReadFrame(&wire)
			check(t, e)
			expected := `{"error":"` + test.code + `","request_id":9007199254740993,"version":"storage-child-lifecycle.v2"}`
			if string(raw) != expected {
				t.Fatal(string(raw))
			}
		})
	}
}
