//go:build linux

package storageworker

import (
	"bytes"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestOwnerReceivePendingDeadlineAndContinuation(t *testing.T) {
	requireRoot(t)
	ch, peer := channelPair(t, unix.SOCK_SEQPACKET, true, os.Getpid())
	owner := &Owner{channel: ch}
	payload := []byte("original sequence and nonce")
	_, err := owner.Exchange(payload, time.Now().Add(10*time.Millisecond))
	var pending *ReplyPendingError
	if !errors.As(err, &pending) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("receive deadline not typed", err)
	}
	buf := make([]byte, 100)
	n, _, err := unix.Recvfrom(peer, buf, unix.MSG_DONTWAIT)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatal("not fully sent", err)
	}
	if _, err := owner.Exchange([]byte("blind resend"), time.Now().Add(time.Second)); !errors.Is(err, ErrProtocol) {
		t.Fatal("resent pending packet", err)
	}
	if _, _, err := unix.Recvfrom(peer, buf, unix.MSG_DONTWAIT); err != unix.EAGAIN {
		t.Fatal("unexpected second send", err)
	}
	if _, err := owner.ReceivePending(time.Now().Add(10 * time.Millisecond)); !errors.As(err, &pending) {
		t.Fatal("repeat receive deadline", err)
	}
	if err := unix.Send(peer, payload, 0); err != nil {
		t.Fatal(err)
	}
	got, err := owner.ReceivePending(time.Now().Add(time.Second))
	if err != nil || !bytes.Equal(got, payload) || owner.awaitingReply {
		t.Fatal("lost original reply", err)
	}
	if _, err := owner.ReceivePending(time.Now().Add(time.Second)); !errors.Is(err, ErrProtocol) {
		t.Fatal("continued without pending reply", err)
	}
}

func TestOwnerReceivePendingRejectsCredentialsAndEOF(t *testing.T) {
	requireRoot(t)
	for _, mode := range []string{"credentials", "eof", "closed"} {
		t.Run(mode, func(t *testing.T) {
			ch, peer := channelPair(t, unix.SOCK_SEQPACKET, true, os.Getpid())
			owner := &Owner{channel: ch}
			_, err := owner.Exchange([]byte("request"), time.Now().Add(10*time.Millisecond))
			var pending *ReplyPendingError
			if !errors.As(err, &pending) {
				t.Fatal(err)
			}
			expected := ErrProtocol
			switch mode {
			case "credentials":
				ch.peer++
				if err := unix.Send(peer, []byte("reply"), 0); err != nil {
					t.Fatal(err)
				}
			case "eof":
				if err := unix.Shutdown(peer, unix.SHUT_WR); err != nil {
					t.Fatal(err)
				}
				expected = io.EOF
			case "closed":
				if err := ch.Close(); err != nil {
					t.Fatal(err)
				}
				// ReceivePending sets the deadline before reading. os.File's
				// closed-deadline error need not wrap os.ErrClosed; preserve
				// that exact terminal error rather than relabeling it pending.
				expected = ch.SetDeadline(time.Now().Add(time.Second))
				if expected == nil || errors.Is(expected, os.ErrDeadlineExceeded) {
					t.Fatal("closed channel accepted a deadline", expected)
				}
			}
			_, err = owner.ReceivePending(time.Now().Add(time.Second))
			if errors.As(err, &pending) || !errors.Is(err, expected) {
				t.Fatal("failure recoverable", mode, err)
			}
		})
	}
}

// Test helper keeps the same real child alive after a delayed first reply.
func TestPendingReplyChild(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	parent, err := strconv.Atoi(os.Args[len(os.Args)-1])
	if err != nil {
		os.Exit(81)
	}
	child, err := accept(parent)
	if err != nil {
		os.Exit(82)
	}
	for i := 0; i < 2; i++ {
		payload, err := child.Receive()
		if err != nil {
			os.Exit(83)
		}
		if i == 0 {
			time.Sleep(150 * time.Millisecond)
		}
		if err := child.Send(payload); err != nil {
			os.Exit(84)
		}
	}
	// Parent must kill and observe the sole Wait, not infer death from IO.
	_, _ = child.Receive()
	os.Exit(0)
}

func TestOwnerPendingReplyRealChildAndReaping(t *testing.T) {
	requireRoot(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owner, err := start(root, []string{"-test.run=^TestPendingReplyChild$", "--", strconv.Itoa(os.Getpid())}, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Kill(); awaitResult(t, owner); _ = owner.Close() }()
	pid := owner.PID()
	first := []byte("sequence 1 original nonce")
	_, err = owner.Exchange(first, time.Now().Add(10*time.Millisecond))
	var pending *ReplyPendingError
	if !errors.As(err, &pending) {
		t.Fatal("missing deadline", err)
	}
	got, err := owner.ReceivePending(time.Now().Add(2 * time.Second))
	if err != nil || !bytes.Equal(got, first) {
		t.Fatal("did not drain original reply", err)
	}
	fresh := []byte("sequence 2 fresh nonce")
	got, err = owner.Exchange(fresh, time.Now().Add(time.Second))
	if err != nil || !bytes.Equal(got, fresh) || owner.PID() != pid {
		t.Fatal("fresh exchange changed worker", err)
	}
	// An actually reaped child cannot authenticate a continuation.
	_, err = owner.Exchange([]byte("no reply"), time.Now().Add(10*time.Millisecond))
	_ = owner.Kill()
	result := awaitResult(t, owner)
	if !result.Reaped {
		t.Fatal("no actual reap", result)
	}
	if _, err := owner.ReceivePending(time.Now().Add(time.Second)); err == nil || errors.As(err, &pending) {
		t.Fatal("reaped worker recovered", err)
	}
}

func TestOwnerSendDeadlineIsNotReplyPending(t *testing.T) {
	requireRoot(t)
	ch, _ := channelPair(t, unix.SOCK_SEQPACKET, true, os.Getpid())
	owner := &Owner{channel: ch}
	_, err := owner.Exchange([]byte("not sent"), time.Now().Add(-time.Second))
	var pending *ReplyPendingError
	if err == nil || errors.As(err, &pending) || owner.awaitingReply {
		t.Fatal("unknown send converted to pending receive", err)
	}
}
