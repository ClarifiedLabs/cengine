package nfs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/willscott/go-nfs-client/nfs/rpc"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

type recordIdentityHandler struct {
	Handler
	called chan struct{}
}

func (h *recordIdentityHandler) WithIdentity(context.Context, Identity, func() error) error {
	h.called <- struct{}{}
	return errors.New("test callback")
}

func TestIncompleteRPCNeverAcquiresIdentityAndIsClosed(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		name := "deadline"
		if cancelRequest {
			name = "cancellation"
		}
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			h := &recordIdentityHandler{called: make(chan struct{}, 1)}
			s := &Server{Handler: h, ReadTimeout: 50 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { s.newConn(server).serve(ctx); close(done) }()
			var header bytes.Buffer
			if err := xdr.Write(&header, uint32(1)); err != nil {
				t.Fatal(err)
			}
			if err := xdr.Write(&header, uint32(0)); err != nil {
				t.Fatal(err)
			}
			if err := xdr.Write(&header, rpc.Header{Rpcvers: 2, Prog: nfsServiceID, Vers: 3, Proc: 1, Cred: authForTest(10001, 10001), Verf: rpc.AuthNull}); err != nil {
				t.Fatal(err)
			}
			var frame bytes.Buffer
			binary.Write(&frame, binary.BigEndian, uint32(header.Len()+8)|0x80000000)
			frame.Write(header.Bytes()) // withhold the eight-byte GETATTR body
			client.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := client.Write(frame.Bytes()); err != nil {
				t.Fatal(err)
			}
			if cancelRequest {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("incomplete RPC outlived read deadline/cancellation")
			}
			if s.receiveBytes != 0 {
				t.Fatalf("incomplete request leaked receive budget: %d", s.receiveBytes)
			}
			select {
			case <-h.called:
				t.Fatal("incomplete request entered identity scope")
			default:
			}
		})
	}
}

func TestNonreadingRPCPeerReleasesQueuedResponseAndBudget(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	h := &recordIdentityHandler{called: make(chan struct{}, 4)}
	s := &Server{Handler: h, ReadTimeout: 50 * time.Millisecond}
	done := make(chan struct{})
	go func() { s.newConn(server).serve(context.Background()); close(done) }()
	var request bytes.Buffer
	xdr.Write(&request, uint32(1))
	xdr.Write(&request, uint32(0))
	xdr.Write(&request, rpc.Header{Rpcvers: 2, Prog: nfsServiceID, Vers: 3, Proc: 1, Cred: authForTest(10001, 10001), Verf: rpc.AuthNull})
	request.Write(make([]byte, 8))
	var frames bytes.Buffer
	for i := 0; i < 3; i++ {
		binary.Write(&frames, binary.BigEndian, uint32(request.Len())|0x80000000)
		frames.Write(request.Bytes())
	}
	client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := client.Write(frames.Bytes()); err != nil {
		t.Fatal(err)
	}
	// Never read replies: the serializer, then response queue, must time out.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("non-reading peer retained request resources")
	}
	if s.receiveBytes != 0 {
		t.Fatalf("queued response leaked %d request bytes", s.receiveBytes)
	}
}

func TestRPCReceiveBudgetBoundsAggregateRecordsAndReleases(t *testing.T) {
	s := &Server{}
	releases := make([]func(), 4)
	for i := range releases {
		release, err := s.reserveRPCBytes(16 << 20)
		if err != nil {
			t.Fatal(err)
		}
		releases[i] = release
	}
	if _, err := s.reserveRPCBytes(1); err == nil {
		t.Fatal("aggregate receive budget exceeded")
	}
	releases[0]()
	releases[0]() // idempotent release cannot make extra space
	if _, err := s.reserveRPCBytes((16 << 20) + 1); err == nil {
		t.Fatal("double release increased budget")
	}
	replacement, err := s.reserveRPCBytes(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	replacement()
	for _, release := range releases[1:] {
		release()
	}
	if s.receiveBytes != 0 {
		t.Fatalf("leaked bytes: %d", s.receiveBytes)
	}
}

func TestRPCRejectsOversizedRecordBeforeAllocation(t *testing.T) {
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, uint32(MaxRead+4097)|0x80000000)
	_, err := (&conn{Server: &Server{}}).readRequestHeader(context.Background(), bufio.NewReader(&frame))
	if !errors.Is(err, ErrInputInvalid) {
		t.Fatalf("oversized frame: %v", err)
	}
}

func TestRPCRejectsTruncatedRecordBody(t *testing.T) {
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, uint32(48)|0x80000000)
	for _, word := range []uint32{1, 0, 2, nfsServiceID, 3, 0, 0, 0, 0, 0} {
		binary.Write(&frame, binary.BigEndian, word)
	}
	_, err := (&conn{Server: &Server{}}).readRequestHeader(context.Background(), bufio.NewReader(&frame))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated body: %v", err)
	}
}
