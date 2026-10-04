package storagebootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

func TestLifecycleWorkloadUnavailableWireAndClassification(t *testing.T) {
	request := lifecyclePrivateCommand("workload-command", nil)
	request.RequestID = 9007199254740993
	reply, err := lifecyclePrivateReply(request, []byte("must not leak"), &lifecycleWorkloadUnavailable{io.EOF})
	check(t, err)
	var wire bytes.Buffer
	check(t, writeLifecyclePrivateReply(&wire, reply, true))
	raw, err := ReadFrame(&wire)
	check(t, err)
	if string(raw) != `{"error":"workload-unavailable","request_id":9007199254740993,"version":"storage-child-lifecycle.v2"}` {
		t.Fatal(string(raw))
	}
	for _, err := range []error{io.EOF, &net.OpError{Op: "read", Err: io.EOF}} {
		if !lifecycleWorkloadTransportLoss(fmt.Errorf("wrapped: %w", err)) {
			t.Fatal("genuine loss rejected", err)
		}
		if _, e := lifecyclePrivateReply(request, nil, err); e == nil {
			t.Fatal("untyped transport error continued", err)
		}
	}
	for _, err := range []error{io.ErrUnexpectedEOF, ErrProtocol, c.ErrProtocol, c.ErrLimit, context.Canceled, context.DeadlineExceeded, syscall.ETIMEDOUT,
		io.ErrClosedPipe, net.ErrClosed, c.ErrClosed, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.ENOTCONN,
		&net.OpError{Op: "read", Err: io.ErrUnexpectedEOF}, &net.OpError{Op: "read", Err: errors.New("unknown")}, errors.New("tls: bad certificate"),
		errors.Join(io.EOF, context.Canceled), errors.Join(io.EOF, c.ErrProtocol)} {
		if lifecycleWorkloadTransportLoss(err) {
			t.Fatal("permanent failure treated as availability", err)
		}
	}
	for _, op := range []string{"connect-workload", "connect-boot", "retire", "takeover", "controller-csr", "attachment-certificate"} {
		if _, err := lifecyclePrivateReply(lifecyclePrivateCommand(op, nil), nil, &lifecycleWorkloadUnavailable{io.EOF}); err == nil {
			t.Fatal("nonworkload recovery", op)
		}
	}
}

type lifecycleDropReplyConn struct {
	net.Conn
	drop    atomic.Bool
	dropped atomic.Uint32
}

func (c *lifecycleDropReplyConn) Write(b []byte) (int, error) {
	if c.drop.Swap(false) {
		c.dropped.Add(1)
		c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}

func lifecycleRecoveryCall(t *testing.T, s *lifecycleSession, request c.Request) c.Response {
	t.Helper()
	raw, err := s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("workload-command", lifecyclePrivateBody(t, request)), nil)
	check(t, err)
	var response c.Response
	check(t, json.Unmarshal(raw, &response))
	if response.Error != "" {
		t.Fatal("remote error", response.Error)
	}
	return response
}

func TestLifecycleWorkloadLostRetireReplyReconnectSameIdentity(t *testing.T) {
	var barriers atomic.Uint32
	f, cfg := lifecycleWorkloadFixture(t, false, func(_ a.Binding, root *os.File) error {
		barriers.Add(1)
		return root.Sync() // Host fixture barrier, not Guest mount/drain evidence.
	})
	lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
	server, err := c.NewPKILifecycleWorkloadServer(f.authority, cfg)
	check(t, err)
	left, right := net.Pipe()
	drop := &lifecycleDropReplyConn{Conn: left}
	done := make(chan error, 1)
	go func() { done <- server.Serve(t.Context(), drop) }()
	t.Cleanup(func() {
		left.Close()
		right.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server hung")
		}
	})
	check(t, f.s.connectWorkload(t.Context(), right))
	volume := lifecycleSessionID(t)
	lifecycleRecoveryCall(t, f.s, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: lifecycleSessionID(t), Store: f.cfg.store, Volume: volume, Name: "lost-retire"}})
	binding := a.Binding{Store: f.cfg.store, Volume: volume, Attachment: lifecycleSessionID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: lifecycleSessionID(t), Key: a.Fingerprint(strings.Repeat("b", 64)), Role: a.RuntimeRole, Mode: a.ReadWrite}
	lifecycleRecoveryCall(t, f.s, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: lifecycleSessionID(t), Binding: binding}})
	request := c.Request{Retire: &a.RetireRequest{Operation: lifecycleSessionID(t), Store: binding.Store, Volume: binding.Volume, Attachment: binding.Attachment, Launch: binding.Launch}}
	lifecycle, greeting, pin := f.s.client, f.s.greeting, lifecycleSessionPin(t, f.s)
	certificate := f.s.privateBootConfig.Identity.Certificate().DER()
	drop.drop.Store(true) // After dispatch, discard exactly the first encrypted reply.
	raw, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("workload-command", lifecyclePrivateBody(t, request)), nil)
	var unavailable *lifecycleWorkloadUnavailable
	if !errors.As(err, &unavailable) || len(raw) != 0 || drop.dropped.Load() != 1 {
		t.Fatal("lost reply not typed", err, string(raw), drop.dropped.Load())
	}
	if f.s.revoked || f.s.client != lifecycle || f.s.workload != nil || f.s.workloadRaw != nil || f.s.greeting != greeting || lifecycleSessionPin(t, f.s) != pin {
		t.Fatal("loss altered keyholder/lifecycle or retained workload")
	}
	// A fresh ROOT result proves the lifecycle connection was not merely retained
	// as a dead pointer. Reconnect reuses the original own-key client certificate.
	lifecycleSessionProof(t, f, f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant))
	connectLifecycleWorkload(t, f, cfg)
	if !bytes.Equal(certificate, f.s.privateBootConfig.Identity.Certificate().DER()) {
		t.Fatal("reconnect replaced client identity")
	}
	before := lifecycleRecoveryCall(t, f.s, c.Request{Query: &c.Empty{}})
	replayed := lifecycleRecoveryCall(t, f.s, request)
	after := lifecycleRecoveryCall(t, f.s, c.Request{Query: &c.Empty{}})
	if replayed.Receipt == nil || replayed.Receipt.Attachment != binding.Attachment || replayed.Receipt.Launch != binding.Launch || before.Snapshot.Revision != after.Snapshot.Revision || barriers.Load() != 1 {
		t.Fatal("retire was not an immutable receipt replay", replayed)
	}
	encoded := string(lifecyclePrivateBody(t, before))
	if !strings.Contains(encoded, string(lifecyclePrivateBody(t, replayed.Receipt))) {
		t.Fatal("replay differs from already durable receipt", encoded, replayed.Receipt)
	}
}

func TestLifecycleWorkloadTransportFailureAndFatalReplies(t *testing.T) {
	for _, mode := range []string{"partial-header", "missing-body", "partial-body", "partial-header-reset", "missing-body-reset", "wrong-id", "unknown-field", "corrupt-tls", "truncated-tls", "cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f, cfg := lifecycleWorkloadFixture(t, false)
			lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
			tlsConfig, err := p.ServerTLSConfig(cfg.Identity, cfg.ClientRoot)
			check(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "timeout" {
				var timeoutCancel context.CancelFunc
				ctx, timeoutCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer timeoutCancel()
			}
			raw, wait := credentialStream(t, func(ctx context.Context, peer net.Conn) error {
				var err error
				defer peer.Close()
				stream := tls.Server(peer, tlsConfig)
				if err := stream.HandshakeContext(ctx); err != nil {
					return err
				}
				if _, err := ReadFrame(stream); err != nil {
					return err
				}
				if err := WriteFrame(stream, c.HelloReply{Version: c.LifecycleWorkloadVersion, Store: f.cfg.store, ServiceEpoch: cfg.ServiceEpoch, LifecycleIdentity: &cfg.LifecycleIdentity}); err != nil {
					return err
				}
				if _, err := ReadFrame(stream); err != nil {
					return err
				}
				switch mode {
				case "partial-header", "partial-header-reset":
					_, err = stream.Write([]byte{0, 0})
				case "missing-body", "missing-body-reset":
					_, err = stream.Write([]byte{0, 0, 0, 16})
				case "partial-body":
					_, err = stream.Write([]byte{0, 0, 0, 16, '{'})
				case "wrong-id":
					err = WriteFrame(stream, c.Response{ID: 99, Error: c.Unauthorized})
				case "unknown-field":
					err = WriteFrame(stream, map[string]any{"id": 1, "error": "unauthorized", "unknown": true})
				case "corrupt-tls":
					_, err = peer.Write([]byte{0xff, 3, 3, 0, 1, 0})
				case "truncated-tls":
					// A valid application-data header, but incomplete ciphertext,
					// after the real TLS handshake and CONTROL hello exchange.
					_, err = peer.Write([]byte{23, 3, 3, 0, 16, 0})
				case "cancel":
					cancel()
					_, _ = stream.Read(make([]byte, 1))
				case "timeout":
					_, _ = stream.Read(make([]byte, 1))
				}
				if strings.HasSuffix(mode, "-reset") {
					if e := peer.(*net.TCPConn).SetLinger(0); e != nil {
						return e
					}
				}
				return err
			})
			check(t, f.s.connectWorkload(t.Context(), raw))
			_, err = f.s.privateLifecycleRequest(ctx, lifecyclePrivateCommand("workload-command", lifecyclePrivateBody(t, c.Request{Query: &c.Empty{}})), nil)
			var unavailable *lifecycleWorkloadUnavailable
			if err == nil || errors.As(err, &unavailable) {
				t.Fatal("permanent failure continued", err)
			}
			var failed *lifecycleWorkloadFailed
			transportFailure := strings.HasSuffix(mode, "-reset")
			if (mode == "truncated-tls" || mode == "partial-header" || mode == "missing-body" || mode == "partial-body") && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal("truncation did not exercise unexpected EOF", err)
			}
			if errors.As(err, &failed) != transportFailure {
				t.Fatal("wrong non-boundary failure classification", err)
			}
			_, replyErr := lifecyclePrivateReply(lifecyclePrivateCommand("workload-command", nil), nil, err)
			if (replyErr == nil) != transportFailure {
				t.Fatal("wrong bridge continuation", err, replyErr)
			}
			if transportFailure {
				assertLifecycleWorkloadFenced(t, f.s)
				lifecycleSessionProof(t, f, f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant))
				assertLifecycleWorkloadFenced(t, f.s) // An old-service ROOT result is not a rebind.
			}
			check(t, wait())
		})
	}
}
