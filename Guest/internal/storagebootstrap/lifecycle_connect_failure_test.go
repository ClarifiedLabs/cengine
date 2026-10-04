package storagebootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

func assertLifecycleConnectFailure(t *testing.T, s *lifecycleSession, err error) {
	t.Helper()
	var failed *lifecycleWorkloadFailed
	if !errors.As(err, &failed) {
		t.Fatal("connect loss did not fence workload", err)
	}
	assertLifecycleWorkloadFenced(t, s)
	request := lifecyclePrivateCommand("connect-workload", nil)
	request.RequestID = 9007199254740993
	reply, err := lifecyclePrivateReply(request, []byte("must not leak"), err)
	check(t, err)
	var wire bytes.Buffer
	check(t, writeLifecyclePrivateReply(&wire, reply, false)) // Small non-workload frame.
	raw, err := ReadFrame(&wire)
	check(t, err)
	if string(raw) != `{"error":"workload-failed","request_id":9007199254740993,"version":"storage-child-lifecycle.v2"}` {
		t.Fatal(string(raw))
	}
}

// Each failure uses real paired TLS and retains the same child/ROOT trust until
// the actual service successor's ROOT commit, not a parent reconnect or retry.
func TestLifecycleConnectFailureROOTSuccessor(t *testing.T) {
	for _, phase := range []string{"proof", "tls", "hello"} {
		t.Run(phase, func(t *testing.T) {
			r := newLifecycleRebindFixture(t)
			f := r.f
			client, trust, key, greeting := f.s.client, f.s.bootTrust, f.s.key, f.s.greeting
			// Retire an existing workload stream as part of the failing connect.
			old, _ := r.stream(t, r.svc.ServeControl)
			check(t, f.s.connectWorkload(t.Context(), old))
			var raw net.Conn
			switch phase {
			case "proof":
				check(t, f.s.raw.(*net.TCPConn).CloseWrite())
				raw, _ = r.stream(t, r.svc.ServeControl)
			case "tls":
				raw, _ = r.stream(t, r.svc.ServeControl)
				check(t, raw.(*net.TCPConn).CloseWrite())
			case "hello":
				// Complete TLS but close before the workload Hello response.
				raw, _ = r.stream(t, func(ctx context.Context, peer net.Conn) error {
					return r.svc.ServeControl(ctx, &lifecycleCloseAfterHandshakeConn{Conn: peer})
				})
			}
			err := f.s.connectWorkload(t.Context(), raw)
			assertLifecycleConnectFailure(t, f.s, err)
			if phase != "hello" && !errors.Is(err, syscall.EPIPE) {
				t.Fatal("did not exercise encrypted broken pipe", err)
			}
			if f.s.client != client || f.s.bootTrust != trust || f.s.key != key || f.s.greeting != greeting {
				t.Fatal("connect loss changed ROOT session")
			}
			if _, err := old.Write([]byte{1}); err == nil {
				t.Fatal("prior workload stream retained")
			}
			r.reopen(t)
			r.stage(t)
			assertLifecycleWorkloadFenced(t, f.s)
			lifecycleSessionProof(t, f, r.challenge(t, 3, p.LifecycleChildServiceResult, nil))
			assertLifecycleWorkloadFenced(t, f.s)
			confirmation := p.LifecycleServiceChangeConfirmation{Request: r.change, Successor: *f.s.pendingRebind.proven}
			lifecycleSessionProof(t, f, r.challenge(t, 4, p.LifecycleChildServiceCommit, &confirmation))
			if f.s.workloadFailed || f.s.client == client || f.s.bootTrust == trust {
				t.Fatal("ROOT successor commit failed to replace service/fence")
			}
			counter := f.s.highWater
			work, _ := r.stream(t, r.svc.ServeControl)
			check(t, f.s.connectWorkload(t.Context(), work))
			lifecycleRecoveryCall(t, f.s, c.Request{Query: &c.Empty{}})
			if f.s.highWater != counter {
				t.Fatal("successful connect required an extra ROOT proof")
			}
		})
	}
}

// TLS 1.3 server writes its handshake in one call, then the Hello response in
// another. Closing the latter supplies clean EOF after the actual handshake.
type lifecycleCloseAfterHandshakeConn struct {
	net.Conn
	writes int
}

func (c *lifecycleCloseAfterHandshakeConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writes == 2 {
		c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}

type lifecycleConnectDropConn struct {
	net.Conn
	armed atomic.Bool
	drop  func(net.Conn)
}

func (c *lifecycleConnectDropConn) Write(b []byte) (int, error) {
	if c.armed.Swap(false) {
		c.drop(c.Conn)
		c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}

func TestLifecycleConnectServiceResultFailureClassification(t *testing.T) {
	for _, mode := range []string{"eof", "reset", "corrupt-tls", "truncated-tls", "cancel", "deadline", "revoked", "changed-client", "changed-config", "changed-grant", "changed-trust"} {
		t.Run(mode, func(t *testing.T) {
			drops := make(chan *lifecycleConnectDropConn, 1)
			var r *lifecycleRebindFixture
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r = newLifecycleRebindFixture(t, func(peer net.Conn) net.Conn {
				drop := &lifecycleConnectDropConn{Conn: peer, drop: func(peer net.Conn) {
					switch mode {
					case "reset":
						_ = peer.(*net.TCPConn).SetLinger(0)
					case "corrupt-tls":
						_, _ = peer.Write([]byte{0xff, 3, 3, 0, 1, 0})
					case "truncated-tls":
						_, _ = peer.Write([]byte{23, 3, 3, 0, 16, 0})
					case "cancel":
						cancel()
					case "deadline":
						<-ctx.Done()
					case "revoked":
						r.f.s.close()
					case "changed-client", "changed-config", "changed-grant", "changed-trust":
						r.f.s.mu.Lock()
						switch mode {
						case "changed-client":
							r.f.s.client = nil
						case "changed-config":
							r.f.s.privateBootConfig.Hello.ControllerEpoch++
						case "changed-grant":
							r.f.s.owner.Grant.Serial++
						case "changed-trust":
							r.f.s.bootTrust = p.LifecycleBootTrust{}
						}
						r.f.s.mu.Unlock()
					}
				}}
				drops <- drop
				return drop
			})
			drop := <-drops
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			drop.armed.Store(true)
			raw, _ := r.stream(t, r.svc.ServeControl)
			err := r.f.s.connectWorkload(ctx, raw)
			var failed *lifecycleWorkloadFailed
			if mode == "eof" || mode == "reset" {
				assertLifecycleConnectFailure(t, r.f.s, err)
			} else if err == nil || errors.As(err, &failed) || r.f.s.workloadFailed {
				t.Fatal("fatal ServiceResult failure preserved bridge", err)
			}
			if mode == "truncated-tls" && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal("did not exercise TLS truncation", err)
			}
			if r.f.s.workload != nil || r.f.s.workloadRaw != nil {
				t.Fatal("failed proof retained workload")
			}
		})
	}
}

func TestLifecycleConnectHelloFailureClassification(t *testing.T) {
	for _, mode := range []string{"eof", "reset", "partial-header", "missing-body", "corrupt-tls", "truncated-tls", "identity-pin", "wrong-identity", "remote-error", "unknown-field", "cancel", "deadline", "revoked", "changed-config", "changed-grant", "changed-trust"} {
		t.Run(mode, func(t *testing.T) {
			f, cfg := lifecycleWorkloadFixture(t, false)
			lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
			if mode == "identity-pin" {
				key, err := p.NewServerKey()
				check(t, err)
				binding, err := p.NewServerBinding(p.StoreID(f.cfg.store), p.ServiceEpoch(cfg.ServiceEpoch))
				check(t, err)
				csr, err := key.CSR(binding)
				check(t, err)
				cert, err := f.issuer.IssueServer(csr, binding, f.now, time.Hour)
				check(t, err)
				cfg.Identity, err = cert.WithKey(key)
				check(t, err)
			}
			tlsConfig, err := p.ServerTLSConfig(cfg.Identity, cfg.ClientRoot)
			check(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			raw, wait := credentialStream(t, func(_ context.Context, peer net.Conn) error {
				var err error
				defer peer.Close()
				stream := tls.Server(peer, tlsConfig)
				if err := stream.HandshakeContext(t.Context()); err != nil {
					if mode == "identity-pin" {
						return nil
					}
					return err
				}
				if _, err := ReadFrame(stream); err != nil {
					return err
				}
				switch mode {
				case "reset":
					return peer.(*net.TCPConn).SetLinger(0)
				case "partial-header":
					_, err = stream.Write([]byte{0, 0})
				case "missing-body":
					_, err = stream.Write([]byte{0, 0, 0, 16})
				case "corrupt-tls":
					_, err = peer.Write([]byte{0xff, 3, 3, 0, 1, 0})
				case "truncated-tls":
					_, err = peer.Write([]byte{23, 3, 3, 0, 16, 0})
				case "wrong-identity":
					identity := cfg.LifecycleIdentity
					identity.Generation++
					err = WriteFrame(stream, c.HelloReply{Version: c.LifecycleWorkloadVersion, Store: f.cfg.store, ServiceEpoch: cfg.ServiceEpoch, LifecycleIdentity: &identity})
				case "unknown-field":
					err = WriteFrame(stream, map[string]any{"version": c.LifecycleWorkloadVersion, "unknown": true})
				case "remote-error":
					err = WriteFrame(stream, c.HelloReply{Error: c.Unauthorized})
				case "cancel":
					cancel()
				case "deadline":
					<-ctx.Done()
				case "revoked":
					f.s.close()
				case "changed-config", "changed-grant", "changed-trust":
					f.s.mu.Lock()
					switch mode {
					case "changed-config":
						f.s.privateBootConfig.Hello.ControllerEpoch++
					case "changed-grant":
						f.s.owner.Grant.Serial++
					case "changed-trust":
						f.s.bootTrust = p.LifecycleBootTrust{}
					}
					f.s.mu.Unlock()
				}
				return err
			})
			err = f.s.connectWorkload(ctx, raw)
			var failed *lifecycleWorkloadFailed
			if mode == "eof" || mode == "reset" {
				assertLifecycleConnectFailure(t, f.s, err)
				lifecycleSessionProof(t, f, f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant))
				assertLifecycleWorkloadFenced(t, f.s)
			} else if err == nil || errors.As(err, &failed) || f.s.workloadFailed {
				t.Fatal("fatal connect failure preserved bridge", err)
			}
			if f.s.workload != nil || f.s.workloadRaw != nil {
				t.Fatal("failed connect retained workload")
			}
			check(t, wait())
		})
	}
}
