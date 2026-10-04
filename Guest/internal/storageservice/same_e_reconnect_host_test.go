//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	a "dev.cengine/guest/internal/storageauthority"
	client "dev.cengine/guest/internal/storageclient"
	control "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	w "dev.cengine/guest/internal/storagewire"
)

func reconnectOriginal(t *testing.T, f *fixture, h a.DataHello, identity p.Identity) *client.Client {
	t.Helper()
	raw, wait := serve(t, f.s.ServeData)
	cfg := consumerTLS(t, f, identity)
	conn := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	must(t, conn.HandshakeContext(ctx))
	data, err := client.New(client.Config{Conn: conn, TLSConfig: cfg, ServerPin: a.Fingerprint(f.ready.ServerKey.String()), Authority: h, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: 0x1ffffffffff, Limits: client.DefaultLimits(), Timeout: time.Second, Invalidate: func(context.Context, client.Notification) error { return nil }})
	must(t, err)
	t.Cleanup(func() { data.Close(); _ = wait() })
	must(t, data.OriginalConsumerPositiveRoot(ctx, h))
	return data
}

func reconnectRetire(t *testing.T, f *fixture, h a.DataHello, operation a.ID) {
	t.Helper()
	ctl, join := f.connect(t)
	defer func() { ctl.Close(); join() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := ctl.Call(ctx, control.Request{Retire: &a.RetireRequest{Operation: operation, Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch}})
	must(t, err)
	if r.Receipt == nil || r.Receipt.Store != h.Binding.Store || r.Receipt.Volume != h.Binding.Volume || r.Receipt.Attachment != h.Binding.Attachment || r.Receipt.Prepare != "" || r.Receipt.Revision == 0 {
		t.Fatal("missing exact real retirement receipt", r)
	}
	s, err := ctl.Call(ctx, control.Request{Query: &control.Empty{}})
	must(t, err)
	if s.Snapshot == nil || s.Snapshot.Store.ID != h.Binding.Store || s.Snapshot.Epoch != h.Epoch {
		t.Fatal("retirement changed S/E")
	}
	rec := s.Snapshot.Attachments[h.Binding.Attachment]
	if rec.Binding != h.Binding || rec.Phase != a.Drained || rec.Retirement != operation || rec.Receipt == nil || *rec.Receipt != *r.Receipt {
		t.Fatal("receipt not independently reconciled", rec)
	}
}

// Only the host filesystem executor/barrier is substituted. Issued TLS, the
// original Client.Do positive, authenticated Retire/Query and reconnect are real.
func TestSameEReconnectActualRetireAndRejections(t *testing.T) {
	for _, kind := range []string{"retired", "active-conflict", "wrong-hello", "foreign-leaf", "foreign-retired", "wrong-digest", "unknown-ca", "eof", "canceled", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			executor, err := f.s.InstallCompatibilityHostTestExecutor()
			must(t, err)
			h, identity := consumerIdentity(t, f)
			other, otherIdentity := wrongHelloROIdentity(t, f)
			data := reconnectOriginal(t, f, h, identity)
			if executor.GetAttrCalls() != 1 {
				t.Fatal("no real original positive")
			}
			q := consumerArm(t, f, h, identity, cc.SameEReconnect)
			q.Version = cc.SameEReconnectVersion
			if kind == "wrong-digest" {
				q.OriginalLeafSHA256 = strings.Repeat("f", 64)
			}
			_, err = f.s.ArmConsumerObservation(q)
			must(t, err)
			if kind != "active-conflict" {
				reconnectRetire(t, f, h, a.ID(q.OperationUUID))
			}
			select {
			case <-data.Terminal():
				t.Fatal("original connection lost before reconnect")
			default:
			}
			changed := h
			switch kind {
			case "wrong-hello":
				changed.Binding.Volume = other.Binding.Volume
			case "foreign-leaf":
				identity = otherIdentity
			case "foreign-retired":
				reconnectRetire(t, f, other, id(t))
				changed, identity = other, otherIdentity
			case "unknown-ca":
				foreign := newFixture(t)
				_, identity = consumerIdentity(t, foreign)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			raw, wait := serve(t, func(_ context.Context, conn net.Conn) error { return f.s.ServeData(ctx, conn) })
			if kind == "eof" {
				raw.Close()
			} else if kind == "canceled" {
				cancel()
				raw.Close()
			} else {
				cfg := consumerTLS(t, f, identity)
				if kind == "unknown-ca" {
					cert := cfg.Certificates[0]
					cfg.Certificates = nil
					cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
				}
				conn := tls.Client(raw, cfg)
				must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
				err = conn.Handshake()
				if kind != "unknown-ca" {
					must(t, err)
				}
				if err == nil {
					var greeting w.ServerHello
					err = w.ReadFrame(conn, &greeting)
					if kind != "unknown-ca" {
						must(t, err)
					}
					if err == nil {
						if greeting.Epoch != h.Epoch || conn.ConnectionState().DidResume {
							t.Fatal("not current same-E non-resumed TLS")
						}
						must(t, w.WriteFrame(conn, &w.ClientHello{Authority: changed, Profile: w.RequiredProfile()}))
						var root w.RootReply
						if w.ReadFrame(conn, &root) == nil {
							t.Fatal("unexpected root grant")
						}
					}
				}
			}
			serverErr := wait()
			if serverErr == nil {
				t.Fatal("missing real rejection")
			}
			if kind == "active-conflict" && serverErr != a.ErrConflict {
				t.Fatal("not real active conflict", serverErr)
			}
			if kind == "retired" || kind == "duplicate" || kind == "wrong-digest" || kind == "foreign-retired" {
				if serverErr != a.ErrBlocked {
					t.Fatal("not actual blocked auth", serverErr)
				}
			}
			if kind == "duplicate" {
				raw2, wait2 := serve(t, f.s.ServeData)
				raw2.Close()
				_ = wait2()
			}
			status, err := f.s.QueryConsumerObservation(q)
			must(t, err)
			must(t, cc.ValidateStatus(status))
			if kind != "retired" {
				if status.State != "failed" || status.Evidence != nil {
					t.Fatal("false auth proof", status)
				}
				if _, err = f.s.FinalizeConsumerObservation(q); err == nil {
					t.Fatal("sealed false proof")
				}
				return
			}
			status, err = f.s.FinalizeConsumerObservation(q)
			must(t, err)
			must(t, cc.ValidateStatus(status))
			e := status.Evidence
			if status.State != "finalized" || status.SelectedCount != 1 || e == nil || e.Hello == nil || *e.Hello != h || e.Stage != "authenticate-data" || e.ErrorClass != "blocked" || e.Admission != nil || e.ByteCount != 0 || e.PrefixSHA256 != "" {
				t.Fatal(status)
			}
			e.Hello.Binding.Key = other.Binding.Key
			raw2, wait2 := serve(t, f.s.ServeData)
			raw2.Close()
			_ = wait2()
			again, err := f.s.FinalizeConsumerObservation(q)
			must(t, err)
			if *again.Evidence.Hello != h {
				t.Fatal("aliased or changed terminal evidence")
			}
			if executor.GetAttrCalls() != 1 {
				t.Fatal("reconnect reached dispatch")
			}
		})
	}
}
