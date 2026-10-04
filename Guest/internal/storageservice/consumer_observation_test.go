package storageservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func consumerIdentity(t *testing.T, f *fixture) (a.DataHello, p.Identity) {
	t.Helper()
	control, join := f.connect(t)
	defer func() { control.Close(); join() }()
	volume := id(t)
	call(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.ready.Store.ID, Volume: volume, Name: "consumer"}})
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	b := a.Binding{Store: f.ready.Store.ID, Volume: volume, Attachment: id(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(t), Key: fingerprint(t, key), Role: a.RuntimeRole, Mode: a.ReadWrite}
	call(t, control, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: b}})
	h := a.DataHello{Epoch: f.ready.ServiceEpoch, Binding: b}
	binding, err := d.AttachmentBinding(h)
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	raw, wait := serve(t, f.s.ServeAttachmentCSR)
	cert, err := RequestLifecycleAttachmentCertificate(context.Background(), raw, f.identity, f.ready, f.s.current.Grant.Identity, h, csr)
	must(t, err)
	must(t, wait())
	identity, err := cert.WithKey(key)
	must(t, err)
	return h, identity
}
func consumerArm(t *testing.T, f *fixture, h a.DataHello, identity p.Identity, name string) cc.Arm {
	t.Helper()
	worker := string(id(t))
	must(t, f.s.BindPrepareCompatibilityWorker(worker))
	sum := sha256.Sum256(identity.Certificate().DER())
	return cc.Arm{Version: cc.Version, Profile: cc.Profile, RequestID: string(id(t)), ArmDigest: strings.Repeat("b", 64), OperationUUID: string(id(t)), CaseName: name, OriginalBootBinding: cc.BootBinding{ShimLaunchUUID: string(h.Binding.Launch), GuestBootNonce: string(id(t))}, Original: cc.OriginalFor(h), OriginalLeafSHA256: hex.EncodeToString(sum[:]), WorkerScope: cc.WorkerScope{StoreUUID: string(f.ready.Store.ID), ServiceEpoch: string(f.ready.ServiceEpoch), WorkerUUID: worker}}
}
func consumerTLS(t *testing.T, f *fixture, identity p.Identity) *tls.Config {
	t.Helper()
	root, err := p.ParseRootDER(f.ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(f.ready.Store.ID), p.ServiceEpoch(f.ready.ServiceEpoch))
	must(t, err)
	cfg, err := p.ClientTLSConfig(identity, root, server, f.ready.ServerKey)
	must(t, err)
	return cfg
}

type consumerReads struct {
	net.Conn
	limit int
}

func (r *consumerReads) Read(b []byte) (int, error) {
	if len(b) > r.limit {
		b = b[:r.limit]
	}
	return r.Conn.Read(b)
}

type consumerWrites struct {
	net.Conn
	Buffer bytes.Buffer
}

func (w *consumerWrites) Write(b []byte) (int, error) {
	n, e := w.Conn.Write(b)
	w.Buffer.Write(b[:n])
	return n, e
}
func TestConsumerServiceCrossERealTLS(t *testing.T) {
	for _, limit := range []int{1, 17, 4096} {
		t.Run(string(rune('a'+limit%26)), func(t *testing.T) {
			f := newFixture(t)
			h, identity := consumerIdentity(t, f)
			old := f.s
			must(t, old.Close())
			next, err := f.open(f.cfg, f.ready.Controller)
			must(t, err)
			f.s = next
			t.Cleanup(func() { must(t, next.Close()) })
			f.refresh(t)
			q := consumerArm(t, f, h, identity, cc.CrossE)
			status, armErr := f.s.ArmConsumerObservation(q)
			enabled := pc.CurrentProfile() == pc.FullProfile
			if enabled {
				must(t, armErr)
				if status.State != "armed" {
					t.Fatal(status)
				}
			} else if armErr == nil {
				t.Fatal("ordinary arm enabled")
			}
			raw, wait := serve(t, func(ctx context.Context, raw net.Conn) error {
				return f.s.ServeData(ctx, &consumerReads{Conn: raw, limit: limit})
			})
			writer := &consumerWrites{Conn: raw}
			client := tls.Client(writer, consumerTLS(t, f, identity))
			must(t, client.SetDeadline(time.Now().Add(4*time.Second)))
			must(t, client.Handshake())
			var b [1]byte
			if _, err := client.Read(b[:]); err == nil {
				t.Fatal("stale leaf accepted")
			}
			serveErr := wait()
			if serveErr == nil {
				t.Fatal("missing real failure")
			}
			_, typed := d.TLSFailureEvidence(serveErr)
			if typed != enabled {
				t.Fatal("incorrect optin", typed)
			}
			if !enabled {
				return
			}
			status, err = f.s.QueryConsumerObservation(q)
			must(t, err)
			must(t, cc.ValidateStatus(status))
			e := status.Evidence
			if status.State != "observed" || status.SelectedCount != 1 || e == nil || e.ByteCount == 0 || e.ByteCount > uint64(writer.Buffer.Len()) {
				t.Fatal(status)
			}
			digest := sha256.New()
			digest.Write([]byte(d.TLSFailurePrefixDomain))
			digest.Write(writer.Buffer.Bytes()[:e.ByteCount])
			if hex.EncodeToString(digest.Sum(nil)) != e.PrefixSHA256 {
				t.Fatal("prefix correlation")
			}
			e.PrefixSHA256 = "changed"
			again, err := f.s.QueryConsumerObservation(q)
			must(t, err)
			if again.Evidence.PrefixSHA256 == "changed" {
				t.Fatal("aliased evidence")
			}
			// A second attempt invalidates the arm and cannot hash or overwrite its first result.
			raw, wait = serve(t, f.s.ServeData)
			raw.Close()
			_ = wait()
			status, err = f.s.QueryConsumerObservation(q)
			must(t, err)
			if status.State != "failed" || status.Failure != "duplicate" || status.SelectedCount != 1 || status.Evidence != nil {
				t.Fatal(status)
			}
		})
	}
}
func TestConsumerServiceTransportAndScopeFailClosed(t *testing.T) {
	f := newFixture(t)
	h, identity := consumerIdentity(t, f)
	q := consumerArm(t, f, h, identity, cc.CrossE)
	q.Original.Epoch = string(id(t))
	if pc.CurrentProfile() != pc.FullProfile {
		if _, err := f.s.ArmConsumerObservation(q); err == nil {
			t.Fatal("ordinary arm")
		}
		return
	}
	for _, change := range []func(*cc.Arm){func(q *cc.Arm) { q.WorkerScope.WorkerUUID = string(id(t)) }, func(q *cc.Arm) { q.WorkerScope.ServiceEpoch = string(id(t)) }, func(q *cc.Arm) { q.WorkerScope.StoreUUID = string(id(t)) }} {
		bad := q
		change(&bad)
		if _, err := f.s.ArmConsumerObservation(bad); err == nil {
			t.Fatal("stale worker armed")
		}
	}
	_, err := f.s.ArmConsumerObservation(q)
	must(t, err)
	raw, wait := serve(t, f.s.ServeData)
	raw.Close()
	if wait() == nil {
		t.Fatal("missing transport error")
	}
	s, err := f.s.QueryConsumerObservation(q)
	must(t, err)
	if s.State != "failed" || s.SelectedCount != 1 || s.Failure != "transport-or-unattributed" || s.Evidence != nil {
		t.Fatal(s)
	}
}

func TestConsumerServiceWrongRejectedLeafCannotMatch(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		return
	}
	f := newFixture(t)
	h, identity := consumerIdentity(t, f)
	must(t, f.s.Close())
	next, err := f.open(f.cfg, f.ready.Controller)
	must(t, err)
	f.s = next
	t.Cleanup(func() { must(t, next.Close()) })
	f.refresh(t)
	q := consumerArm(t, f, h, identity, cc.CrossE)
	q.OriginalLeafSHA256 = strings.Repeat("f", 64)
	_, err = f.s.ArmConsumerObservation(q)
	must(t, err)
	raw, wait := serve(t, f.s.ServeData)
	client := tls.Client(raw, consumerTLS(t, f, identity))
	must(t, client.SetDeadline(time.Now().Add(4*time.Second)))
	must(t, client.Handshake())
	var b [1]byte
	if _, err = client.Read(b[:]); err == nil {
		t.Fatal("stale leaf accepted")
	}
	if _, ok := d.TLSFailureEvidence(wait()); !ok {
		t.Fatal("not a real attributed failure")
	}
	status, err := f.s.QueryConsumerObservation(q)
	must(t, err)
	if status.State != "failed" || status.SelectedCount != 1 || status.Failure != "mismatch" || status.Evidence != nil {
		t.Fatal(status)
	}
}

// TLS and ServeData are real in every ordering. Finalize races the actual second
// DATA connection selection, not a fabricated status or a direct recorder hook.
func TestConsumerServiceFinalizeAgainstRealSecondConnection(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		return
	}
	for _, order := range []string{"before", "after", "concurrent", "mismatch"} {
		iterations := 1
		if order == "concurrent" {
			iterations = 16
		}
		for iteration := 0; iteration < iterations; iteration++ {
			t.Run(fmt.Sprintf("%s/%d", order, iteration), func(t *testing.T) {
				f := newFixture(t)
				h, identity := consumerIdentity(t, f)
				must(t, f.s.Close())
				next, err := f.open(f.cfg, f.ready.Controller)
				must(t, err)
				f.s = next
				t.Cleanup(func() { must(t, next.Close()) })
				f.refresh(t)
				q := consumerArm(t, f, h, identity, cc.CrossE)
				if _, err = f.s.FinalizeConsumerObservation(q); err == nil {
					t.Fatal("finalized without arm")
				}
				_, err = f.s.ArmConsumerObservation(q)
				must(t, err)
				if _, err = f.s.FinalizeConsumerObservation(q); err == nil {
					t.Fatal("finalized armed")
				}
				cfg := consumerTLS(t, f, identity)
				reject := func(start chan struct{}) {
					raw, wait := serve(t, func(ctx context.Context, raw net.Conn) error {
						if start != nil {
							<-start
						}
						return f.s.ServeData(ctx, raw)
					})
					client := tls.Client(raw, cfg)
					if start != nil {
						close(start)
					}
					must(t, client.SetDeadline(time.Now().Add(4*time.Second)))
					must(t, client.Handshake())
					var b [1]byte
					if _, err := client.Read(b[:]); err == nil {
						t.Fatal("old leaf accepted")
					}
					if wait() == nil {
						t.Fatal("old leaf not rejected by ServeData")
					}
				}
				reject(nil)
				observed, err := f.s.QueryConsumerObservation(q)
				must(t, err)
				if observed.State != "observed" {
					t.Fatal(observed)
				}
				for _, change := range []func(*cc.Query){
					func(q *cc.Query) { q.WorkerScope.WorkerUUID = string(id(t)) },
					func(q *cc.Query) { q.WorkerScope.ServiceEpoch = string(id(t)) },
					func(q *cc.Query) {
						q.WorkerScope.StoreUUID = string(id(t))
						q.Original.Binding.Store = q.WorkerScope.StoreUUID
					},
				} {
					bad := q
					change(&bad)
					if _, err = f.s.FinalizeConsumerObservation(bad); err == nil {
						t.Fatal("wrong owner scope finalized")
					}
				}
				if order == "mismatch" {
					bad := q
					bad.OperationUUID = string(id(t))
					if _, err = f.s.FinalizeConsumerObservation(bad); err == nil {
						t.Fatal("mismatched finalize accepted")
					}
					got, err := f.s.QueryConsumerObservation(q)
					must(t, err)
					if got.State != "failed" || got.Failure != "mismatch" || got.Evidence != nil {
						t.Fatal(got)
					}
					if _, err = f.s.FinalizeConsumerObservation(q); err == nil {
						t.Fatal("mismatch revived")
					}
					reject(nil)
					return
				}
				var terminal cc.Status
				var sealErr error
				switch order {
				case "before":
					reject(nil)
					terminal, sealErr = f.s.FinalizeConsumerObservation(q)
				case "after":
					terminal, sealErr = f.s.FinalizeConsumerObservation(q)
					must(t, sealErr)
					reject(nil)
				case "concurrent":
					start := make(chan struct{})
					done := make(chan struct{})
					go func() {
						<-start
						terminal, sealErr = f.s.FinalizeConsumerObservation(q)
						close(done)
					}()
					// Both operations are released without ordering their recorder lock.
					reject(start)
					<-done
				}
				got, err := f.s.QueryConsumerObservation(q)
				must(t, err)
				if sealErr != nil {
					if got.State != "failed" || got.Failure != "duplicate" || got.Evidence != nil {
						t.Fatal(got)
					}
					if _, err = f.s.FinalizeConsumerObservation(q); err == nil {
						t.Fatal("finalized failed")
					}
					return
				}
				if order == "before" {
					t.Fatal("duplicate before seal accepted")
				}
				observed.State = "finalized"
				if !reflect.DeepEqual(got, observed) || !reflect.DeepEqual(terminal, observed) {
					t.Fatal("seal changed evidence", got)
				}
				must(t, cc.ValidateStatus(terminal))
				terminal.Evidence.PrefixSHA256 = "mutated"
				bad := q
				bad.OperationUUID = string(id(t))
				if _, err = f.s.FinalizeConsumerObservation(bad); err == nil {
					t.Fatal("wrong query finalized")
				}
				if _, err = f.s.QueryConsumerObservation(bad); err == nil {
					t.Fatal("wrong query accepted")
				}
				if _, err = f.s.ArmConsumerObservation(q); err == nil {
					t.Fatal("rearmed finalized")
				}
				f.s.consumer.Close()
				for i := 0; i < 3; i++ {
					got, err = f.s.FinalizeConsumerObservation(q)
					must(t, err)
					if !reflect.DeepEqual(got, observed) {
						t.Fatal("terminal snapshot changed", got)
					}
					got.Evidence.ByteCount++
				}
			})
		}
	}
}
