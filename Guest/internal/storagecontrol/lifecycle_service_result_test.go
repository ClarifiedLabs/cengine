package storagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

func liveResultServer(t *testing.T, f *lifecycleFixture) *LifecycleServer {
	t.Helper()
	cfg := f.sc
	cfg.SuccessorGrant = a.LifecycleGrant{}
	cfg.SuccessorKey = p.Fingerprint{}
	cfg.RetireGrant = a.LifecycleGrant{}
	s, err := NewLifecycleServer(f.authority, cfg)
	must(t, err)
	return s
}

func TestLifecycleServiceResultTLSReopenAndAppliedReceipt(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	c := lifecycleConnect(t, liveResultServer(t, f), f.cc)
	ctx := context.Background()
	nonce := bytes.Repeat([]byte{1}, 32)
	old, err := c.Result(ctx, f.initial.Grant, nonce)
	must(t, err)
	live, err := c.ServiceResult(ctx, f.initial.Grant, nonce)
	must(t, err)
	if live.OpenRevision != 1 || live.ServiceEpoch != old.ServiceEpoch {
		t.Fatal("wrong initialized open")
	}
	c.Close()
	must(t, f.authority.Close())
	root, err := os.Open(f.rootPath)
	must(t, err)
	defer root.Close()
	f.authority, err = a.OpenLifecycleCurrent(a.Config{Root: root, DeviceID: "lifecycle-control-host-test", BootstrapKey: f.bootstrap.Public().(ed25519.PublicKey), Barrier: func(a.Binding, *os.File) error { return a.ErrBlocked }}, f.initial)
	must(t, err)
	f.sc.ServiceEpoch = f.authority.Epoch()
	f.cc.Hello.ServiceEpoch = f.authority.Epoch()
	binding, err := p.NewServerBinding(p.StoreID(f.initial.Grant.Identity.Store), p.ServiceEpoch(f.authority.Epoch()))
	must(t, err)
	f.sc.Identity = f.issue(f.serverKey, binding)
	c = lifecycleConnect(t, liveResultServer(t, f), f.cc)
	fresh, err := c.ServiceResult(ctx, f.initial.Grant, bytes.Repeat([]byte{2}, 32))
	must(t, err)
	if fresh.ServiceEpoch == live.ServiceEpoch || fresh.OpenRevision != 2 || fresh.ControllerEpoch != 1 || fresh.ControllerKey != f.initial.Grant.NewKey {
		t.Fatal("reopen did not return live E/open anchor")
	}
	// The old result/candidate path deliberately remains strict about applied E.
	_, err = c.Result(ctx, f.initial.Grant, nonce)
	remote(t, err, Unauthorized)
	again, err := c.ServiceResult(ctx, f.initial.Grant, nonce)
	must(t, err)
	if again.OpenRevision != fresh.OpenRevision || again.ServiceEpoch != fresh.ServiceEpoch || bytes.Equal(again.Nonce, fresh.Nonce) {
		t.Fatal("live result cached or changed open anchor")
	}
	must(t, f.authority.Close())
	if _, err = c.ServiceResult(ctx, f.initial.Grant, nonce); err == nil {
		t.Fatal("closed authority returned live result")
	}
}

func TestLifecycleServiceResultTLSPendingAndRetirementFence(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	ctx := context.Background()
	nonce := make([]byte, 32)
	cfg := f.sc
	cfg.RetireGrant = a.LifecycleGrant{}
	pending, err := NewLifecycleServer(f.authority, cfg)
	must(t, err)
	old := lifecycleConnect(t, pending, f.cc)
	initial, err := old.ServiceResult(ctx, f.initial.Grant, nonce)
	must(t, err)
	next := lifecycleConnect(t, pending, f.successor())
	_, err = next.ServiceResult(ctx, f.takeover.Grant, nonce)
	remote(t, err, Unauthorized)
	_, err = next.Takeover(ctx, f.takeover)
	must(t, err)
	_, err = old.ServiceResult(ctx, f.initial.Grant, nonce)
	remote(t, err, Unauthorized)
	// The service retains this endpoint/session after reconciliation, so the
	// actually promoted successor must work without replacing its transport.
	live, err := next.ServiceResult(ctx, f.takeover.Grant, nonce)
	must(t, err)
	if live.OpenRevision != initial.OpenRevision || live.ControllerEpoch != 2 {
		t.Fatal("takeover rewrote open anchor")
	}
	must(t, pending.ArmRetirement(f.retire.Grant))
	_, err = next.ServiceResult(ctx, f.takeover.Grant, nonce)
	remote(t, err, Blocked)
	must(t, next.Retire(ctx, f.retire))
	_, err = next.ServiceResult(ctx, f.takeover.Grant, nonce)
	remote(t, err, Blocked)
	_, err = next.Result(ctx, f.retire.Grant, nonce)
	must(t, err)
}

func TestLifecycleServiceResultTLSExactRequest(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	c := lifecycleConnect(t, liveResultServer(t, f), f.cc)
	for _, change := range []func(*a.LifecycleGrant){
		func(g *a.LifecycleGrant) { g.ID = id(t) }, func(g *a.LifecycleGrant) { g.Serial++ },
		func(g *a.LifecycleGrant) { g.Identity.Store = id(t) }, func(g *a.LifecycleGrant) { g.Identity.Generation++ },
		func(g *a.LifecycleGrant) { g.Identity.Binding = g.NewKey }, func(g *a.LifecycleGrant) { g.ExpectedEpoch++ },
		func(g *a.LifecycleGrant) { g.NewKey = f.takeover.Grant.NewKey }, func(g *a.LifecycleGrant) { g.Operation = a.LifecycleRetire },
	} {
		g := f.initial.Grant
		change(&g)
		_, err := c.call(context.Background(), lifecycleRequest{ServiceResult: &lifecycleResultRequest{g, make([]byte, 32)}})
		remote(t, err, Unauthorized)
	}
	for _, n := range []int{0, 31, 33} {
		_, err := c.call(context.Background(), lifecycleRequest{ServiceResult: &lifecycleResultRequest{f.initial.Grant, make([]byte, n)}})
		remote(t, err, Unauthorized)
	}
	_, err := c.ServiceResult(context.Background(), f.initial.Grant, make([]byte, 32))
	must(t, err)
}

func TestLifecycleServiceResultTLSRejectsCorruptResponse(t *testing.T) {
	for _, kind := range []string{"nonce", "grant", "store", "generation", "binding", "epoch", "controller", "key", "revision", "counter", "receipt", "error", "missing"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			left, right := tcpPair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer left.Close()
				cfg, err := p.ServerTLSConfig(f.sc.Identity, f.sc.ClientRoot)
				if err != nil {
					return
				}
				conn := tls.Server(left, cfg)
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if conn.HandshakeContext(context.Background()) != nil {
					return
				}
				var h LifecycleHello
				if readFrame(conn, &h, 4096, &budget{}) != nil {
					return
				}
				if writeFrame(conn, h, 4096, &budget{}) != nil {
					return
				}
				var q lifecycleRequest
				if readFrame(conn, &q, lifecycleFrameBytes, &budget{}) != nil {
					return
				}
				g := q.ServiceResult.Grant
				r := a.LifecycleServiceResult{Identity: h.Identity, Grant: g, Nonce: bytes.Clone(q.ServiceResult.Nonce), ServiceEpoch: h.ServiceEpoch, ControllerEpoch: h.ControllerEpoch, ControllerKey: g.NewKey, OpenRevision: 1}
				response := lifecycleResponse{ID: q.ID, ServiceResult: &r}
				switch kind {
				case "nonce":
					r.Nonce[0] ^= 1
				case "grant":
					r.Grant.Serial++
				case "store":
					r.Identity.Store = g.ID
					r.Grant.Identity = r.Identity
				case "generation":
					r.Identity.Generation++
					r.Grant.Identity = r.Identity
				case "binding":
					r.Identity.Binding = g.NewKey
					r.Grant.Identity = r.Identity
				case "epoch":
					r.ServiceEpoch = g.ID
				case "controller":
					r.ControllerEpoch++
				case "key":
					r.ControllerKey = f.takeover.Grant.NewKey
				case "revision":
					r.OpenRevision = 0
				case "counter":
					response.ID++
				case "receipt":
					response.Receipt = &a.LifecycleReceipt{Grant: g, Nonce: r.Nonce, ServiceEpoch: r.ServiceEpoch, Revision: 1}
				case "error":
					response.Error = Unauthorized
				case "missing":
					response.ServiceResult = nil
				}
				writeFrame(conn, response, lifecycleFrameBytes, &budget{})
			}()
			client, err := NewLifecycleClient(context.Background(), right, f.cc)
			must(t, err)
			_, err = client.ServiceResult(context.Background(), f.initial.Grant, make([]byte, 32))
			if !errors.Is(err, ErrProtocol) {
				t.Fatal(err)
			}
			client.Close()
			<-done
		})
	}
}

func TestLifecycleServiceResultFixtureProtocolShape(t *testing.T) {
	b, err := os.ReadFile("../../../Tests/Fixtures/storage-bootstrap/lifecycle-service-result-v2.json")
	must(t, err)
	var fixture struct {
		Vectors []struct {
			Value         a.LifecycleServiceResult `json:"value"`
			CanonicalJSON string                   `json:"canonical_json"`
			RequestJSON   string                   `json:"request_json"`
			ResponseJSON  string                   `json:"response_json"`
		} `json:"vectors"`
	}
	must(t, json.Unmarshal(b, &fixture))
	if len(fixture.Vectors) != 2 {
		t.Fatal("fixture missing initialize/takeover vectors")
	}
	for _, v := range fixture.Vectors {
		var q lifecycleRequest
		must(t, strictDecode([]byte(v.RequestJSON), &q))
		var r lifecycleResponse
		must(t, strictDecode([]byte(v.ResponseJSON), &r))
		var value a.LifecycleServiceResult
		must(t, strictDecode([]byte(v.CanonicalJSON), &value))
		if !q.valid() || q.ID != 1 || q.ServiceResult == nil || q.ServiceResult.Grant != v.Value.Grant || !bytes.Equal(q.ServiceResult.Nonce, v.Value.Nonce) || r.ID != 1 || !reflect.DeepEqual(r.ServiceResult, &v.Value) || !reflect.DeepEqual(value, v.Value) {
			t.Fatal("fixture wire shape/correlation")
		}
		for _, bad := range []string{
			strings.Replace(v.ResponseJSON, `"open_revision":18446744073709551615,`, "", 1),
			strings.Replace(v.ResponseJSON, `"open_revision":`, `"open_revision":1,"open_revision":`, 1),
			strings.Replace(v.ResponseJSON, `"open_revision":18446744073709551615`, `"open_revision":null`, 1),
			strings.Replace(v.ResponseJSON, `"controller_epoch":`, `"extra":1,"controller_epoch":`, 1),
		} {
			var badResponse lifecycleResponse
			if strictDecode([]byte(bad), &badResponse) == nil {
				t.Fatal("open response schema", bad)
			}
		}
		for _, mixed := range []lifecycleRequest{
			{ID: 1, ServiceResult: q.ServiceResult, Result: q.ServiceResult},
			{ID: 1, ServiceResult: q.ServiceResult, Takeover: &a.SignedLifecycleGrant{Grant: v.Value.Grant, Signature: make([]byte, 64)}},
			{ID: 1, ServiceResult: q.ServiceResult, Retire: &a.SignedLifecycleGrant{Grant: v.Value.Grant, Signature: make([]byte, 64)}},
		} {
			if mixed.valid() {
				t.Fatal("mixed request union accepted")
			}
		}
	}
}
