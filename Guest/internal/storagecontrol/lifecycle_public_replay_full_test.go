//go:build cengine_prepare_full_compat

package storagecontrol

import (
	"context"
	"crypto/tls"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	"testing"
	"time"
)

func TestLifecyclePublicReplayRequiresOnlyCorrelatedRemoteUnauthorized(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("mixed profiles disabled")
	}
	for _, kind := range []string{"unauthorized", "counter", "zero", "extra-controller", "extra-ok", "other-error", "eof", "cancel", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			old := f.takeover
			g := old.Grant
			g.ID = id(t)
			g.ExpectedEpoch = 2
			g.Serial++
			g.NewKey = f.initial.Grant.NewKey
			pending := lifecycleSign(t, f.bootstrap, g)
			cc := f.cc
			cc.Hello.ControllerEpoch = 3
			binding, err := p.NewControllerBinding(p.StoreID(g.Identity.Store), 3)
			must(t, err)
			cc.Identity = f.issue(f.controllerKey, binding)
			cc.Limits, err = lifecycleLimits(Limits{})
			must(t, err)
			cc.Limits.OperationTimeout = 100 * time.Millisecond
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
				var hello LifecycleHello
				if readFrame(conn, &hello, 4096, &budget{}) != nil {
					return
				}
				if writeFrame(conn, hello, 4096, &budget{}) != nil {
					return
				}
				var q lifecycleRequest
				if readFrame(conn, &q, lifecycleFrameBytes, &budget{}) != nil {
					return
				}
				response := lifecycleResponse{ID: q.ID, Error: Unauthorized}
				switch kind {
				case "counter":
					response.ID++
				case "zero":
					response.ID = 0
				case "extra-controller":
					response.Controller = &a.Controller{Epoch: 2, Key: old.Grant.NewKey}
				case "extra-ok":
					response.OK = &Empty{}
				case "other-error":
					response.Error = Conflict
				case "eof":
					return
				case "timeout":
					time.Sleep(200 * time.Millisecond)
					return
				}
				_ = writeFrame(conn, response, lifecycleFrameBytes, &budget{})
			}()
			t.Cleanup(func() { right.Close(); left.Close(); <-done })
			client, err := NewLifecycleClient(t.Context(), right, cc)
			must(t, err)
			ctx := t.Context()
			if kind == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = ReplaySignedLifecycleTakeover(ctx, client, pending, old)
			if (err == nil) != (kind == "unauthorized") {
				t.Fatalf("%s: %v", kind, err)
			}
			client.Close()
		})
	}
}

func TestLifecyclePublicReplayMixedProfilesRefuse(t *testing.T) {
	if pc.CurrentProfile() == pc.FullProfile {
		t.Skip("single full profile")
	}
	if ReplaySignedLifecycleTakeover(t.Context(), nil, a.SignedLifecycleGrant{}, a.SignedLifecycleGrant{}) == nil {
		t.Fatal("mixed profile admitted replay")
	}
}
