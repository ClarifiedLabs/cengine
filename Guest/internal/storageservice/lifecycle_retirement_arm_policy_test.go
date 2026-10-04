package storageservice

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

func retirementRemote(t *testing.T, err error, code c.Code) {
	t.Helper()
	var remote *c.RemoteError
	if !errors.As(err, &remote) || remote.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

// Real TCP/TLS clients, real composed authority and ROOT signatures; no fake
// result/barrier and no reconnect between fresh boot, arm and seal. This models
// the persistent child transport, not native audit-token/XPC or VM execution.
func TestLifecycleServicePersistentClientRetirementArm(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		name := "fresh"
		if takeover {
			name = "after-takeover-reconcile"
		}
		t.Run(name, func(t *testing.T) {
			f := newLifecycleServiceFixture(t)
			ctx := context.Background()
			identity := lifecycleCredential(t, f)
			current, join := lifecycleConnect(t, f.s, identity, 1)
			grant := f.initial.Grant
			_, err := current.Result(ctx, grant, bytes.Repeat([]byte{1}, 32))
			must(t, err)
			if takeover {
				key, err := p.NewControllerKey()
				must(t, err)
				next := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: grant.Identity, Serial: grant.Serial + 1, ExpectedEpoch: 1, NewKey: fingerprint(t, key)}
				signed := lifecycleSign(t, f.root, next)
				cert, err := f.s.AuthorizeSuccessor(signed, lifecycleCSR(t, key, f.cfg.Store, 2))
				must(t, err)
				nextIdentity, err := cert.WithKey(key)
				must(t, err)
				successor, nextJoin := lifecycleConnect(t, f.s, nextIdentity, 2)
				controller, err := successor.Takeover(ctx, signed)
				must(t, err)
				endpoint := f.s.endpoint
				must(t, f.s.ReconcileController(controller))
				if f.s.endpoint != endpoint {
					t.Fatal("reconcile replaced live endpoint")
				}
				_, err = current.Result(ctx, grant, make([]byte, 32))
				retirementRemote(t, err, c.Unauthorized)
				current.Close()
				join()
				// Preserved old-current pin still cannot admit a stale idle session.
				r, err := f.s.Ready()
				must(t, err)
				root, err := p.ParseRootDER(r.TLSRootDER)
				must(t, err)
				raw, staleJoin := serve(t, f.s.ServeLifecycle)
				stale, err := c.NewLifecycleClient(ctx, raw, c.LifecycleClientConfig{Identity: identity, ServerRoot: root, ServerKey: r.ServerKey, Hello: c.LifecycleHello{Version: c.LifecycleControlVersion, Identity: grant.Identity, ServiceEpoch: r.ServiceEpoch, ControllerEpoch: 1}})
				if err == nil {
					stale.Close()
					t.Fatal("stale Hello accepted")
				}
				if err = staleJoin(); !errors.Is(err, a.ErrUnauthorized) {
					t.Fatal("stale quota/auth check", err)
				}
				current, join, grant = successor, nextJoin, next
			}
			defer func() { current.Close(); join() }()
			before, err := f.s.Ready()
			must(t, err)
			endpoint := f.s.endpoint
			retirement := a.LifecycleGrant{Operation: a.LifecycleRetire, ID: id(t), Identity: grant.Identity, Serial: grant.Serial + 1, ExpectedEpoch: lifecycleController(grant).Epoch, NewKey: grant.NewKey}
			signed := lifecycleSign(t, f.root, retirement)
			retirementRemote(t, current.Retire(ctx, signed), c.Unauthorized)
			bad := signed
			bad.Signature = make([]byte, 64)
			if err := f.s.AuthorizeRetirement(bad); !errors.Is(err, a.ErrUnauthorized) {
				t.Fatal("ROOT not checked before arm", err)
			}
			retirementRemote(t, current.Retire(ctx, signed), c.Unauthorized)
			must(t, f.s.AuthorizeRetirement(signed))
			must(t, f.s.AuthorizeRetirement(signed))
			changed := retirement
			changed.ID = id(t)
			if err := f.s.AuthorizeRetirement(lifecycleSign(t, f.root, changed)); !errors.Is(err, a.ErrConflict) {
				t.Fatal("replaced terminal arm", err)
			}
			retirementRemote(t, current.Retire(ctx, lifecycleSign(t, f.root, changed)), c.Unauthorized)
			_, err = current.Result(ctx, changed, make([]byte, 32))
			retirementRemote(t, err, c.Unauthorized)
			after, err := f.s.Ready()
			must(t, err)
			if f.s.endpoint != endpoint || !reflect.DeepEqual(before, after) {
				t.Fatal("arming changed endpoint/identity/E/C/pins/metadata")
			}
			_, err = current.Result(ctx, retirement, make([]byte, 32))
			retirementRemote(t, err, c.Unauthorized)                      // arm is not retirement
			retirementRemote(t, current.Retire(ctx, bad), c.Unauthorized) // authority verifies again
			must(t, current.Retire(ctx, signed))
			for i := 1; i <= 2; i++ {
				nonce := bytes.Repeat([]byte{byte(i)}, 32)
				r, err := current.Result(ctx, retirement, nonce)
				must(t, err)
				if r.Grant != retirement || r.ServiceEpoch != before.ServiceEpoch || !bytes.Equal(r.Nonce, nonce) {
					t.Fatal("stale/cached terminal result")
				}
			}
			_, err = current.Result(ctx, grant, make([]byte, 32))
			retirementRemote(t, err, c.Unauthorized)
			if err := current.Retire(ctx, signed); err == nil {
				t.Fatal("sealed owner reused for mutation")
			}
			t.Log("persistent pre-arm client: signed arm -> Retire -> fresh terminal Results; identity/E/C/pins unchanged; old-grant reuse refused")
		})
	}
}
