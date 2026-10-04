package storagecontrol

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

func TestLifecycleRetirementArmValidationAndImmutability(t *testing.T) {
	for _, successor := range []bool{false, true} {
		name := "current"
		if successor {
			name = "successor"
		}
		t.Run(name, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			cfg := f.sc
			cfg.RetireGrant = a.LifecycleGrant{}
			grant := f.retire.Grant
			if !successor {
				grant.ExpectedEpoch, grant.NewKey = 1, f.initial.Grant.NewKey
			}
			server, err := NewLifecycleServer(f.authority, cfg)
			must(t, err)
			previous := cfg.CurrentGrant
			if successor {
				previous = cfg.SuccessorGrant
			}
			for _, change := range []func(*a.LifecycleGrant){
				func(g *a.LifecycleGrant) { *g = a.LifecycleGrant{} },
				func(g *a.LifecycleGrant) { g.Operation = a.LifecycleTakeover },
				func(g *a.LifecycleGrant) { g.Identity.Store = id(t) },
				func(g *a.LifecycleGrant) { g.Identity.Generation++ },
				func(g *a.LifecycleGrant) { g.Identity.Binding = g.NewKey },
				func(g *a.LifecycleGrant) { g.ExpectedEpoch = 3 },
				func(g *a.LifecycleGrant) { g.NewKey = a.Fingerprint(pkiPin(t, f.serverKey).String()) },
				func(g *a.LifecycleGrant) { g.Serial = previous.Serial },
				func(g *a.LifecycleGrant) { g.ID = previous.ID },
			} {
				bad := grant
				change(&bad)
				if err := server.ArmRetirement(bad); !errors.Is(err, ErrConfiguration) {
					t.Fatalf("invalid arm: %v", err)
				}
				seeded := cfg
				seeded.RetireGrant = bad
				if bad != (a.LifecycleGrant{}) {
					if _, err := NewLifecycleServer(f.authority, seeded); !errors.Is(err, ErrConfiguration) {
						t.Fatalf("constructor validation diverged: %v", err)
					}
				}
				if server.retirement() != (a.LifecycleGrant{}) {
					t.Fatal("invalid grant armed")
				}
			}
			must(t, server.ArmRetirement(grant))
			must(t, server.ArmRetirement(grant))
			changed := grant
			changed.ID = id(t)
			for _, other := range []a.LifecycleGrant{changed, {}, f.initial.Grant} {
				if err := server.ArmRetirement(other); !errors.Is(err, a.ErrConflict) {
					t.Fatalf("replaced/unarmed terminal grant: %v", err)
				}
			}
			cfg.Limits = server.config.Limits
			if !reflect.DeepEqual(cfg, server.config) || server.retirement() != grant {
				t.Fatal("arm changed frozen config")
			}
			cfg.RetireGrant = grant
			seeded, err := NewLifecycleServer(f.authority, cfg)
			must(t, err)
			must(t, seeded.ArmRetirement(grant))
			if err := seeded.ArmRetirement(changed); !errors.Is(err, a.ErrConflict) {
				t.Fatal("replaced constructor arm", err)
			}
		})
	}
}

func TestLifecycleRetirementArmLiveTLSAndConcurrentRepeats(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	cfg := f.sc
	cfg.RetireGrant = a.LifecycleGrant{}
	server, err := NewLifecycleServer(f.authority, cfg)
	must(t, err)
	old := lifecycleConnect(t, server, f.cc)
	next := lifecycleConnect(t, server, f.successor())
	ctx := context.Background()
	_, err = next.Takeover(ctx, f.takeover)
	must(t, err)
	remote(t, next.Retire(ctx, f.retire), Unauthorized)
	_, err = next.Result(ctx, f.retire.Grant, make([]byte, 32))
	remote(t, err, Unauthorized)
	// One writer races real TLS Result readers. Exact repeats cannot allocate a
	// grant history or replace the sole arm. The race suite checks publication.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 64; i++ {
			if err := server.ArmRetirement(f.retire.Grant); err != nil {
				t.Error(err)
			}
		}
	}()
	for i := 0; i < 64; i++ {
		_, err = next.Result(ctx, f.takeover.Grant, bytes.Repeat([]byte{byte(i)}, 32))
		must(t, err)
	}
	wg.Wait()
	bad := f.retire
	bad.Signature = make([]byte, 64)
	remote(t, next.Retire(ctx, bad), Unauthorized) // Authority still checks ROOT.
	_, err = next.Result(ctx, f.retire.Grant, make([]byte, 32))
	remote(t, err, Unauthorized) // Arm is not applied retirement.
	must(t, next.Retire(ctx, f.retire))
	for i := 0; i < 2; i++ {
		nonce := bytes.Repeat([]byte{byte(i + 1)}, 32)
		r, err := next.Result(ctx, f.retire.Grant, nonce)
		must(t, err)
		if r.Grant != f.retire.Grant || !bytes.Equal(r.Nonce, nonce) {
			t.Fatal("cached or mismatched result")
		}
	}
	_, err = next.Result(ctx, f.takeover.Grant, make([]byte, 32))
	remote(t, err, Unauthorized)
	_, err = old.Result(ctx, f.initial.Grant, make([]byte, 32))
	remote(t, err, Unauthorized)
	_, err = old.call(ctx, lifecycleRequest{Retire: &f.retire}) // bypass client epoch precheck
	remote(t, err, Unauthorized)
	if server.config.RetireGrant != (a.LifecycleGrant{}) || server.config.SuccessorKey == (p.Fingerprint{}) {
		t.Fatal("frozen config changed")
	}
	t.Log("same pre-arm TLS successor: takeover -> arm -> signed retire -> two fresh terminal results; old grants refused")
}
