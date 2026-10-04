package storageservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

func TestLifecycleColdServiceTLSIdempotentTakeoverAndReconcile(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	before, err := f.s.Ready()
	must(t, err)
	meta, err := f.s.Scope()
	must(t, err)
	must(t, f.s.Close())
	key, err := p.NewControllerKey()
	must(t, err)
	g := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: meta.Identity, Serial: f.initial.Grant.Serial + 1, ExpectedEpoch: meta.Controller.Epoch, NewKey: fingerprint(t, key)}
	takeover := lifecycleSign(t, f.root, g)
	f.cfg.Now = f.cfg.Now.Truncate(time.Second)
	cold := a.SignedLifecycleColdOpen{Request: a.LifecycleColdOpenRequest{
		OperationID:    g.ID,
		Predecessor:    a.LifecycleColdPredecessor{CurrentGrant: meta.CurrentGrant, ServiceEpoch: meta.Epoch, ControllerEpoch: meta.Controller.Epoch, ControllerKey: meta.Controller.Key, OpenRevision: meta.OpenRevision, BootstrapKey: meta.Bootstrap},
		Takeover:       takeover,
		Launch:         a.LifecycleColdLaunch{ShimLaunchUUID: id(t), SpecSHA256: strings.Repeat("a", 64), InitramfsSHA256: strings.Repeat("b", 64), Ext4UUID: "cccccccc-cccc-1ccc-accc-cccccccccccc", Bytes: 104857600},
		NowUnixSeconds: uint64(f.cfg.Now.Unix()), LifetimeSeconds: uint64(f.cfg.Lifetime / time.Second),
	}}
	msg, err := a.LifecycleColdOpenSigningBytes(cold.Request)
	must(t, err)
	cold.Signature = ed25519.Sign(f.root, msg)
	journal := lifecycleServiceJournal(t, f)
	for _, bad := range []Config{func() Config { cfg := f.cfg; cfg.Now = cfg.Now.Add(time.Second); return cfg }(), func() Config { cfg := f.cfg; cfg.Lifetime += time.Second; return cfg }()} {
		service, err := ColdOpenAndTakeover(bad, cold)
		if service != nil || err == nil {
			if service != nil {
				service.Close()
			}
			t.Fatal("accepted unsigned certificate timing")
		}
		if !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
			t.Fatal("invalid timing mutated journal")
		}
	}
	f.s, err = ColdOpenAndTakeover(f.cfg, cold)
	must(t, err)
	f.key = key
	ready, err := f.s.Ready()
	must(t, err)
	current, err := f.s.Scope()
	must(t, err)
	if ready.Controller != (a.Controller{Epoch: 2, Key: g.NewKey}) || current.CurrentGrant != g || ready.ServiceEpoch == before.ServiceEpoch || current.OpenRevision <= meta.OpenRevision || bytes.Equal(ready.TLSRootDER, before.TLSRootDER) || bytes.Equal(ready.ServerDER, before.ServerDER) || ready.ServerKey == before.ServerKey {
		t.Fatal("cold service did not install actual new controller/E/TLS")
	}
	identity := lifecycleCredential(t, f)
	client, join := lifecycleConnect(t, f.s, identity, 2)
	defer func() { client.Close(); join() }()
	journal = lifecycleServiceJournal(t, f)
	bad := takeover
	bad.Signature = bytes.Repeat([]byte{0}, 64)
	if _, err = client.Takeover(context.Background(), bad); err == nil {
		t.Fatal("current retry bypassed ROOT verification")
	}
	bad = lifecycleSign(t, f.root, func() a.LifecycleGrant { changed := g; changed.Serial++; return changed }())
	if _, err = client.Takeover(context.Background(), bad); err == nil {
		t.Fatal("nonexact current grant accepted")
	}
	for i := 0; i < 2; i++ {
		got, err := client.Takeover(context.Background(), takeover)
		must(t, err)
		if got != ready.Controller {
			t.Fatal("wrong retry controller")
		}
		must(t, f.s.ReconcileController(got))
		receipt, err := client.Result(context.Background(), g, bytes.Repeat([]byte{byte(i + 1)}, 32))
		must(t, err)
		if receipt.ServiceEpoch != ready.ServiceEpoch || receipt.Grant != g {
			t.Fatal("wrong actual result")
		}
	}
	if !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
		t.Fatal("idempotent TLS takeover/reconcile changed journal")
	}
	workload, workJoin := lifecycleWorkload(t, f.s, identity)
	response := call(t, workload, c.Request{Query: &c.Empty{}})
	if response.Snapshot.Controller != ready.Controller {
		t.Fatal("workload controller not installed")
	}
	workload.Close()
	workJoin()
	client.Close()
	join()
	must(t, f.s.Close())
	journal = lifecycleServiceJournal(t, f)
	retry, err := ColdOpenAndTakeover(f.cfg, cold)
	if retry != nil || !errors.Is(err, a.ErrLifecycleColdAlreadyApplied) {
		if retry != nil {
			retry.Close()
		}
		t.Fatalf("retry result %v", err)
	}
	if !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
		t.Fatal("constructor retry lost retained evidence")
	}
}
