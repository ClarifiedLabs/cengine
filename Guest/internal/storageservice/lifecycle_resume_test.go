package storageservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

// Component coverage only: temp directories do not qualify the native Linux
// clean/no-replay probe or the still-uncoupled read-only promotion boundary.
func TestLifecycleResumeServiceTLSAndReconcile(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "genesis"
		if empty {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			f := newLifecycleServiceFixture(t)
			before, err := f.s.Ready()
			must(t, err)
			must(t, f.s.Close())
			if empty {
				root, err := os.Open(t.TempDir())
				must(t, err)
				defer root.Close()
				f.cfg.Root = root
			}
			key, err := p.NewControllerKey()
			must(t, err)
			g := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: f.initial.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: fingerprint(t, key)}
			takeover := lifecycleSign(t, f.root, g)
			f.cfg.Now = f.cfg.Now.Truncate(time.Second)
			signed := a.SignedLifecycleResumeOpen{Request: a.LifecycleResumeOpenRequest{
				OperationID: g.ID, Original: f.initial.Grant, Takeover: takeover,
				Launch:         a.LifecycleColdLaunch{ShimLaunchUUID: id(t), SpecSHA256: strings.Repeat("a", 64), InitramfsSHA256: strings.Repeat("b", 64), Ext4UUID: "cccccccc-cccc-1ccc-accc-cccccccccccc", Bytes: 104857600},
				NowUnixSeconds: uint64(f.cfg.Now.Unix()), LifetimeSeconds: uint64(f.cfg.Lifetime / time.Second),
			}}
			msg, err := a.LifecycleResumeOpenSigningBytes(signed.Request)
			must(t, err)
			signed.Signature = ed25519.Sign(f.root, msg)
			var prior map[string]string
			if !empty {
				prior = lifecycleServiceJournal(t, f)
			}
			for _, invalid := range []string{"time", "lifetime", "store", "signature"} {
				cfg, bad := f.cfg, signed
				switch invalid {
				case "time":
					cfg.Now = cfg.Now.Add(time.Second)
				case "lifetime":
					cfg.Lifetime += time.Second
				case "store":
					cfg.Store = id(t)
				case "signature":
					bad.Signature = make([]byte, ed25519.SignatureSize)
				}
				got, err := ResumeOpenAndTakeover(cfg, bad)
				if got != nil || err == nil {
					if got != nil {
						got.Close()
					}
					t.Fatalf("accepted %s", invalid)
				}
				if empty {
					entries, err := os.ReadDir(f.cfg.Root.Name())
					must(t, err)
					if len(entries) != 0 {
						t.Fatal("rejected resume wrote empty layout")
					}
				} else if !reflect.DeepEqual(prior, lifecycleServiceJournal(t, f)) {
					t.Fatal("rejected resume changed genesis")
				}
			}
			f.s, err = ResumeOpenAndTakeover(f.cfg, signed)
			must(t, err)
			f.key = key
			ready, err := f.s.Ready()
			must(t, err)
			meta, err := f.s.Scope()
			must(t, err)
			wantRevision := uint64(2)
			if empty {
				wantRevision = 1
			}
			if ready.Controller != (a.Controller{Epoch: 2, Key: g.NewKey}) || meta.CurrentGrant != g || meta.OpenRevision != wantRevision || ready.ServiceEpoch == before.ServiceEpoch || bytes.Equal(ready.TLSRootDER, before.TLSRootDER) || bytes.Equal(ready.ServerDER, before.ServerDER) || ready.ServerKey == before.ServerKey {
				t.Fatal("resume did not install actual successor state/TLS")
			}
			identity := lifecycleCredential(t, f)
			client, join := lifecycleConnect(t, f.s, identity, 2)
			defer func() { client.Close(); join() }()
			journal := lifecycleServiceJournal(t, f)
			for i := 0; i < 2; i++ {
				got, err := client.Takeover(context.Background(), takeover)
				must(t, err)
				if got != ready.Controller {
					t.Fatal("wrong idempotent takeover")
				}
				must(t, f.s.ReconcileController(got))
				receipt, err := client.Result(context.Background(), g, bytes.Repeat([]byte{byte(i + 1)}, 32))
				must(t, err)
				if receipt.ServiceEpoch != ready.ServiceEpoch || receipt.Grant != g {
					t.Fatal("wrong actual result")
				}
			}
			if !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
				t.Fatal("retry/reconcile changed registry")
			}
			workload, workJoin := lifecycleWorkload(t, f.s, identity)
			reply := call(t, workload, c.Request{Query: &c.Empty{}})
			if reply.Snapshot.Controller != ready.Controller {
				t.Fatal("workload controller not installed")
			}
			workload.Close()
			workJoin()
			client.Close()
			join()
			must(t, f.s.Close())
			journal = lifecycleServiceJournal(t, f)
			retry, err := ResumeOpenAndTakeover(f.cfg, signed)
			if retry != nil || !errors.Is(err, a.ErrLifecycleResumeAlreadyApplied) {
				if retry != nil {
					retry.Close()
				}
				t.Fatalf("retry: %v", err)
			}
			if !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
				t.Fatal("constructor retry changed retained evidence")
			}
		})
	}
}
