package storageservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

func serviceHandoff(t *testing.T, f *lifecycleFixture, pending a.LifecycleGrant) a.SignedLifecycleHandoff {
	t.Helper()
	meta, err := f.s.Scope()
	must(t, err)
	r := a.LifecycleHandoffRequest{OperationID: id(t), Predecessor: f.initial.Grant, Pending: pending, ServiceEpoch: meta.Epoch, OpenRevision: meta.OpenRevision}
	b, err := a.LifecycleHandoffSigningBytes(r)
	must(t, err)
	return a.SignedLifecycleHandoff{Request: r, Signature: ed25519.Sign(f.root, b)}
}

func TestLifecycleServiceHandoffActualOutcomeAndLateTLS(t *testing.T) {
	for _, phase := range []string{"unapplied", "applied", "reconciled", "busy-control"} {
		t.Run(phase, func(t *testing.T) {
			f := newLifecycleServiceFixture(t)
			identity := lifecycleCredential(t, f)
			work, workJoin := lifecycleWorkload(t, f.s, identity)
			created := call(t, work, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.cfg.Store, Volume: id(t), Name: "retained"}})
			if phase != "busy-control" {
				work.Close()
				workJoin()
			}
			key, err := p.NewControllerKey()
			must(t, err)
			g := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: f.initial.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: fingerprint(t, key)}
			signed := lifecycleSign(t, f.root, g)
			cert, err := f.s.AuthorizeSuccessor(signed, lifecycleCSR(t, key, f.cfg.Store, 2))
			must(t, err)
			nextIdentity, err := cert.WithKey(key)
			must(t, err)
			late, join := lifecycleConnect(t, f.s, nextIdentity, 2)
			defer func() { late.Close(); join() }()
			if phase == "applied" || phase == "reconciled" {
				_, err = late.Takeover(context.Background(), signed)
				must(t, err)
				identity = nextIdentity
			}
			if phase == "reconciled" {
				must(t, f.s.ReconcileController(lifecycleController(g)))
			}
			handoff := serviceHandoff(t, f, g)
			before, err := f.s.Scope()
			must(t, err)
			data, resources, endpoint := f.s.owner.data, f.s.owner.resources, f.s.endpoint
			result, err := f.s.FenceLifecycleHandoff(handoff, bytes.Repeat([]byte{1}, 32))
			if phase == "busy-control" {
				if !errors.Is(err, a.ErrBusy) || f.s.endpoint != endpoint || f.s.pending != g {
					t.Fatal("busy CONTROL repaired endpoint", err)
				}
				// Fence is already durable even while old CONTROL is draining.
				if _, e := late.Takeover(context.Background(), signed); e == nil {
					t.Fatal("late authenticated takeover escaped busy fence")
				}
				work.Close()
				workJoin()
				result, err = f.s.FenceLifecycleHandoff(handoff, bytes.Repeat([]byte{1}, 32))
			}
			must(t, err)
			must(t, result.Validate())
			after, err := f.s.Scope()
			must(t, err)
			if result.AppliedGrant != before.CurrentGrant || after.Controller != before.Controller || after.Epoch != before.Epoch || after.OpenRevision != before.OpenRevision || f.s.owner.data != data || f.s.owner.resources != resources || f.s.pending != (a.LifecycleGrant{}) || f.s.owner.generation != after.Controller {
				t.Fatal("handoff changed live state or retained stale endpoint")
			}
			if phase != "busy-control" {
				if _, err = late.Takeover(context.Background(), signed); err == nil {
					t.Fatal("late authenticated takeover escaped fence")
				}
			}
			again, err := f.s.FenceLifecycleHandoff(handoff, bytes.Repeat([]byte{2}, 32))
			must(t, err)
			result.Nonce = again.Nonce
			if !reflect.DeepEqual(result, again) {
				t.Fatal("retry changed immutable outcome")
			}
			current, currentJoin := lifecycleWorkload(t, f.s, identity)
			query := call(t, current, c.Request{Query: &c.Empty{}})
			if query.Snapshot.Volumes[created.VolumeReceipt.Volume.ID] != created.VolumeReceipt.Volume {
				t.Fatal("handoff lost workload state")
			}
			current.Close()
			currentJoin()
			fresh, err := p.NewControllerKey()
			must(t, err)
			g.ID, g.Serial, g.ExpectedEpoch, g.NewKey = id(t), 3, after.Controller.Epoch, fingerprint(t, fresh)
			_, err = f.s.AuthorizeSuccessor(lifecycleSign(t, f.root, g), lifecycleCSR(t, fresh, f.cfg.Store, after.Controller.Epoch+1))
			must(t, err)
		})
	}
}

func TestLifecycleServiceHandoffRejectsBeforeEndpointRepair(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	key, err := p.NewControllerKey()
	must(t, err)
	g := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: f.initial.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: fingerprint(t, key)}
	_, err = f.s.AuthorizeSuccessor(lifecycleSign(t, f.root, g), lifecycleCSR(t, key, f.cfg.Store, 2))
	must(t, err)
	handoff := serviceHandoff(t, f, g)
	before, err := f.s.Scope()
	must(t, err)
	endpoint, control := f.s.endpoint, f.s.owner.control
	for _, kind := range []string{"signature", "nonce", "different-pending"} {
		bad, nonce := handoff, make([]byte, 32)
		switch kind {
		case "signature":
			bad.Signature = make([]byte, 64)
		case "nonce":
			nonce = nil
		case "different-pending":
			other := g
			other.ID = id(t)
			bad = serviceHandoff(t, f, other)
		}
		if _, err := f.s.FenceLifecycleHandoff(bad, nonce); err == nil {
			t.Fatal("accepted", kind)
		}
		after, err := f.s.Scope()
		must(t, err)
		if before != after || endpoint != f.s.endpoint || control != f.s.owner.control || f.s.pending != g {
			t.Fatal("rejection repaired or mutated", kind)
		}
	}
}
