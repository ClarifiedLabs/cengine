//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storagecontrol

import (
	"context"
	a "dev.cengine/guest/internal/storageauthority"
	"errors"
	"os"
	"sync/atomic"
	"testing"
)

func TestStorageCompatibilityA8ActualControlDropSameOperationRetry(t *testing.T) {
	var barriers atomic.Int32
	f := fixtureFor(t, Limits{}, func(_ a.Binding, root *os.File) error {
		if err := root.Sync(); err != nil {
			return err
		}
		barriers.Add(1)
		return nil
	})
	client := f.client()
	volume := id(t)
	call(t, client, Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: volume, Name: "prepare"}})
	b, _ := f.binding(volume, id(t))
	call(t, client, Request{ReservePrepare: &a.ReserveRequest{Operation: id(t), Prepare: b.Prepare, Attachments: []a.Binding{b}}})
	call(t, client, Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: b}})
	witness, err := f.authority.InstallPrepareCompatibility(a.PrepareCompatibilityPlan{Stage: "drain-durable-reply-lost", Epoch: f.authority.Epoch(), Controller: a.Controller{Epoch: 1, Key: f.initial.Grant.NewKey}, Target: b, Bindings: []a.Binding{b}, RuntimeAttachments: []a.ID{id(t)}})
	must(t, err)
	request := a.RetireRequest{Operation: id(t), Store: f.store, Volume: volume, Attachment: b.Attachment, Launch: b.Launch}
	_, err = client.Call(context.Background(), Request{Retire: &request})
	var remote *RemoteError
	if err == nil || errors.As(err, &remote) {
		t.Fatal("expected lost TLS reply, not authority error", err)
	}
	client.Close()
	cut := witness.Snapshot()
	if cut.State != "observed" || cut.Receipt == nil || cut.RetireOperation != request.Operation || cut.ReceiptReplayCount != 0 || barriers.Load() != 1 {
		t.Fatal("not actual postbarrier receipt", cut)
	}
	receipt := *cut.Receipt
	// Reconnect the CURRENT controller and retry its original durable operation.
	client = f.client()
	reply := call(t, client, Request{Retire: &request})
	if reply.Receipt == nil || *reply.Receipt != receipt {
		t.Fatal("same-operation receipt changed")
	}
	final := witness.Snapshot()
	if final.State != "finished" || final.ReceiptReplayCount != 1 || *final.Receipt != receipt || barriers.Load() != 1 {
		t.Fatal("retry facts", final)
	}
	// A different operation must not be counted as the original reply replay.
	request.Operation = id(t)
	call(t, client, Request{Retire: &request})
	if witness.Snapshot().ReceiptReplayCount != 1 {
		t.Fatal("unrelated operation counted")
	}
	if witness.Release("drain-durable-reply-lost", final.ReleaseToken) == nil {
		t.Fatal("A8 release")
	}
}
