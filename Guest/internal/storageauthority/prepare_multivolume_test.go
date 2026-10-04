//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTwoVolumeRealDrainReplyGap(t *testing.T) {
	f := newFixture(t, nil)
	v1, v2 := f.volume("first"), f.volume("second")
	b1, _ := f.binding(v1, PrepareRole, ReadWrite, mustID(t))
	b2, _ := f.binding(v2, PrepareRole, ReadWrite, b1.Prepare)
	b2.Container, b2.Launch = b1.Container, b1.Launch
	bindings := []Binding{b1, b2}
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{Operation: mustID(t), Prepare: b1.Prepare, Attachments: bindings}))
	for _, b := range bindings {
		must(t, f.a.RegisterAttachment(f.control, RegisterRequest{Operation: mustID(t), Binding: b}))
	}
	plan := PrepareCompatibilityPlan{Stage: "vm-two-volume-drain-reply-gap", Epoch: f.a.Epoch(), Controller: f.a.s.Controller, Target: b2, Bindings: bindings, RuntimeAttachments: []ID{mustID(t), mustID(t)}}
	bad := plan
	bad.Bindings = bindings[:1]
	if _, err := f.a.InstallPrepareCompatibility(bad); err == nil {
		t.Fatal("single-volume arm accepted")
	}
	w, err := f.a.InstallPrepareCompatibility(plan)
	must(t, err)
	req1 := RetireRequest{mustID(t), b1.Store, b1.Volume, b1.Attachment, b1.Launch}
	req2 := RetireRequest{mustID(t), b2.Store, b2.Volume, b2.Attachment, b2.Launch}
	if f.a.observeTwoVolumeDrainReply(w, req2, Receipt{}) {
		t.Fatal("early observation")
	}
	first, err := f.a.Retire(context.Background(), f.control, req1)
	must(t, err)
	if f.a.PrepareCompatibilityRetireReply(req1, first) {
		t.Fatal("held first reply")
	}
	second, err := f.a.Retire(context.Background(), f.control, req2)
	must(t, err)
	if w.Snapshot().State != "armed" {
		t.Fatal("observed before reply boundary")
	}
	if _, err := os.Stat(filepath.Join(f.path, ".cengine-storage-authority", barrierName)); !os.IsNotExist(err) {
		t.Fatal("barrier not cleared", err)
	}
	wrong := req2
	wrong.Operation = mustID(t)
	if f.a.observeTwoVolumeDrainReply(w, wrong, second) {
		t.Fatal("wrong operation")
	}
	altered := second
	altered.Revision++
	if f.a.observeTwoVolumeDrainReply(w, req2, altered) {
		t.Fatal("altered receipt")
	}
	done := make(chan struct{})
	go func() { f.a.PrepareCompatibilityRetireReply(req2, second); close(done) }()
	deadline := time.Now().Add(time.Second)
	for w.Snapshot().State != "held" {
		if time.Now().After(deadline) {
			t.Fatal("no held reply")
		}
		time.Sleep(time.Millisecond)
	}
	snapshot := w.Snapshot()
	if *snapshot.Receipt != second || snapshot.RetireOperation != req2.Operation || snapshot.ReceiptReplayCount != 0 {
		t.Fatal("lost exact receipt", snapshot)
	}
	if w.Release(plan.Stage, snapshot.ReleaseToken) == nil {
		t.Fatal("crash hold released")
	}
	if !f.a.observeTwoVolumeDrainReply(w, req2, second) {
		t.Fatal("matching duplicate bypassed hold")
	}
	select {
	case <-done:
		t.Fatal("original reply returned")
	default:
	}
	// Reopen is a host journal regression, NOT a physical VM death claim.
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	replay1, err := f.a.Retire(context.Background(), f.control, req1)
	must(t, err)
	replay2, err := f.a.Retire(context.Background(), f.control, req2)
	must(t, err)
	if replay1 != first || replay2 != second {
		t.Fatal("reopen changed original receipts")
	}
	select {
	case <-done:
		t.Fatal("observer/reopen released original reply")
	default:
	}
}
