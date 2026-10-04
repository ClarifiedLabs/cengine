//go:build cengine_prepare_compat

package preparecompat

import (
	"context"
	a "dev.cengine/guest/internal/storageauthority"
	"errors"
	"sync"
	"testing"
)

func TestNormalWitnessImmutableAndWrittenOnce(t *testing.T) {
	arm := vectorArm(t)
	w, err := NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	arm.Mounts[0].Destination = "/changed"
	snapshot := w.Arm()
	snapshot.Credentials[0].Key = "changed"
	if w.Arm().Mounts[1].Destination == "/changed" || w.Arm().Credentials[0].Key == "changed" {
		t.Fatal("mutable witness")
	}
	observation := testObservation(t, w.Arm())
	if w.ObservationWritten(nil) {
		t.Fatal("successful ACK before observation")
	}
	returned := make(chan error, 1)
	go func() { returned <- w.PublishAndHold(observation) }()
	if got := <-w.Observations(); got != observation {
		t.Fatal("normal observation")
	}
	if w.NormalObservationWritten() {
		t.Fatal("completion before ACK")
	}
	select {
	case <-returned:
		t.Fatal("normal returned before write ACK")
	default:
	}
	if !w.ObservationWritten(nil) {
		t.Fatal("write ACK rejected")
	}
	if err := <-returned; err != nil || !w.NormalObservationWritten() {
		t.Fatal("normal write completion", err)
	}
	if w.ObservationWritten(nil) || w.PublishAndHold(observation) == nil {
		t.Fatal("duplicate accepted")
	}
	select {
	case <-w.Observations():
		t.Fatal("duplicate observation")
	default:
	}
}
func TestA7OneWayHoldIgnoresObserverCancellation(t *testing.T) {
	arm := vectorArm(t)
	arm.CaseName = "first-child-published"
	w, err := NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	o := testObservation(t, arm)
	returned := make(chan error, 1)
	go func() { returned <- w.PublishAndHold(o) }()
	observed := <-w.Observations()
	if observed != o {
		t.Fatal("observation")
	}
	if !w.ObservationWritten(errors.New("failed write")) {
		t.Fatal("failure ACK rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	<-ctx.Done()
	// There is intentionally no release and no cleanup wait: the publishing
	// goroutine can end only with the real host test process, just like PID1.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w.PublishAndHold(o) == nil {
				t.Error("duplicate")
			}
		}()
	}
	wg.Wait()
	select {
	case <-returned:
		t.Fatal("hold released")
	default:
	}
	select {
	case <-w.Observations():
		t.Fatal("duplicate observation")
	default:
	}
}
func TestWitnessFullActualIntentComparison(t *testing.T) {
	arm := vectorArm(t)
	w, err := NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	var slot Slot
	var credential Credential
	for _, s := range arm.Slots {
		if s.Attachment == arm.TargetAttachment {
			slot = s
		}
	}
	for _, c := range arm.Credentials {
		if c.Attachment == slot.Attachment {
			credential = c
		}
	}
	i := a.CopyIntent{ID: a.ID(arm.RequestID), Epoch: a.ID(arm.Scope.ServiceEpoch), Owner: a.Binding{Store: a.ID(arm.Scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Prepare: a.ID(arm.Scope.Prepare), Container: a.ContainerID(arm.Scope.Container), Launch: a.ID(arm.Scope.Launch), Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.ReadWrite}, Root: a.CopyRootV1{Store: a.ID(arm.Scope.Store), Volume: a.ID(slot.Volume), BackingUUID: [16]byte{1}, Root: object(1, 16384)}}
	if w.ValidateIntent(i) != nil {
		t.Fatal("actual tuple")
	}
	for _, mutate := range []func(*a.CopyIntent){func(i *a.CopyIntent) { i.Epoch = "wrong" }, func(i *a.CopyIntent) { i.Owner.Key = "wrong" }, func(i *a.CopyIntent) { i.Owner.Container = "wrong" }, func(i *a.CopyIntent) { i.Owner.Launch = "wrong" }, func(i *a.CopyIntent) { i.Owner.Mode = a.ReadOnly }, func(i *a.CopyIntent) { i.Owner.Prepare = "wrong" }, func(i *a.CopyIntent) { i.Root.Root.Handle[0]++ }} {
		bad := i
		mutate(&bad)
		if w.ValidateIntent(bad) == nil {
			t.Fatal("tuple mismatch")
		}
	}
}

func TestNormalWitnessWriteErrorAndCancellationFailClosed(t *testing.T) {
	for _, before := range []bool{false, true} {
		for _, failure := range []error{errors.New("write failure"), context.Canceled} {
			w, err := NewWitness(vectorArm(t))
			if err != nil {
				t.Fatal(err)
			}
			if before && !w.ObservationWritten(failure) {
				t.Fatal("early failure ACK")
			}
			returned := make(chan error, 1)
			go func() { returned <- w.PublishAndHold(testObservation(t, w.Arm())) }()
			<-w.Observations()
			if !before && !w.ObservationWritten(failure) {
				t.Fatal("failure ACK")
			}
			if err := <-returned; err == nil || w.NormalObservationWritten() {
				t.Fatal("failed observer became success")
			}
			if w.ObservationWritten(nil) {
				t.Fatal("failure overwritten")
			}
		}
	}
}
