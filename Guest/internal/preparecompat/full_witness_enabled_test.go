//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package preparecompat

import (
	"context"
	"testing"
)

func TestFullNormalAndA8JoinPhysicalObservation(t *testing.T) {
	for _, name := range []string{"normal", "drain-durable-reply-lost"} {
		for _, failed := range []bool{false, true} {
			arm := fullArm(t, name)
			w, err := NewWitness(arm)
			if err != nil {
				t.Fatal(err)
			}
			o := testObservation(t, arm)
			o.Version = 3
			o.Profile = FullProfile
			returned := make(chan error, 1)
			go func() { returned <- w.PublishAndHold(o) }()
			if got := <-w.Observations(); got != o {
				t.Fatal("physical observation")
			}
			select {
			case <-returned:
				t.Fatal("returned before observer")
			default:
			}
			var writeErr error
			if failed {
				writeErr = context.Canceled
			}
			if !w.ObservationWritten(writeErr) {
				t.Fatal("ack rejected")
			}
			err = <-returned
			if (err == nil) == failed || w.NormalObservationWritten() == failed {
				t.Fatal("normal/A8 write result", name, err)
			}
			if w.PublishAndHold(o) == nil {
				t.Fatal("duplicate publication")
			}
		}
	}
}
func TestFullA7CannotBeReleasedByWriteACK(t *testing.T) {
	arm := fullArm(t, "first-child-published")
	w, err := NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	o := testObservation(t, arm)
	o.Version = 3
	o.Profile = FullProfile
	returned := make(chan error, 1)
	go func() { returned <- w.PublishAndHold(o) }()
	<-w.Observations()
	if !w.ObservationWritten(context.Canceled) {
		t.Fatal("failure ACK")
	}
	if w.PublishAndHold(o) == nil || w.NormalObservationWritten() {
		t.Fatal("duplicate/success")
	}
	select {
	case <-returned:
		t.Fatal("A7 released")
	default:
	}
	// The parked goroutine is owned by the actual host test process until death.
}
func TestFullA4A6DoNotWaitForMissingPhysicalObserver(t *testing.T) {
	for _, name := range []string{"full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost"} {
		arm := fullArm(t, name)
		w, err := NewWitness(arm)
		if err != nil {
			t.Fatal(err)
		}
		if w.RequiresGuestObservation() {
			t.Fatal("storage cut awaiting guest event")
		}
		if w.AcceptPrepare(7) != nil {
			t.Fatal("storage arm rejected before actual hook")
		}
		o := testObservation(t, arm)
		o.Version = 3
		o.Profile = FullProfile
		if w.PublishAndHold(o) == nil || w.NormalObservationWritten() {
			t.Fatal("storage cut accepted physical success")
		}
		select {
		case <-w.Observations():
			t.Fatal("fabricated physical event")
		default:
		}
	}
}
func TestFullA1A3EarlySeams(t *testing.T) {
	before, _ := NewWitness(fullArm(t, "before-prepare-send"))
	if before.AcceptPrepare(1) == nil {
		t.Fatal("A1 reached guest PREPARE")
	}
	accepted, _ := NewWitness(fullArm(t, "guest-accepted-before-prepare"))
	hold, err := accepted.acceptPrepare(9)
	if err != nil || !hold {
		t.Fatal("A2 cut", err)
	}
	o := <-accepted.EarlyObservations()
	if o.Version != 3 || o.Profile != FullProfile || o.RequestSequence != 9 || ValidateEarlyObservation(o) != nil {
		t.Fatal("A2 evidence")
	}
	partial, _ := NewWitness(fullArm(t, "data-partial-frame"))
	if !partial.UsesPartialData() || partial.AcceptPrepare(10) != nil || partial.NormalObservationWritten() {
		t.Fatal("A3 admission")
	}
}
