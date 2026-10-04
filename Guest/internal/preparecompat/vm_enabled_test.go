//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package preparecompat

import (
	"context"
	"testing"
)

func TestVMCleaningPhysicalWriteReturnsWithoutPrepareSuccess(t *testing.T) {
	for _, outcome := range []string{"written", "failed-write", "canceled-before-publication"} {
		t.Run(outcome, func(t *testing.T) {
			arm := vmArm(t, "vm-cleaning-transaction-removed")
			w, err := NewWitness(arm)
			if err != nil || !w.RequiresGuestObservation() {
				t.Fatal("CLEANING physical witness", err)
			}
			o := testObservation(t, arm)
			o.Version, o.Profile = 3, FullProfile
			raw, err := CanonicalJSON(o)
			decoded, decodeErr := DecodeObservation(raw)
			if err != nil || decodeErr != nil || decoded != o || ValidateObservationForArm(decoded, arm) != nil {
				t.Fatal("bounded first-child carrier", err, decodeErr)
			}
			if w.ObservationWritten(nil) {
				t.Fatal("successful write before publication")
			}
			if outcome == "canceled-before-publication" && !w.ObservationWritten(context.Canceled) {
				t.Fatal("early observer failure")
			}
			returned := make(chan error, 1)
			go func() { returned <- w.PublishAndHold(o) }()
			if got := <-w.Observations(); got != o {
				t.Fatal("source atimes/identity changed")
			}
			if outcome != "canceled-before-publication" {
				select {
				case <-returned:
					t.Fatal("publication continued before observer write")
				default:
				}
				var writeErr error
				if outcome == "failed-write" {
					writeErr = context.Canceled
				}
				if !w.ObservationWritten(writeErr) {
					t.Fatal("observer result rejected")
				}
			}
			err = <-returned
			if (err == nil) != (outcome == "written") || w.delivered.Load() != (outcome == "written") || w.NormalObservationWritten() {
				t.Fatal("CLEANING return must not authorize PREPARE", err)
			}
			if w.ObservationWritten(nil) || w.PublishAndHold(o) == nil {
				t.Fatal("duplicate write/publication")
			}
			select {
			case <-w.Observations():
				t.Fatal("duplicate physical event")
			default:
			}
		})
	}
}

func TestVMRootHoldRejectsEarlyCheckpointAndCannotRelease(t *testing.T) {
	arm := vmArm(t, "vm-root-synced-before-cleanup")
	w, err := NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	o := testObservation(t, arm)
	o.Version = 3
	o.Profile = FullProfile
	if w.PublishAndHold(o) == nil {
		t.Fatal("A7 is not root-synced evidence")
	}
	o.Stage = arm.CaseName
	returned := make(chan error, 1)
	go func() { returned <- w.PublishAndHold(o) }()
	if got := <-w.Observations(); got.Stage != arm.CaseName {
		t.Fatal(got)
	}
	if !w.ObservationWritten(context.Canceled) {
		t.Fatal("observer result")
	}
	if w.PublishAndHold(o) == nil || w.NormalObservationWritten() {
		t.Fatal("duplicate/success")
	}
	select {
	case <-returned:
		t.Fatal("observer loss released hold")
	default:
	}
}
