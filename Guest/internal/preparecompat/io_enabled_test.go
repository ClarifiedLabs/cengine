//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package preparecompat

import (
	"context"
	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
	"testing"
)

func TestIOWitnessExactFirstOwnerAndObserverAck(t *testing.T) {
	for _, errno := range []string{"eio", "enospc"} {
		for _, failed := range []bool{false, true} {
			arm := fullArm(t, "io-"+errno+"-root-fsync")
			w, err := NewWitness(arm)
			if err != nil {
				t.Fatal(err)
			}
			base := fullStorageObservation(t, fullStorageArm(t, "transaction-published-bind-reply-lost"))
			intent := base.Bound.Intent
			intent.Phase = a.CopySealed
			if !w.IsIO() || !w.IsWorkloadIO() || !w.RequiresGuestObservation() || w.NormalObservationWritten() {
				t.Fatal("selection")
			}
			if w.InjectIO("unmatched", a.CopyIntent{}) != nil {
				t.Fatal("unmatched")
			}
			wrong := intent
			wrong.Epoch = a.ID(arm.RequestID)
			if w.InjectIO("root-fsync", wrong) == nil {
				t.Fatal("foreign")
			}
			result := make(chan error, 1)
			go func() { result <- w.InjectIO("root-fsync", intent) }()
			o := <-w.IOObservations()
			if ValidateIOObservation(o) != nil || o.CopyIntent != string(intent.ID) {
				t.Fatal(o)
			}
			raw, _ := CanonicalJSON(o)
			if _, err := DecodeIOObservation(raw); err != nil {
				t.Fatal(err)
			}
			select {
			case <-result:
				t.Fatal("before ACK")
			default:
			}
			var ack error
			if failed {
				ack = context.Canceled
			}
			if !w.ObservationWritten(ack) {
				t.Fatal("ACK")
			}
			got := <-result
			expected := error(unix.EIO)
			if errno == "enospc" {
				expected = unix.ENOSPC
			}
			if failed {
				expected = ErrInvalidFrame
			}
			if got != expected || w.NormalObservationWritten() {
				t.Fatal(got, expected)
			}
			if w.InjectIO("root-fsync", intent) != nil || w.ObservationWritten(nil) {
				t.Fatal("second fault/ACK")
			}
		}
	}
}
