//go:build cengine_prepare_early_compat

package preparecompat

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestEarlyA2EmissionOneShotAndUnreleasableSource(t *testing.T) {
	w, err := NewWitness(earlyArm(t, "guest-accepted-before-prepare"))
	if err != nil {
		t.Fatal(err)
	}
	if hold, err := w.acceptPrepare(17); err != nil || !hold {
		t.Fatal("accept", err)
	}
	o := <-w.EarlyObservations()
	if o.RequestSequence != 17 || o.PrepareCommandsSent != 1 || o.PrepareCommandsAccepted != 1 || o.DataBytesWritten != 0 || ValidateEarlyObservation(o) != nil {
		t.Fatal("not actual accepted evidence")
	}
	w.ObservationWritten(context.Canceled)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.acceptPrepare(18); err == nil {
				t.Error("replay")
			}
		}()
	}
	wg.Wait()
	if w.NormalObservationWritten() {
		t.Fatal("early success")
	}
	raw, err := os.ReadFile("early_witness.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "if hold {\n\t\tselect {}\n\t}") {
		t.Fatal("A2 park must have no release arm")
	}
}
func TestEarlyNormalExactPhysicalWriteJoin(t *testing.T) {
	a := earlyArm(t, "normal")
	w, err := NewWitness(a)
	if err != nil {
		t.Fatal(err)
	}
	o := testObservation(t, a)
	o.Version, o.Profile = 2, EarlyProfile
	returned := make(chan error, 1)
	go func() { returned <- w.PublishAndHold(o) }()
	if <-w.Observations() != o {
		t.Fatal("physical mismatch")
	}
	select {
	case <-returned:
		t.Fatal("returned before write")
	default:
	}
	if !w.ObservationWritten(nil) {
		t.Fatal("ack")
	}
	if err := <-returned; err != nil || !w.NormalObservationWritten() {
		t.Fatal("normal", err)
	}
	early, _ := NewWitness(earlyArm(t, "data-partial-frame"))
	o.ArmDigest = early.Digest()
	if early.PublishAndHold(o) == nil {
		t.Fatal("early physical accepted")
	}
}
