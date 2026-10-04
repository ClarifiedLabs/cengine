//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// observedWorkerExit arms the requested admission stage and actually holds it:
// A5 is the admitted-queued cut (real guard, rt.count > 0); A4 is the
// full-frame-before-admit cut (no guard accepted, rt.count == 0).
func observedWorkerExit(t *testing.T, stage string) (*fixture, Binding, *Guard, *PrepareCompatibilityWitness) {
	t.Helper()
	f, v, b, p, w := fullCompatibilityFixture(t, stage)
	var g *Guard
	if stage == "admitted-queued" {
		var err error
		g, err = f.a.Admit(p, v.ID, true)
		must(t, err)
	}
	joined := make(chan struct{})
	go func() {
		f.a.PrepareCompatibilityAdmission(DataHello{Epoch: f.a.Epoch(), Binding: b}, 37, g)
		close(joined)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for w.Snapshot().State != "observed" {
		if time.Now().After(deadline) {
			t.Fatal("no actual cut")
		}
		runtime.Gosched()
	}
	t.Cleanup(func() {
		// Test-only teardown of the held goroutine; production has no exit release.
		w.mu.Lock()
		close(w.release)
		w.mu.Unlock()
		<-joined
		if g != nil {
			g.Release()
		}
	})
	return f, b, g, w
}
func TestWorkerExitAtomicOneShotNeverReleases(t *testing.T) {
	for _, stage := range []string{"admitted-queued", "full-frame-before-admit"} {
		t.Run(stage, func(t *testing.T) {
			_, _, _, w := observedWorkerExit(t, stage)
			token := w.Snapshot().ReleaseToken
			inFlight := uint32(1)
			if stage == "full-frame-before-admit" {
				inFlight = 0
			}
			var successes atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Go(func() {
					snapshot, err := w.ClaimWorkerExit(stage, token)
					if err == nil {
						successes.Add(1)
						if snapshot.AcceptedInFlight != inFlight || snapshot.Sequence != 37 || snapshot.RetirementStarted {
							t.Error("not live cut")
						}
					}
				})
			}
			wg.Wait()
			if successes.Load() != 1 {
				t.Fatal("not one shot", successes.Load())
			}
			if w.Release(stage, token) == nil {
				t.Fatal("claim permitted release")
			}
			select {
			case <-w.release:
				t.Fatal("claim released admission")
			default:
			}
		})
	}
}
func TestWorkerExitCrossStageClaimRejected(t *testing.T) {
	for _, stage := range []string{"admitted-queued", "full-frame-before-admit"} {
		t.Run(stage, func(t *testing.T) {
			_, _, _, w := observedWorkerExit(t, stage)
			other := "full-frame-before-admit"
			if stage == "full-frame-before-admit" {
				other = "admitted-queued"
			}
			if _, err := w.ClaimWorkerExit(other, w.Snapshot().ReleaseToken); err == nil {
				t.Fatal("cross-stage claim")
			}
			select {
			case <-w.release:
				t.Fatal("rejected claim released gate")
			default:
			}
		})
	}
}
func TestWorkerExitRequiresCurrentLiveAuthority(t *testing.T) {
	for _, stage := range []string{"admitted-queued", "full-frame-before-admit"} {
		kinds := []string{"token", "stage", "epoch", "controller", "binding", "phase", "retirement", "zero-count", "not-observed", "not-admitted", "zero-sequence", "retirement-started", "foreign-witness", "fault"}
		if stage == "admitted-queued" {
			kinds = append(kinds, "released-guard")
		}
		for _, kind := range kinds {
			t.Run(stage+"/"+kind, func(t *testing.T) {
				f, b, g, w := observedWorkerExit(t, stage)
				token := w.Snapshot().ReleaseToken
				claimStage := stage
				f.a.mu.Lock()
				w.mu.Lock()
				switch kind {
				case "token":
					token = "wrong"
				case "stage":
					if claimStage == "admitted-queued" {
						claimStage = "full-frame-before-admit"
					} else {
						claimStage = "admitted-queued"
					}
				case "epoch":
					w.plan.Epoch = mustID(t)
				case "controller":
					w.plan.Controller.Epoch++
				case "binding":
					w.plan.Target.Launch = mustID(t)
				case "phase":
					rec := f.a.s.Attachments[b.Attachment]
					rec.Phase = Retiring
					f.a.s.Attachments[b.Attachment] = rec
				case "retirement":
					rec := f.a.s.Attachments[b.Attachment]
					rec.Retirement = mustID(t)
					f.a.s.Attachments[b.Attachment] = rec
				case "zero-count":
					w.plan.Target.Attachment = mustID(t)
				case "not-observed":
					w.snapshot.State = "armed"
				case "not-admitted":
					w.snapshot.Admitted = !w.snapshot.Admitted
				case "zero-sequence":
					w.snapshot.Sequence = 0
				case "retirement-started":
					w.snapshot.RetirementStarted = true
				case "foreign-witness":
					f.a.prepareCompatibility.Store(nil)
				case "fault":
					f.a.fault = ErrBlocked
				}
				w.mu.Unlock()
				f.a.mu.Unlock()
				if kind == "released-guard" {
					g.Release()
				}
				if _, err := w.ClaimWorkerExit(claimStage, token); err == nil {
					t.Fatal("claimed stale authority")
				}
				select {
				case <-w.release:
					t.Fatal("rejected claim released guard")
				default:
				}
			})
		}
	}
}

// A4 is the full-frame-before-admit hold: the admission was never admitted and
// no carrier was accepted, so an actual held A4 claim requires rt.count == 0
// and !Admitted; any accepted in-flight or admitted cut is stale.
func TestWorkerExitA4RejectsAdmittedOrAcceptedInFlight(t *testing.T) {
	for _, kind := range []string{"admitted", "accepted-in-flight", "both"} {
		t.Run(kind, func(t *testing.T) {
			f, b, _, w := observedWorkerExit(t, "full-frame-before-admit")
			f.a.mu.Lock()
			w.mu.Lock()
			switch kind {
			case "admitted":
				w.snapshot.Admitted = true
			case "accepted-in-flight":
				f.a.runtime[b.Attachment].count = 1
			case "both":
				w.snapshot.Admitted = true
				f.a.runtime[b.Attachment].count = 1
			}
			w.mu.Unlock()
			f.a.mu.Unlock()
			if _, err := w.ClaimWorkerExit("full-frame-before-admit", w.Snapshot().ReleaseToken); err == nil {
				t.Fatal("claimed non-empty A4 hold")
			}
			select {
			case <-w.release:
				t.Fatal("rejected claim released gate")
			default:
			}
		})
	}
}

// A5 is the admitted-queued hold: an actual claim requires the admitted cut and
// rt.count > 0; an empty runtime is a stale authority, never an A4 claim.
func TestWorkerExitA5RejectsDrainedOrNotAdmitted(t *testing.T) {
	for _, kind := range []string{"not-admitted", "empty-runtime"} {
		t.Run(kind, func(t *testing.T) {
			f, b, _, w := observedWorkerExit(t, "admitted-queued")
			f.a.mu.Lock()
			w.mu.Lock()
			switch kind {
			case "not-admitted":
				w.snapshot.Admitted = false
			case "empty-runtime":
				f.a.runtime[b.Attachment].count = 0
			}
			w.mu.Unlock()
			f.a.mu.Unlock()
			if _, err := w.ClaimWorkerExit("admitted-queued", w.Snapshot().ReleaseToken); err == nil {
				t.Fatal("claimed drained A5 hold")
			}
			select {
			case <-w.release:
				t.Fatal("rejected claim released gate")
			default:
			}
		})
	}
}
