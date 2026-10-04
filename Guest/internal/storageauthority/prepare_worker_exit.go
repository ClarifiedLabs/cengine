package storageauthority

import "crypto/subtle"

// ClaimWorkerExit atomically claims the actual observed A4/A5 admission hold
// and current live authority. A5 is the admitted-queued cut (admitted,
// rt.count > 0); A4 is the full-frame-before-admit cut (!admitted,
// rt.count == 0, no accepted in-flight). Lock ordering matches Retire/Release;
// no Query or wait occurs here. It is distinct from Release and deliberately
// never closes the admission gate.
func (w *PrepareCompatibilityWitness) ClaimWorkerExit(stage, token string) (PrepareCompatibilitySnapshot, error) {
	if !prepareCompatibilityEnabled() || w == nil || w.owner == nil {
		return PrepareCompatibilitySnapshot{}, ErrUnauthorized
	}
	a := w.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := a.available(); err != nil {
		return PrepareCompatibilitySnapshot{}, err
	}
	rec := a.s.Attachments[w.plan.Target.Attachment]
	rt := a.runtime[w.plan.Target.Attachment]
	admittedStage := stage == "admitted-queued"
	if a.prepareCompatibility.Load() != w || a.s.Epoch != w.plan.Epoch || a.s.Controller != w.plan.Controller || rec.Binding != w.plan.Target || rec.Phase != Active || rec.Retirement != "" || rt == nil || (admittedStage && (rt.count <= 0 || uint64(rt.count) > uint64(^uint32(0)))) || (!admittedStage && rt.count != 0) || (stage != "full-frame-before-admit" && stage != "admitted-queued") || stage != w.plan.Stage || w.snapshot.State != "observed" || w.snapshot.Admitted != admittedStage || w.snapshot.Sequence == 0 || w.snapshot.RetirementStarted || w.workerExitClaimed || subtle.ConstantTimeCompare([]byte(token), []byte(w.snapshot.ReleaseToken)) != 1 {
		return PrepareCompatibilitySnapshot{}, ErrConflict
	}
	w.workerExitClaimed = true
	w.snapshot.AcceptedInFlight = uint32(rt.count)
	return w.snapshot, nil
}
