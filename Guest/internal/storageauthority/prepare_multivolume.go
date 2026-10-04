package storageauthority

// observeTwoVolumeDrainReply records only a successful production Retire result.
// compatibilityDrainedLocked supplies the receipt after journal commit AND barrier
// clearance. The non-target volume must already be drained; host persistence is
// independently checked by the parent against its durable journal, never inferred
// from elapsed time or from this storage witness.
func (a *Authority) observeTwoVolumeDrainReply(w *PrepareCompatibilityWitness, req RetireRequest, receipt Receipt) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if a.available() != nil || w.owner != a || w.plan.Stage != "vm-two-volume-drain-reply-gap" || w.plan.Epoch != a.s.Epoch || w.plan.Controller != a.s.Controller || len(w.plan.Bindings) != 2 || !w.retirementFinished || !w.snapshot.RetirementStarted || w.snapshot.AcceptedInFlight != 0 || w.snapshot.Receipt == nil || receipt != *w.snapshot.Receipt || req.Operation != w.snapshot.RetireOperation || req.Store != receipt.Store || req.Volume != receipt.Volume || req.Attachment != receipt.Attachment {
		return false
	}
	target := a.s.Attachments[w.plan.Target.Attachment]
	if target.Binding != w.plan.Target || target.Phase != Drained || target.Receipt == nil || *target.Receipt != receipt || target.Retirement != req.Operation {
		return false
	}
	for _, b := range w.plan.Bindings {
		if b == w.plan.Target {
			continue
		}
		first := a.s.Attachments[b.Attachment]
		if first.Binding != b || first.Phase != Drained || first.Receipt == nil || first.Receipt.Revision >= receipt.Revision {
			return false
		}
	}
	if w.snapshot.State != "armed" && w.snapshot.State != "held" {
		return false
	}
	w.snapshot.State = "held"
	// Matching duplicates also remain held: they cannot turn this cut into A8's
	// dropped-reply replay or release the original request.
	return true
}
