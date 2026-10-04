package storageauthority

// Called under authority.mu at exactly the durable private BOUND boundary or
// after the trusted FINISH implementation's transaction unlink + parent sync.
// Snapshot uses only witness.mu, so observation never waits on this parked IO.
func (g *Guard) prepareVMCheckpointLocked(stage string, intent CopyIntent, action string) error {
	a := g.token.owner
	w := a.prepareCompatibility.Load()
	if !prepareCompatibilityEnabled() || w == nil || w.plan.Stage != stage {
		return nil
	}
	// Project actual admission state while authority.mu prevents retirement or
	// release from racing the durable checkpoint. Never invent a held count.
	rt := a.runtime[g.token.binding.Attachment]
	rec := a.s.Attachments[g.token.binding.Attachment]
	if rt == nil || rt.count <= 0 || uint64(rt.count) > uint64(^uint32(0)) || rec.Binding != g.token.binding || rec.Phase != Active || rec.Retirement != "" {
		return ErrConflict
	}
	t := a.copyIO
	phase := CopyBound
	if stage == "vm-cleaning-transaction-removed" {
		phase = CopyCleaning
	}
	if (stage != "vm-private-bound" && stage != "vm-cleaning-transaction-removed") || w.owner != a || w.plan.Target != g.token.binding || w.plan.Epoch != a.s.Epoch || w.plan.Controller != a.s.Controller || g.token.released || g.token.epoch != a.s.Epoch || a.available() != nil || t == nil || t.completed || t.guard != g.token || t.record.Epoch != a.s.Epoch || t.record.Controller != a.s.Controller || t.record.Binding != g.token.binding || t.record.Action != action || t.record.Intent != intent.ID || t.record.Sequence == 0 || intent != a.s.Copy.Intents[g.token.binding.Volume] || intent.Owner != w.plan.Target || intent.Phase != phase || !intent.InitialCaptured || !a.validCopyRoot(intent.Root, intent.Owner) || !validCopyDirectory(intent.Transaction) {
		return ErrConflict
	}
	w.mu.Lock()
	if w.snapshot.State != "armed" || w.snapshot.RetirementStarted {
		w.mu.Unlock()
		return ErrConflict
	}
	w.snapshot.State, w.snapshot.Sequence, w.snapshot.Admitted = "observed", t.record.Sequence, true
	w.snapshot.AcceptedInFlight = uint32(rt.count)
	w.snapshot.RetirementStarted = false
	w.snapshot.Bound = &intent
	w.mu.Unlock()
	select {} // no release, deadline, cancellation, EOF or observation ACK
}

// syncReplayParent is supplied only when FINISH found an already-absent
// transaction. Ordinary replay never invokes this witness-only durability step.
func (g *Guard) PrepareCompatibilityTransactionRemoved(id ID, syncReplayParent func() error) error {
	if !prepareCompatibilityEnabled() {
		return nil
	}
	a, err := g.copyAuthority()
	if err != nil {
		return err
	}
	w := a.prepareCompatibility.Load()
	if w == nil || w.plan.Stage != "vm-cleaning-transaction-removed" || w.owner != a || w.plan.Target != g.token.binding || w.plan.Epoch != g.token.epoch {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return err
	}
	if syncReplayParent != nil {
		if err := syncReplayParent(); err != nil {
			return err
		}
	}
	return g.prepareVMCheckpointLocked("vm-cleaning-transaction-removed", intent, CopyOperationFinish)
}
