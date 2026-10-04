package storageauthority

// LifecycleMetadata is detached, constant-size public configuration, never a
// principal, receipt, readiness certificate, or input to an authority operation.
// CurrentGrant is the exact persisted initialize/latest takeover; RetirementGrant
// is zero until terminal intent is persisted. No historical grants are retained.
type LifecycleMetadata struct {
	StartupMetadata
	Identity        LifecycleIdentity
	CurrentGrant    LifecycleGrant
	RetirementGrant LifecycleGrant
	Sealed          bool
	OpenRevision    uint64
}

// LifecycleMetadata permits inspection of a still-live terminal seal, without
// reopening ordinary admission. Closed, poisoned, zero and v1 owners fail closed.
func (a *Authority) LifecycleMetadata() (LifecycleMetadata, error) {
	if a == nil {
		return LifecycleMetadata{}, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return LifecycleMetadata{}, ErrClosed
	}
	if a.fault != nil {
		return LifecycleMetadata{}, ErrBlocked
	}
	if a.s == nil || a.s.Lifecycle == nil {
		return LifecycleMetadata{}, ErrInvalid
	}
	l := a.s.Lifecycle
	m := LifecycleMetadata{
		StartupMetadata: StartupMetadata{a.s.Store, a.s.Epoch, a.s.Controller, a.s.Revision, a.s.Bootstrap},
		Identity:        l.Identity, CurrentGrant: l.Latest.Grant, Sealed: l.Seal != nil,
		OpenRevision: l.OpenRevision,
	}
	if l.Retiring != nil {
		m.RetirementGrant = *l.Retiring
	}
	return m, nil
}
