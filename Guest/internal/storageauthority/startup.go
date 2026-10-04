package storageauthority

// StartupMetadata is public, value-only configuration metadata. It contains no
// maps, attachment state, authority principal, or ability to authorize work.
// Bootstrap is the pinned ROOT public-key fingerprint, not the separate TLS CA.
type StartupMetadata struct {
	Store      Store
	Epoch      ID
	Controller Controller
	Revision   uint64
	Bootstrap  Fingerprint
}

// StartupMetadata returns a detached current constructor/reconciliation view.
// It is never an authenticated Query or proof that a controller is alive.
func (a *Authority) StartupMetadata() (StartupMetadata, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return StartupMetadata{}, err
	}
	return StartupMetadata{a.s.Store, a.s.Epoch, a.s.Controller, a.s.Revision, a.s.Bootstrap}, nil
}
