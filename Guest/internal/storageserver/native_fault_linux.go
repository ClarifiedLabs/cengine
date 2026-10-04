//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storageserver

import (
	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
)

// The wrapper cannot fabricate an executor, principal, guard, root, or result.
// It only rejects a mismatched operation at the exact selected sequence, then
// delegates to the original factory and real Session.Dispatch unchanged.
func (s *Server) InstallNativeFault(witness *a.NativeFaultWitness) (*m.NativeFaultCounter, error) {
	p := witness.Plan()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections) != 0 {
		return nil, a.ErrBusy
	}
	// PKI construction already binds the authority, before any Serve call.
	// Only that exact owner and immutable PKI S/E may install its witness.
	if s.pki == nil || s.pki.Store != p.Store || s.pki.ServiceEpoch != p.Epoch ||
		!witness.ReadyForInstall(s.authority) {
		return nil, a.ErrConflict
	}
	// The registry also rejects duplicate installs and retains its worker after
	// session closure: an empty connection set is not proof of an unused server.
	counter, err := s.resources.registry.InstallNativeFault(witness)
	if err != nil {
		return nil, err
	}
	real := s.factory
	s.factory = func(g *a.Guard, principal *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		e, root, err := real(g, principal, b)
		if err != nil {
			return nil, root, err
		}
		return &nativeFaultExecutor{e, p, b}, root, nil
	}
	return counter, nil
}

type nativeFaultExecutor struct {
	real    executor
	plan    a.NativeFaultPlan
	binding a.Binding
}

func (e *nativeFaultExecutor) Dispatch(g *a.Guard, r w.Request) (m.Result, error) {
	if e.plan.Stage <= a.NativePostCreateNamespace && e.plan.Matches(e.binding) && r.Sequence == e.plan.Sequence {
		valid := false
		switch body := r.Body.(type) {
		case w.FsyncRequest:
			valid = e.plan.Stage == a.NativeDataFsync && !body.DataOnly
		case w.CreateRequest:
			valid = e.plan.Stage == a.NativePostCreateNamespace
		}
		if !valid {
			return m.Result{}, a.ErrInvalid
		}
	}
	return e.real.Dispatch(g, r)
}
