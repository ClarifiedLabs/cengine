//go:build cengine_native_faulttest

package storageservice

import (
	a "dev.cengine/guest/internal/storageauthority"
	d "dev.cengine/guest/internal/storageserver"
)

// InstallNativeSnapshot101 installs observation only before any transport starts.
// No untagged API, environment switch, credential override or second authority.
func (s *commonService) InstallNativeSnapshot101(targets [2]a.Binding) (*d.NativeSnapshot101Observer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.transportStarted || s.controlActive != 0 || s.dataActive != 0 {
		return nil, ErrConfiguration
	}
	return s.data.InstallNativeSnapshot101(targets)
}

// The only scheduling cut is the closed native Rename/Unlink admission pair.
func (s *commonService) InstallNativeSnapshot101Queue(epoch a.ID, targets [2]a.Binding) (*d.NativeSnapshot101Queue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.transportStarted || s.controlActive != 0 || s.dataActive != 0 {
		return nil, ErrConfiguration
	}
	meta, err := s.authority.StartupMetadata()
	if err != nil {
		return nil, err
	}
	if epoch != meta.Epoch || targets[0].Store != meta.Store.ID || targets[1].Store != meta.Store.ID {
		return nil, ErrConfiguration
	}
	return s.data.InstallNativeSnapshot101Queue(epoch, targets)
}

func (s *LifecycleService) InstallNativeSnapshot101(targets [2]a.Binding) (*d.NativeSnapshot101Observer, error) {
	if !s.valid() {
		return nil, ErrConfiguration
	}
	return s.owner.InstallNativeSnapshot101(targets)
}
func (s *LifecycleService) InstallNativeSnapshot101Queue(epoch a.ID, targets [2]a.Binding) (*d.NativeSnapshot101Queue, error) {
	if !s.valid() {
		return nil, ErrConfiguration
	}
	return s.owner.InstallNativeSnapshot101Queue(epoch, targets)
}
