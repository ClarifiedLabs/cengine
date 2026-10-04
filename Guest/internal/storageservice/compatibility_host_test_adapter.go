//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import d "dev.cengine/guest/internal/storageserver"

// InstallCompatibilityHostTestExecutor is available only in the explicit host
// test build, before any transport starts. No principal or authority is exposed.
func (s *commonService) InstallCompatibilityHostTestExecutor() (*d.CompatibilityHostTestExecutor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.controlActive != 0 || s.dataActive != 0 {
		return nil, ErrConfiguration
	}
	if err := s.authority.InstallCompatibilityHostTestBarrier(); err != nil {
		return nil, err
	}
	return s.data.InstallCompatibilityHostTestExecutor()
}
