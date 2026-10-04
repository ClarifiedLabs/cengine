//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import "os"

// InstallCompatibilityHostTestBarrier substitutes host directory fsync for the
// unavailable Linux managed-resource barrier. It is test-tag-only and must run
// before any DATA attachment or witness exists. Guard joining, receipt journal
// commits, and barrier marker clearing remain real authority operations.
func (a *Authority) InstallCompatibilityHostTestBarrier() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.runtime) != 0 || a.prepareCompatibility.Load() != nil {
		return ErrBusy
	}
	a.barrier = func(_ Binding, root *os.File) error { return root.Sync() }
	return nil
}
