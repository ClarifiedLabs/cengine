package supervisor

import "fmt"

// finalizeConfinedCopy retains the rollback journal through publication sync.
// The caller holds the initialization lock and supplies pinned-root operations.
// Success includes the final root timestamps and namespace cleanup in an fsync;
// it does not make journal removal and timestamp restoration crash-atomic.
func finalizeConfinedCopy(setTimes, syncRoot, removeJournal func() error, rollback func(error) error) error {
	// Test timestamp support before discarding rollback authority. Ownership,
	// mode and xattrs have already been applied while the journal is present.
	if err := setTimes(); err != nil {
		return rollback(fmt.Errorf("apply copy-up root times: %w", err))
	}
	if err := syncRoot(); err != nil {
		return rollback(fmt.Errorf("sync published copy-up entries and metadata: %w", err))
	}
	if err := removeJournal(); err != nil {
		return fmt.Errorf("remove committed copy-up transaction: %w", err)
	}
	// Removing the journal directory changes the root mtime. Restore through
	// the retained descriptor, including when the copied mode is restrictive.
	if err := setTimes(); err != nil {
		return fmt.Errorf("restore committed copy-up root times: %w", err)
	}
	if err := syncRoot(); err != nil {
		return fmt.Errorf("sync committed copy-up transaction: %w", err)
	}
	return nil
}
