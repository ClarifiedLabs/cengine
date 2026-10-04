//go:build linux

package supervisor

import (
	"os"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

// InstallPrepareCompatibility accepts only the private PID1 Session's witness,
// before any managed preparation. Ordinary profiles cannot construct one.
func (s *Supervisor) InstallPrepareCompatibility(w *preparecompat.Witness) error {
	if w == nil || !preparecompat.SupportsArm(w.Arm()) || os.Getpid() != 1 {
		return preparecompat.ErrInvalidFrame
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if !s.managed.boot || !s.managed.configured || s.managed.attempted || s.managed.stopped || s.managed.compatibility != nil {
		return preparecompat.ErrInvalidFrame
	}
	s.managed.compatibility = w
	return nil
}

// sourceAtimeNanos rejects negative/unrepresentable filesystem times without
// wrapping. The carrier does not change or claim persistence of source atimes.
func sourceAtimeNanos(t unix.Timespec) (uint64, error) {
	const max = uint64(1<<63 - 1)
	if t.Sec < 0 || t.Nsec < 0 || t.Nsec >= 1_000_000_000 {
		return 0, preparecompat.ErrInvalidFrame
	}
	seconds, nanos := uint64(t.Sec), uint64(t.Nsec)
	if seconds > max/1_000_000_000 || seconds*1_000_000_000 > max-nanos {
		return 0, preparecompat.ErrInvalidFrame
	}
	return seconds*1_000_000_000 + nanos, nil
}
func (copy *managedCopy) compatibilitySource(source *confinedRoot) error {
	if copy.compatibility == nil {
		return nil
	}
	// Capture each selected attempt afresh before any source enumeration/staging
	// read. Only descriptor-confined stat operations: no O_NOATIME, read, metadata
	// mutation or alternative copy behavior. Exact two-entry vocabulary is checked
	// against the authenticated sealed manifest before publication.
	copy.sourceAtimes = nil
	var root, a, z unix.Stat_t
	if err := unix.Fstat(source.fd, &root); err != nil {
		return err
	}
	if err := unix.Fstatat(source.fd, "a", &a, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := unix.Fstatat(source.fd, "z", &z, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if root.Mode&unix.S_IFMT != unix.S_IFDIR || a.Mode&unix.S_IFMT != unix.S_IFREG || z.Mode&unix.S_IFMT != unix.S_IFREG {
		return preparecompat.ErrInvalidFrame
	}
	r, e1 := sourceAtimeNanos(root.Atim)
	av, e2 := sourceAtimeNanos(a.Atim)
	zv, e3 := sourceAtimeNanos(z.Atim)
	if e1 != nil || e2 != nil || e3 != nil {
		return preparecompat.ErrInvalidFrame
	}
	snapshot := preparecompat.SourceAtimes{Root: r, A: av, Z: zv}
	copy.sourceAtimes = &snapshot
	return nil
}
func (copy *managedCopy) compatibilityManifest(m managedCopyManifest) error {
	if copy.compatibility == nil {
		return nil
	}
	if copy.intent.Phase != a.CopySealed || len(m.Entries) != 2 {
		return preparecompat.ErrInvalidFrame
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if (e.Path != "a" && e.Path != "z") || seen[e.Path] || e.Identity.FileType != unix.S_IFREG {
			return preparecompat.ErrInvalidFrame
		}
		seen[e.Path] = true
	}
	return nil
}
func (copy *managedCopy) compatibilityPublished(m managedCopyManifest, name string) error {
	if copy.compatibility == nil {
		return nil
	}
	// CLEANING first emits returning, sealed first-child evidence of this
	// attempt's source atimes, then continues to the storage-owned hold. Private
	// BOUND and root-synced VM cuts retain their separate checkpoint paths.
	if copy.compatibility.IsVM() && copy.compatibility.Arm().CaseName != "vm-cleaning-transaction-removed" {
		return copy.compatibility.ValidateIntent(copy.intent)
	}
	// A4-A6 own storage evidence, not a guest physical observation. If the
	// selected storage hook was missed, fail here without awaiting a nonexistent
	// guest observer and without manufacturing successful PREPARE.
	if !copy.compatibility.RequiresGuestObservation() && !copy.compatibility.IsIO() {
		return preparecompat.ErrInvalidFrame
	}
	if copy.sourceAtimes == nil || name != "a" || copy.compatibilityManifest(m) != nil {
		return preparecompat.ErrInvalidFrame
	}
	// These are genuine authority IdentityAt controls after the real synchronized
	// exclusive rename, not path/stat substitutes or a synthesized manifest.
	root, err := copy.identity("")
	if err != nil {
		return err
	}
	transaction, err := copy.identity(confinedCopyTransactionName)
	if err != nil {
		return err
	}
	published, err := copy.identity("a")
	if err != nil {
		return err
	}
	staged, err := copy.identity(confinedCopyTransactionName + "/" + confinedCopyStagingName + "/z")
	if err != nil {
		return err
	}
	for _, e := range m.Entries {
		if e.Path == "a" && e.Identity != published || e.Path == "z" && e.Identity != staged {
			return preparecompat.ErrInvalidFrame
		}
	}
	// IO arms use their authenticated errno checkpoint, never the A7 hold.
	// Keep the physical/owner validation that Observation performs for A7.
	if copy.compatibility.IsIO() {
		if root != copy.intent.Root.Root || transaction != copy.intent.Transaction {
			return preparecompat.ErrInvalidFrame
		}
		return copy.compatibility.ValidateIntent(copy.intent)
	}
	observation, err := copy.compatibility.Observation(copy.intent, root, transaction, published, staged, *copy.sourceAtimes)
	if err != nil {
		return err
	}
	return copy.compatibility.PublishAndHold(observation)
}

// Never turn a selected fixture mismatch into successful PREPARE completion.
func (copy *managedCopy) finishWithoutPublication() error {
	if copy.compatibility != nil {
		return preparecompat.ErrInvalidFrame
	}
	return copy.finish()
}
