package preparecompat

import a "dev.cengine/guest/internal/storageauthority"

// These three single-volume cuts extend the signed carrier, not RTM-096's
// acceptance denominator. No selector enables a release or successful PREPARE.
func isVMCase(stage string) bool {
	switch stage {
	case "vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed":
		return true
	}
	return false
}
func (w *Witness) IsVM() bool {
	return w != nil && w.arm.Profile == FullProfile && isVMCase(w.arm.CaseName)
}
func physicalStage(arm Arm) string {
	if arm.Profile == FullProfile && arm.CaseName == "vm-root-synced-before-cleanup" {
		return arm.CaseName
	}
	return "first-child-published"
}
func validCheckpointIntent(stage string, i a.CopyIntent) bool {
	if stage != "vm-cleaning-transaction-removed" {
		return validBoundIntent(i)
	}
	if i.Phase != a.CopyCleaning || i.ManifestSize == 0 || i.ManifestSize > 64<<20 || i.ManifestDigest == [32]byte{} {
		return false
	}
	c := i.Cleanup
	manifest, e1 := ObjectFromAuthority(c.Manifest)
	staging, e2 := ObjectFromAuthority(c.Staging)
	if e1 != nil || e2 != nil || manifest.FileType != 32768 || staging.FileType != 16384 || c.Mode & ^uint32(07777) != 0 || c.UID == ^uint32(0) || c.GID == ^uint32(0) || c.ATimeNanos >= 1e9 || c.MTimeNanos >= 1e9 {
		return false
	}
	// All four objects coexist in this volume's CLEANING provenance. Compare
	// inode numbers, not full handles: changing generation/type cannot unalias.
	seen := make(map[uint64]bool, 4)
	for _, inode := range []uint64{i.Root.Root.Inode, i.Transaction.Inode, c.Manifest.Inode, c.Staging.Inode} {
		if seen[inode] {
			return false
		}
		seen[inode] = true
	}
	i.Phase, i.ManifestSize, i.ManifestDigest, i.Cleanup = a.CopyBound, 0, [32]byte{}, a.CopyCleanupV1{}
	return validBoundIntent(i)
}
