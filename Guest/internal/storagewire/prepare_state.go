package storagewire

import a "dev.cengine/guest/internal/storageauthority"

// Pending may describe either side of its exact commit. Only an unresolved
// directory tail may replay a COMPLETED intent; ordinary finish stays retired.
func validatePreparePending(v PrepareReply) error {
	phase := v.Intent.Phase
	allowed := false
	switch v.Pending {
	case 0:
		return nil
	case BeginCopy:
		allowed = phase == a.CopyBegun || phase == a.CopyBound || phase == a.CopySealed || phase == a.CopyCleaning
	case BindCopyTransaction:
		allowed = phase == a.CopyBegun || phase == a.CopyBound || phase == a.CopySealed
	case SealManifest:
		allowed = phase == a.CopyBound || phase == a.CopySealed
	case StartCleanup:
		allowed = phase == a.CopyBound || phase == a.CopySealed || phase == a.CopyCleaning
	case RollbackCopy:
		allowed = phase == a.CopySealed || phase == a.CopyCleaning
	case ResumeCopyDirectory:
		allowed = phase == a.CopySealed || phase == a.CopyCleaning || phase == a.CopyCompleted
	case FinishCopy:
		allowed = phase == a.CopyCleaning || (phase == a.CopyBegun && !v.Intent.InitialCaptured)
	}
	if !allowed || v.Intent == (a.CopyIntent{}) || v.Root == (a.CopyRootV1{}) || v.Identity != (a.Ext4ObjectV1{}) {
		return invalid("pending copy operation")
	}
	return nil
}

// Mirrors the authority's private phase invariants at the authenticated wire
// boundary. A valid handle alone cannot turn an impossible state into recovery.
func validatePrepareIntentState(i a.CopyIntent) error {
	zero := a.Ext4ObjectV1{}
	if i.Initial.Manifest != zero || i.Initial.Staging != zero || (!i.InitialCaptured && i.Initial != (a.CopyCleanupV1{})) {
		return invalid("copy initial state")
	}
	bound := i.Transaction != zero
	sealed := i.ManifestSize != 0
	if bound && (i.Transaction.FileType != 0040000 || i.Transaction.Inode == i.Root.Root.Inode) {
		return invalid("copy transaction state")
	}
	if sealed && !bound {
		return invalid("copy unbound seal")
	}
	cleanup := i.Cleanup != (a.CopyCleanupV1{})
	if cleanup || i.Phase == a.CopyCleaning {
		if !bound {
			return invalid("unbound cleanup")
		}
		seen := map[uint64]bool{i.Root.Root.Inode: true, i.Transaction.Inode: true}
		for _, e := range []struct {
			o    a.Ext4ObjectV1
			kind uint32
		}{{i.Cleanup.Manifest, 0100000}, {i.Cleanup.Staging, 0040000}} {
			if e.o == zero {
				continue
			}
			if e.o.FileType != e.kind || seen[e.o.Inode] {
				return invalid("copy cleanup object")
			}
			seen[e.o.Inode] = true
		}
		if sealed && i.Cleanup.Manifest == zero {
			return invalid("copy cleanup missing manifest")
		}
	}
	switch i.Phase {
	case a.CopyBegun:
		if bound || sealed || cleanup {
			return invalid("begun state")
		}
	case a.CopyBound:
		if !bound || sealed || cleanup {
			return invalid("bound state")
		}
	case a.CopySealed:
		if !bound || !sealed || cleanup {
			return invalid("sealed state")
		}
	case a.CopyCleaning:
		if !bound {
			return invalid("cleaning state")
		}
	case a.CopyCompleted:
	default:
		return invalid("copy phase")
	}
	return nil
}
