//go:build linux || darwin

package storageauthority

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const copyTransactionName = ".cengine-copyup-transaction"

// ProvisionCopyTransaction must run under the caller's namespace gate. identify
// reads real ext4 identity from the borrowed FD, without closing it or reentering
// authority. The private deterministic name belongs exclusively to this durable
// intent; no pathname in the public volume ever establishes ownership.
//
// InitialCaptured distinguishes a legitimate all-zero metadata snapshot from no
// snapshot. Initial is durable before mkdir/publication and never recaptured on
// resume. The trusted server restores it on pre-manifest rollback. This API does
// not restore metadata or delete evidence itself.
func (g *Guard) ProvisionCopyTransaction(id ID, identify func(int) (Ext4ObjectV1, error)) (CopyIntent, error) {
	a, err := g.copyAuthority()
	if err != nil {
		return CopyIntent{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	intent, err := g.ownedCopyLocked(id)
	if err != nil {
		return CopyIntent{}, err
	}
	var result CopyIntent
	err = g.withPrepareFilesystemIO("provision", CopyOperationProvision, id, func() error {
		var provisionErr error
		result, provisionErr = g.provisionCopyTransactionLocked(intent, identify)
		return provisionErr
	})
	return result, err
}

func (g *Guard) provisionCopyTransactionLocked(intent CopyIntent, identify func(int) (Ext4ObjectV1, error)) (CopyIntent, error) {
	a := g.token.owner
	if identify == nil {
		return CopyIntent{}, ErrInvalid
	}
	if intent.Phase != CopyBegun && intent.Phase != CopyBound && intent.Phase != CopySealed {
		return CopyIntent{}, ErrConflict
	}
	root := a.roots[intent.Root.Volume]
	if root == nil {
		return CopyIntent{}, ErrConflict
	}
	rootID, err := identity(root)
	if err != nil {
		return CopyIntent{}, err
	}
	privateID, err := identity(a.j.dir)
	if err != nil {
		return CopyIntent{}, err
	}
	if rootID != a.s.Volumes[intent.Root.Volume].Root || rootID.Device != privateID.Device {
		return CopyIntent{}, ErrConflict
	}
	name := "copy-" + string(intent.ID)

	// Public objects are only accepted after a private provisioning bind. Even
	// an empty public directory in BEGUN is foreign evidence, never adopted.
	public, err := volumeDirectory(root, copyTransactionName)
	if err == nil {
		defer public.Close()
		if intent.Phase == CopyBegun || !intent.InitialCaptured {
			return CopyIntent{}, ErrConflict
		}
		if err = absent(a.j.dir, name); err != nil {
			return CopyIntent{}, err
		}
		object, _, e := identifyCopyDirectory(public, rootID.Device, identify)
		if e != nil {
			return CopyIntent{}, e
		}
		if object != intent.Transaction {
			return CopyIntent{}, ErrConflict
		}
		// Covers a crash after rename but before either parent fsync.
		if err = a.syncCopyPublication(root); err != nil {
			return CopyIntent{}, err
		}
		g.token.publishedCopy = intent.ID
		return intent, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return CopyIntent{}, err
	}
	if intent.Phase == CopySealed {
		return CopyIntent{}, ErrConflict
	}

	if !intent.InitialCaptured {
		// Direct Bind remains supported, but cannot manufacture private provenance.
		if intent.Phase != CopyBegun {
			return CopyIntent{}, ErrConflict
		}
		if err = absent(a.j.dir, name); err != nil {
			return CopyIntent{}, err
		}
		var st unix.Stat_t
		if err = unix.Fstat(int(root.Fd()), &st); err != nil {
			return CopyIntent{}, err
		}
		intent.Initial = copyInitialMetadata(&st)
		intent.InitialCaptured = true
		next := a.clone()
		next.Copy.Intents[intent.Root.Volume] = intent
		if err = a.commit(next); err != nil {
			return CopyIntent{}, err
		}
		if err = a.j.step("copy-initial-durable", func() error { return nil }); err != nil {
			return CopyIntent{}, a.poison(err)
		}
	}

	private, err := volumeDirectory(a.j.dir, name)
	if errors.Is(err, unix.ENOENT) {
		// A bound object that vanished must not be replaced with a fresh inode.
		if intent.Phase != CopyBegun {
			return CopyIntent{}, ErrConflict
		}
		if err = a.j.step("copy-private-mkdir", func() error { return unix.Mkdirat(int(a.j.dir.Fd()), name, 0700) }); err != nil {
			return CopyIntent{}, a.poison(err)
		}
		private, err = volumeDirectory(a.j.dir, name)
	}
	if err != nil {
		return CopyIntent{}, err
	}
	defer private.Close()
	// Sync before collecting identity/binding; a crash here leaves durable name
	// ownership in BEGUN, which can be resumed only by this exact live intent.
	if err = a.j.step("copy-private-sync", private.Sync); err != nil {
		return CopyIntent{}, a.poison(err)
	}
	if err = a.j.step("copy-private-parent-sync", a.j.dir.Sync); err != nil {
		return CopyIntent{}, a.poison(err)
	}
	object, pinned, err := identifyCopyDirectory(private, rootID.Device, identify)
	if err != nil {
		return CopyIntent{}, err
	}
	if err = a.bindCopyTransactionLocked(intent, object); err != nil {
		return CopyIntent{}, err
	}
	intent = a.s.Copy.Intents[intent.Root.Volume]
	if err = a.j.step("copy-bound-durable", func() error { return nil }); err != nil {
		return CopyIntent{}, a.poison(err)
	}
	if err = g.prepareVMCheckpointLocked("vm-private-bound", intent, CopyOperationProvision); err != nil {
		return CopyIntent{}, err
	}
	if err = exactChild(a.j.dir, name, pinned); err != nil {
		return CopyIntent{}, err
	}
	if err = a.j.step("copy-private-publish", func() error { return renameCopyNoReplace(a.j.dir, name, root, copyTransactionName) }); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return CopyIntent{}, ErrConflict
		}
		return CopyIntent{}, a.poison(err)
	}
	if err = a.syncCopyPublication(root); err != nil {
		return CopyIntent{}, err
	}
	g.token.publishedCopy = intent.ID
	return intent, nil
}

func identifyCopyDirectory(f *os.File, device uint64, identify func(int) (Ext4ObjectV1, error)) (Ext4ObjectV1, RootIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return Ext4ObjectV1{}, RootIdentity{}, err
	}
	if uint64(st.Dev) != device || st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 {
		return Ext4ObjectV1{}, RootIdentity{}, ErrConflict
	}
	object, err := identify(int(f.Fd()))
	if err != nil {
		return Ext4ObjectV1{}, RootIdentity{}, err
	}
	if !validCopyDirectory(object) || object.Inode != uint64(st.Ino) {
		return Ext4ObjectV1{}, RootIdentity{}, ErrConflict
	}
	return object, RootIdentity{uint64(st.Dev), uint64(st.Ino)}, nil
}

func (a *Authority) syncCopyPublication(root *os.File) error {
	if err := a.j.step("copy-public-parent-sync", root.Sync); err != nil {
		return a.poison(err)
	}
	if err := a.j.step("copy-source-parent-sync", a.j.dir.Sync); err != nil {
		return a.poison(err)
	}
	return nil
}
