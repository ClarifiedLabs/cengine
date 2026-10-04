//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"io"
	"os"
	"path"
	"sort"

	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

type copyCleanupEntry struct {
	Path     string
	Identity a.Ext4ObjectV1
}

func openCopyManifest(transaction int) (*os.File, a.Ext4ObjectV1, error) {
	fd, err := copyPinAt(transaction, "manifest.json", unix.O_RDONLY|unix.O_NOATIME|unix.O_NONBLOCK)
	if err != nil {
		return nil, a.Ext4ObjectV1{}, err
	}
	f := os.NewFile(uintptr(fd), "copy-manifest")
	st, err := stat(fd)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > maxCopyManifestBytes || st.Nlink != 1) {
		err = unix.EINVAL
	}
	var identity a.Ext4ObjectV1
	if err == nil {
		identity, err = ext4Identity(fd)
	}
	if err != nil {
		f.Close()
		return nil, identity, err
	}
	return f, identity, nil
}
func (s *Session) copyTransaction(intent a.CopyIntent) (int, error) {
	fd, err := copyPinAt(int(s.root.Fd()), copyTransactionPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if err != nil {
		return -1, err
	}
	got, err := ext4Identity(fd)
	if err == nil && got != intent.Transaction {
		err = unix.ESTALE
	}
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
func (s *Session) authenticateCopyManifest(guard *a.Guard, intent a.CopyIntent, seal bool) (a.CopyIntent, error) {
	fd, err := s.copyTransaction(intent)
	if err != nil {
		return a.CopyIntent{}, err
	}
	defer unix.Close(fd)
	// BOUND is private prepublication ownership, not authorization derived from
	// unsealed bytes. Even a present malformed manifest cannot block safe abort.
	if !seal && intent.Phase == a.CopyBound {
		return guard.AuthenticateCopyManifest(intent.ID, intent.Transaction, nil)
	}
	f, _, err := openCopyManifest(fd)
	if err != nil {
		return a.CopyIntent{}, err
	}
	defer f.Close()
	digest, size, err := digestCopyManifest(f)
	if err != nil {
		return a.CopyIntent{}, err
	}
	if seal {
		if err = guard.SealCopyManifestDigest(intent.ID, intent.Transaction, digest, size); err != nil {
			return a.CopyIntent{}, err
		}
		return guard.InspectCopy(intent.ID, intent.Root)
	}
	return guard.AuthenticateCopyManifestDigest(intent.ID, intent.Transaction, digest, size)
}

func copyRootCleanup(fd int) (a.CopyCleanupV1, error) {
	st, err := stat(fd)
	if err != nil {
		return a.CopyCleanupV1{}, err
	}
	return a.CopyCleanupV1{UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, ATimeSeconds: st.Atim.Sec, ATimeNanos: uint32(st.Atim.Nsec), MTimeSeconds: st.Mtim.Sec, MTimeNanos: uint32(st.Mtim.Nsec)}, nil
}
func optionalCopyIdentity(fd int, name string) (a.Ext4ObjectV1, error) {
	identity, err := copyIdentityAt(fd, name)
	if errors.Is(err, unix.ENOENT) {
		return a.Ext4ObjectV1{}, nil
	}
	return identity, err
}
func (s *Session) startCopyCleanup(guard *a.Guard, intent a.CopyIntent) (result a.CopyIntent, resultErr error) {
	if intent.Phase == a.CopyCleaning {
		return intent, nil
	}
	if intent.Phase != a.CopyBound && intent.Phase != a.CopySealed {
		return a.CopyIntent{}, unix.EINVAL
	}
	fd, err := s.copyTransaction(intent)
	if err != nil {
		return a.CopyIntent{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	metadata, err := copyRootCleanup(int(s.root.Fd()))
	if err != nil {
		return a.CopyIntent{}, err
	}
	metadata.Manifest, err = optionalCopyIdentity(fd, "manifest.json")
	if err == nil {
		metadata.Staging, err = optionalCopyIdentity(fd, "staging")
	}
	if err != nil {
		return a.CopyIntent{}, err
	}
	if metadata.Staging != (a.Ext4ObjectV1{}) && metadata.Staging.FileType != unix.S_IFDIR {
		return a.CopyIntent{}, unix.ESTALE
	}
	probe := intent
	probe.Cleanup = metadata
	// Authenticate and preflight the complete owned subtree before recording
	// deletion authority. No earlier object is deleted on late uncertainty.
	if _, err = s.snapshotCopyCleanup(guard, probe, fd); err != nil {
		return a.CopyIntent{}, err
	}
	if err = s.registry.syncFilesystem(s.binding.Volume, int(s.root.Fd())); err != nil {
		return a.CopyIntent{}, err
	}
	return guard.StartCopyCleanup(intent.ID, intent.Transaction, metadata)
}

func (s *Session) snapshotCopyCleanup(guard *a.Guard, intent a.CopyIntent, fd int) (result []copyCleanupEntry, resultErr error) {
	var expected map[string]a.Ext4ObjectV1
	manifest, err := optionalCopyIdentity(fd, "manifest.json")
	if err != nil {
		return nil, err
	}
	if manifest != (a.Ext4ObjectV1{}) && manifest != intent.Cleanup.Manifest {
		return nil, unix.ESTALE
	}
	if intent.ManifestSize != 0 && manifest != (a.Ext4ObjectV1{}) {
		f, identity, err := openCopyManifest(fd)
		if err != nil {
			return nil, err
		}
		defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
		if identity != intent.Cleanup.Manifest {
			return nil, unix.ESTALE
		}
		digest, size, err := digestCopyManifest(f)
		if err != nil {
			return nil, err
		}
		if _, err = guard.AuthenticateCopyManifestDigest(intent.ID, intent.Transaction, digest, size); err != nil {
			return nil, err
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		expected, err = copyExpectedEntries(f, intent)
		if err != nil {
			return nil, err
		}
	} else if intent.ManifestSize != 0 && intent.Phase != a.CopyCleaning {
		return nil, unix.ESTALE
	}
	var entries []copyCleanupEntry
	var walk func(int, string, int) error
	walk = func(parent int, relative string, depth int) error {
		if depth > 255 || len(entries) > maxCopyEntries+4 {
			return unix.E2BIG
		}
		// Caller owns parent; duplicate for ReadDir so closing cannot consume it.
		duplicate, err := dup(parent)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(duplicate), "copy-cleanup-directory")
		children, err := file.ReadDir(-1)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		sort.Slice(children, func(i, j int) bool {
			// Reverse deletion removes manifest last, after all staging children.
			if relative == "" && (children[i].Name() == "manifest.json" || children[j].Name() == "manifest.json") {
				return children[i].Name() == "manifest.json"
			}
			return children[i].Name() < children[j].Name()
		})
		for _, child := range children {
			name := child.Name()
			rel := name
			if relative != "" {
				rel = relative + "/" + name
			}
			identity, err := copyIdentityAt(parent, name)
			if err != nil {
				return err
			}
			if rel == "manifest.json" && identity != intent.Cleanup.Manifest {
				return unix.ESTALE
			}
			if rel == "staging" && identity != intent.Cleanup.Staging {
				return unix.ESTALE
			}
			if intent.ManifestSize != 0 {
				switch rel {
				case "manifest.json":
					if identity != intent.Cleanup.Manifest {
						return unix.ESTALE
					}
				case "staging":
					if manifest == (a.Ext4ObjectV1{}) || identity != intent.Cleanup.Staging {
						return unix.ESTALE
					}
				default:
					if manifest == (a.Ext4ObjectV1{}) || expected[rel] != identity {
						return unix.ESTALE
					}
				}
			}
			entries = append(entries, copyCleanupEntry{Path: copyTransactionPath + "/" + rel, Identity: identity})
			if identity.FileType == unix.S_IFDIR {
				next, err := copyPinAt(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
				if err != nil {
					return err
				}
				err = walk(next, rel, depth+1)
				unix.Close(next)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err = walk(fd, "", 0); err != nil {
		return nil, err
	}
	if manifest == (a.Ext4ObjectV1{}) && intent.Phase == a.CopyCleaning && intent.Cleanup.Manifest != (a.Ext4ObjectV1{}) && len(entries) != 0 {
		return nil, unix.ESTALE
	}
	return entries, nil
}

func (s *Session) removeCopyCleanupEntry(guard *a.Guard, intent a.CopyIntent, entry copyCleanupEntry) error {
	root := int(s.root.Fd())
	current, err := copyIdentityAt(root, entry.Path)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if current != entry.Identity {
		return unix.ESTALE
	}
	parent := path.Dir(entry.Path)
	fd, err := copyPinAt(root, parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	flags := 0
	if entry.Identity.FileType == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
	}
	if err = unix.Unlinkat(fd, path.Base(entry.Path), flags); err != nil {
		return err
	}
	point := "child-unlink-parent-sync"
	if entry.Path == copyTransactionPath+"/manifest.json" {
		point = "manifest-unlink-parent-sync"
	}
	if err = s.prepareCleanupIO(guard, intent.ID, point); err != nil {
		return err
	}
	return s.syncFile(fd, false)
}

// Faults remain private to an exact owned FINISH boundary, never syncOps-wide.
func (s *Session) prepareCleanupIO(guard *a.Guard, id a.ID, point string) error {
	err := guard.PrepareCompatibilityCleanupIO(id, point)
	if err != nil {
		s.registry.latch(s.binding.Volume, err)
	}
	return err
}

func (s *Session) restoreCopyCleanupRoot(guard *a.Guard, intent a.CopyIntent) error {
	metadata := intent.Cleanup
	fd := int(s.root.Fd())
	st, err := stat(fd)
	if err != nil {
		return err
	}
	// Cleanup never changes ownership/mode/xattrs. A mismatch is uncertainty,
	// not permission to chown (which would erase capabilities) or rewrite ACLs.
	if st.Uid != metadata.UID || st.Gid != metadata.GID || st.Mode&07777 != metadata.Mode {
		return unix.ESTALE
	}
	if err = unix.UtimesNanoAt(fd, "", []unix.Timespec{{Sec: metadata.ATimeSeconds, Nsec: int64(metadata.ATimeNanos)}, {Sec: metadata.MTimeSeconds, Nsec: int64(metadata.MTimeNanos)}}, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	if err = s.prepareCleanupIO(guard, intent.ID, "root-restoration-syncfs"); err != nil {
		return err
	}
	return s.registry.syncFilesystem(s.binding.Volume, fd)
}
func (s *Session) finishCopyCleanup(guard *a.Guard, intent a.CopyIntent) error {
	if intent.Phase == a.CopyBegun {
		identity, err := optionalCopyIdentity(int(s.root.Fd()), copyTransactionPath)
		if err != nil {
			return err
		}
		if identity != (a.Ext4ObjectV1{}) {
			return unix.EBUSY
		}
		if err = s.registry.syncFilesystem(s.binding.Volume, int(s.root.Fd())); err != nil {
			return err
		}
		return guard.FinishCopy(intent.ID)
	}
	if intent.Phase != a.CopyCleaning {
		return unix.EBUSY
	}
	fd, err := s.copyTransaction(intent)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err == nil {
		entries, snapshotErr := s.snapshotCopyCleanup(guard, intent, fd)
		unix.Close(fd)
		if snapshotErr != nil {
			return snapshotErr
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if err = s.removeCopyCleanupEntry(guard, intent, entries[i]); err != nil {
				return err
			}
		}
		current, err := copyIdentityAt(int(s.root.Fd()), copyTransactionPath)
		if err != nil {
			return err
		}
		if current != intent.Transaction {
			return unix.ESTALE
		}
		if err = unix.Unlinkat(int(s.root.Fd()), copyTransactionPath, unix.AT_REMOVEDIR); err != nil {
			return err
		}
		if err = s.prepareCleanupIO(guard, intent.ID, "transaction-unlink-parent-sync"); err != nil {
			return err
		}
		if err = s.syncFile(int(s.root.Fd()), false); err != nil {
			return err
		}
		if hook := s.registry.copyCleanupCheckpoint; hook != nil {
			if err = hook("transaction-removed-before-root-restore"); err != nil {
				return err
			}
		}
	}
	var syncReplayParent func() error
	if errors.Is(err, unix.ENOENT) {
		// Only the exact staged witness needs this extra replay durability
		// boundary. Ordinary replay retains its existing root-restoration sync.
		syncReplayParent = func() error { return s.syncFile(int(s.root.Fd()), false) }
	}
	if err = guard.PrepareCompatibilityTransactionRemoved(intent.ID, syncReplayParent); err != nil {
		return err
	}
	if err = s.restoreCopyCleanupRoot(guard, intent); err != nil {
		return err
	}
	return guard.FinishCopy(intent.ID)
}
