//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	c "dev.cengine/guest/internal/copycontract"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// copyRollbackPlan owns no descriptors. Construct it completely before changing
// metadata or unlinking anything. Private evidence survives until durable CLEANING.
type copyRollbackPlan struct {
	manifest c.Manifest
	matching map[string]bool
	expected map[string]a.Ext4ObjectV1
	xattrs   []string
}

// PreflightCopyRecovery borrows root. Startup calls this before journal recovery
// or epoch changes, without a live Guard. It must never write, sync, or close root.
func PreflightCopyRecovery(root *os.File, deviceID, action string, intent a.CopyIntent) error {
	_, err := planCopyRecovery(root, deviceID, action, intent)
	return err
}

func validateCopyRecoveryMetadata(m a.CopyCleanupV1) error {
	if m.Mode & ^uint32(07777) != 0 || m.UID == ^uint32(0) || m.GID == ^uint32(0) || m.ATimeNanos >= 1e9 || m.MTimeNanos >= 1e9 {
		return unix.EINVAL
	}
	return nil
}

func verifyCopyRecoveryRoot(root *os.File, deviceID string, intent a.CopyIntent) error {
	if root == nil {
		return unix.EBADF
	}
	expected, err := parseCopyDeviceUUID(deviceID)
	if err != nil {
		return err
	}
	uuid, err := backingUUID(int(root.Fd()))
	if err != nil {
		return err
	}
	if uuid != expected || uuid != intent.Root.BackingUUID {
		return unix.EXDEV
	}
	identity, err := ext4Identity(int(root.Fd()))
	if err != nil {
		return err
	}
	if identity != intent.Root.Root || identity.FileType != unix.S_IFDIR {
		return unix.ESTALE
	}
	return nil
}

func planCopyRecovery(root *os.File, deviceID, action string, intent a.CopyIntent) (plan copyRollbackPlan, result error) {
	if action != a.CopyOperationRollback && action != a.CopyOperationDirectoryTail {
		return plan, unix.EINVAL
	}
	if intent.Phase != a.CopySealed && intent.Phase != a.CopyCleaning && !(action == a.CopyOperationDirectoryTail && intent.Phase == a.CopyCompleted) {
		return plan, unix.EINVAL
	}
	if err := verifyCopyRecoveryRoot(root, deviceID, intent); err != nil {
		return plan, err
	}
	rootFD := int(root.Fd())
	if intent.Phase == a.CopyCompleted {
		identity, err := optionalCopyIdentity(rootFD, copyTransactionPath)
		if err != nil {
			return plan, err
		}
		if identity != (a.Ext4ObjectV1{}) {
			return plan, unix.ESTALE
		}
		if intent.InitialCaptured {
			if err = validateCopyRecoveryMetadata(intent.Cleanup); err != nil {
				return plan, err
			}
			current, err := copyRootCleanup(rootFD)
			if err != nil {
				return plan, err
			}
			want := intent.Cleanup
			want.Manifest, want.Staging = a.Ext4ObjectV1{}, a.Ext4ObjectV1{}
			if current != want {
				return plan, unix.ESTALE
			}
		}
		return plan, nil
	}
	// A minimal Session lets both paths use the same descriptor-rooted binding
	// check; no registry, authority callback, or mutation is available here.
	s := &Session{root: root}
	transaction, err := s.copyTransaction(intent)
	if errors.Is(err, unix.ENOENT) && intent.Phase == a.CopyCleaning {
		return plan, verifyCopyCleanupMetadata(rootFD, intent.Cleanup)
	}
	if err != nil {
		return plan, err
	}
	defer func() { result = errors.Join(result, unix.Close(transaction)) }()
	manifestIdentity, err := optionalCopyIdentity(transaction, "manifest.json")
	if err != nil {
		return plan, err
	}
	stagingIdentity, err := optionalCopyIdentity(transaction, "staging")
	if err != nil {
		return plan, err
	}
	if stagingIdentity != (a.Ext4ObjectV1{}) && stagingIdentity.FileType != unix.S_IFDIR {
		return plan, unix.ESTALE
	}
	if intent.Phase == a.CopyCleaning {
		if err = verifyCopyCleanupMetadata(rootFD, intent.Cleanup); err != nil {
			return plan, err
		}
		if manifestIdentity != (a.Ext4ObjectV1{}) && manifestIdentity != intent.Cleanup.Manifest || stagingIdentity != (a.Ext4ObjectV1{}) && stagingIdentity != intent.Cleanup.Staging {
			return plan, unix.ESTALE
		}
	}
	if intent.Phase == a.CopySealed || intent.ManifestSize != 0 && manifestIdentity != (a.Ext4ObjectV1{}) {
		plan.manifest, err = readCopyRollbackManifest(transaction, intent)
		if err != nil {
			return plan, err
		}
		plan.expected = make(map[string]a.Ext4ObjectV1, len(plan.manifest.Entries))
		for _, entry := range plan.manifest.Entries {
			plan.expected[entry.Path] = entry.Identity
		}
	}
	// Missing sealed evidence is permissible only after durable CLEANING and
	// only after all other private entries were removed (manifest is removed last).
	if intent.ManifestSize != 0 && manifestIdentity == (a.Ext4ObjectV1{}) && stagingIdentity != (a.Ext4ObjectV1{}) {
		return plan, unix.ESTALE
	}
	if err = preflightCopyPrivate(transaction, manifestIdentity, stagingIdentity, plan.expected, intent.ManifestSize != 0); err != nil {
		return plan, err
	}
	if intent.Phase == a.CopyCleaning {
		return plan, nil // Never inspect or authorize deletion of public objects.
	}
	plan.matching, err = planCopyPublic(plan.manifest.Entries, func(relative string) (a.Ext4ObjectV1, error) {
		return copyIdentityAt(rootFD, relative)
	})
	if err != nil {
		return plan, err
	}
	plan.xattrs, err = preflightCopyXattrs(rootFD, plan.manifest.Root.Xattrs)
	return plan, err
}

func verifyCopyCleanupMetadata(fd int, want a.CopyCleanupV1) error {
	if err := validateCopyRecoveryMetadata(want); err != nil {
		return err
	}
	got, err := copyRootCleanup(fd)
	if err != nil {
		return err
	}
	// Private unlinks may have changed times; FINISH restores the durable times.
	if got.UID != want.UID || got.GID != want.GID || got.Mode != want.Mode {
		return unix.ESTALE
	}
	return nil
}

func readCopyRollbackManifest(transaction int, intent a.CopyIntent) (manifest c.Manifest, result error) {
	file, _, err := openCopyManifest(transaction)
	if err != nil {
		return manifest, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	raw, err := io.ReadAll(io.LimitReader(file, maxCopyManifestBytes+1))
	if err != nil {
		return manifest, err
	}
	digest, size, err := digestCopyManifest(bytes.NewReader(raw))
	if err != nil {
		return manifest, err
	}
	if digest != intent.ManifestDigest || size != intent.ManifestSize {
		return manifest, unix.ESTALE
	}
	manifest, err = c.DecodeManifest(raw)
	if err != nil {
		return manifest, err
	}
	if manifest.Intent != intent.ID || manifest.Physical != intent.Root || !intent.InitialCaptured {
		return manifest, unix.ESTALE
	}
	if err = validateCopyRecoveryMetadata(intent.Initial); err != nil {
		return manifest, err
	}
	// The JSON root is the original snapshot, not the possibly source-modified
	// current root. Its legacy dev/fsid fields are not cross-boot identity proof.
	if manifest.Root == nil || manifest.Root.UID != intent.Initial.UID || manifest.Root.GID != intent.Initial.GID || manifest.Root.Mode != intent.Initial.Mode {
		return manifest, unix.ESTALE
	}
	return manifest, nil
}

// planCopyPublic is top-down even though deletion is child-first. A missing or
// replaced parent cuts off its entire branch, including matching hardlink aliases
// maliciously placed below the replacement. No probe occurs below that parent.
func planCopyPublic(entries []c.Entry, probe func(string) (a.Ext4ObjectV1, error)) (map[string]bool, error) {
	matching := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if parent := path.Dir(entry.Path); parent != "." && !matching[parent] {
			continue
		}
		got, err := probe(entry.Path)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
			continue
		}
		if err != nil {
			return nil, err
		}
		matching[entry.Path] = got == entry.Identity
	}
	return matching, nil
}

func preflightCopyPrivate(transaction int, manifest, staging a.Ext4ObjectV1, expected map[string]a.Ext4ObjectV1, sealed bool) error {
	count := 0
	var walk func(int, string, int) error
	walk = func(parent int, relative string, depth int) (result error) {
		if depth > 255 {
			return unix.E2BIG
		}
		// Open a fresh noatime description, not a dup sharing directory offsets.
		fd, err := unix.Openat(parent, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "copy-private-preflight")
		defer func() { result = errors.Join(result, file.Close()) }()
		for {
			children, readErr := file.ReadDir(128)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			for _, child := range children {
				count++
				if count > maxCopyEntries+2 {
					return unix.E2BIG
				}
				rel := child.Name()
				if relative != "" {
					rel = relative + "/" + rel
				}
				identity, err := copyIdentityAt(parent, child.Name())
				if err != nil {
					return err
				}
				switch rel {
				case "manifest.json":
					if identity != manifest {
						return unix.ESTALE
					}
				case "manifest.tmp":
					// A failed prepublication manifest write leaves this private
					// regular file empty, partial or complete. Its bytes grant no
					// authority; sealed recovery must still reject any extra file.
					if sealed || identity.FileType != unix.S_IFREG {
						return unix.ESTALE
					}
					// The producer creates a single-link file. Reject aliases of
					// public inodes: cleanup would change their link count/ctime.
					// O_PATH pins without reading or changing atime, even if the
					// enumerated entry was replaced with a special file.
					temporary, err := copyPinAt(parent, child.Name(), unix.O_PATH)
					if err != nil {
						return err
					}
					pinned, identityErr := ext4Identity(temporary)
					st, statErr := stat(temporary)
					if identityErr == nil && statErr == nil && (pinned != identity || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
						identityErr = unix.ESTALE
					}
					if err = errors.Join(identityErr, statErr, unix.Close(temporary)); err != nil {
						return err
					}
				case "staging":
					if identity != staging {
						return unix.ESTALE
					}
				default:
					if !strings.HasPrefix(rel, "staging/") || sealed && expected[strings.TrimPrefix(rel, "staging/")] != identity {
						return unix.ESTALE
					}
				}
				if identity.FileType == unix.S_IFDIR {
					next, err := copyPinAt(parent, child.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
					if err != nil {
						return err
					}
					pinned, identityErr := ext4Identity(next)
					if identityErr == nil && pinned != identity {
						identityErr = unix.ESTALE
					}
					if identityErr == nil {
						identityErr = walk(next, rel, depth+1)
					}
					if err = errors.Join(identityErr, unix.Close(next)); err != nil {
						return err
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
		}
	}
	return walk(transaction, "", 0)
}

func preflightCopyXattrs(fd int, snapshot *c.XattrSnapshot) ([]string, error) {
	return preflightCopyXattrsWith(fd, snapshot, c.XattrOperations{List: unix.Flistxattr})
}

func preflightCopyXattrsWith(fd int, snapshot *c.XattrSnapshot, operations c.XattrOperations) ([]string, error) {
	if err := c.ValidateXattrs(snapshot); err != nil {
		return nil, err
	}
	names, supported, err := c.ListXattrs(fd, operations)
	if err != nil {
		return nil, err
	}
	if supported != (snapshot.State == "supported") {
		return nil, unix.ESTALE
	}
	return names, nil
}

func restoreCopyRollbackMetadata(fd int, plan copyRollbackPlan) error {
	metadata := plan.manifest.Root
	// chown clears capabilities/set-ID; chmod rewrites ACL masks. Restore both
	// only after these operations, using the fully validated immutable snapshot.
	if err := unix.Fchown(fd, int(metadata.UID), int(metadata.GID)); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, metadata.Mode); err != nil {
		return err
	}
	if metadata.Xattrs.State == "unsupported" {
		return nil
	}
	wanted := make(map[string]bool, len(metadata.Xattrs.Entries))
	for _, entry := range metadata.Xattrs.Entries {
		wanted[string(entry.Name)] = true
	}
	for _, name := range plan.xattrs {
		if !wanted[name] {
			if err := unix.Fremovexattr(fd, name); err != nil && !errors.Is(err, unix.ENODATA) {
				return err
			}
		}
	}
	for _, entry := range metadata.Xattrs.Entries {
		if err := unix.Fsetxattr(fd, string(entry.Name), entry.Value, 0); err != nil {
			return err
		}
	}
	return nil
}

// openCopyRollbackParent checks EVERY public ancestor on the descriptor chain.
// The returned descriptor is owned; a replacement/absence returns (-1, nil).
func openCopyRollbackParent(root int, relative string, expected map[string]a.Ext4ObjectV1) (int, error) {
	fd, err := unix.Openat(root, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parent := path.Dir(relative)
	if parent == "." {
		return fd, nil
	}
	prefix := ""
	for _, component := range strings.Split(parent, "/") {
		if prefix != "" {
			prefix += "/"
		}
		prefix += component
		identity, identityErr := copyIdentityAt(fd, component)
		if errors.Is(identityErr, unix.ENOENT) || errors.Is(identityErr, unix.ENOTDIR) || errors.Is(identityErr, unix.ELOOP) {
			return -1, unix.Close(fd)
		}
		if identityErr != nil || identity != expected[prefix] {
			return -1, errors.Join(identityErr, unix.Close(fd))
		}
		next, openErr := copyPinAt(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return -1, errors.Join(openErr, closeErr)
		}
		pinned, identityErr := ext4Identity(next)
		if closeErr != nil || identityErr != nil || pinned != identity {
			return -1, errors.Join(closeErr, identityErr, unix.Close(next), unix.ESTALE)
		}
		fd = next
	}
	return fd, nil
}

func (s *Session) removeCopyRollbackEntry(entry c.Entry, expected map[string]a.Ext4ObjectV1) (result error) {
	parent, err := openCopyRollbackParent(int(s.root.Fd()), entry.Path, expected)
	if err != nil || parent < 0 {
		return err
	}
	defer func() { result = errors.Join(result, unix.Close(parent)) }()
	identity, err := copyIdentityAt(parent, path.Base(entry.Path))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if identity != entry.Identity {
		return nil // Preserve public replacements, never authorize recursion.
	}
	flags := 0
	if identity.FileType == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
	}
	err = unix.Unlinkat(parent, path.Base(entry.Path), flags)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTEMPTY) {
		return nil // Unknown public children are not transaction-owned.
	}
	if err != nil {
		return err
	}
	return s.syncFile(parent, false)
}

// copyRollbackEvents snapshots cache identities BEFORE mutation. Parent pins in
// the registry are inode-reuse-safe even when a public ancestor was replaced.
func (s *Session) copyRollbackEvents(plan copyRollbackPlan) ([]w.Event, error) {
	st, err := stat(int(s.root.Fd()))
	if err != nil {
		return nil, err
	}
	events := make([]w.Event, 0)
	for key, object := range s.registry.objects {
		if key.volume == s.binding.Volume {
			for _, kind := range []w.EventKind{w.InvalidateAttr, w.InvalidateData} {
				events = append(events, w.Event{Volume: s.binding.Volume, Object: object.id, Kind: kind, Name: []byte{}})
			}
		}
	}
	for _, entry := range plan.manifest.Entries {
		parentInode := st.Ino
		if parent := path.Dir(entry.Path); parent != "." {
			parentInode = plan.expected[parent].Inode
		}
		parent := s.registry.objects[inodeKey{s.binding.Volume, st.Dev, parentInode}]
		if parent == nil {
			continue
		}
		// Entry notifications invalidate Parent/Name, including negative cache.
		// With no known child, Object is the real affected parent, never a minted ID.
		id := parent.id
		if child := s.registry.objects[inodeKey{s.binding.Volume, st.Dev, entry.Identity.Inode}]; child != nil {
			id = child.id
		}
		events = append(events, w.Event{Volume: s.binding.Volume, Object: id, Parent: parent.id, Kind: w.InvalidateEntry, Name: []byte(path.Base(entry.Path))})
	}
	if uint64(len(events)) > ^uint64(0)-s.registry.eventSequence {
		return nil, unix.EOVERFLOW
	}
	for _, event := range events {
		probe := event
		probe.EventSequence = 1 // Validate shape; Dispatch alone allocates sequences.
		if err := probe.Validate(); err != nil {
			return nil, err
		}
	}
	return events, nil
}

// rollbackCopy is called only under the namespace gate and a private PREPARE
// obligation. The caller must poison the volume on any error (including close),
// and publish returned events only with the successful reply under that gate.
func (s *Session) rollbackCopy(guard *a.Guard, intent a.CopyIntent) (a.CopyIntent, []w.Event, error) {
	device, err := guard.CopyDeviceID()
	if err != nil {
		return a.CopyIntent{}, nil, err
	}
	plan, err := planCopyRecovery(s.root, device, a.CopyOperationRollback, intent)
	if err != nil {
		return a.CopyIntent{}, nil, err
	}
	events, err := s.copyRollbackEvents(plan)
	if err != nil {
		return a.CopyIntent{}, nil, err
	}
	if intent.Phase == a.CopyCleaning {
		return intent, events, nil
	}
	if err = restoreCopyRollbackMetadata(int(s.root.Fd()), plan); err != nil {
		return a.CopyIntent{}, nil, err
	}
	for i := len(plan.manifest.Entries) - 1; i >= 0; i-- {
		entry := plan.manifest.Entries[i]
		if plan.matching[entry.Path] {
			if err = s.removeCopyRollbackEntry(entry, plan.expected); err != nil {
				return a.CopyIntent{}, nil, err
			}
		}
	}
	initial := intent.Initial
	if err = unix.UtimesNanoAt(int(s.root.Fd()), "", []unix.Timespec{{Sec: initial.ATimeSeconds, Nsec: int64(initial.ATimeNanos)}, {Sec: initial.MTimeSeconds, Nsec: int64(initial.MTimeNanos)}}, unix.AT_EMPTY_PATH); err != nil {
		return a.CopyIntent{}, nil, err
	}
	if err = s.registry.syncFilesystem(s.binding.Volume, int(s.root.Fd())); err != nil {
		return a.CopyIntent{}, nil, err
	}
	cleaning, err := s.startCopyCleanup(guard, intent)
	if err != nil {
		return a.CopyIntent{}, nil, err
	}
	return cleaning, events, nil
}

// resumeCopyDirectory acknowledges only fresh filesystem durability. It neither
// replays an old FD nor changes the intent, metadata, namespace, or receipt state.
func (s *Session) resumeCopyDirectory(guard *a.Guard, intent a.CopyIntent) error {
	device, err := guard.CopyDeviceID()
	if err != nil {
		return err
	}
	if err = PreflightCopyRecovery(s.root, device, a.CopyOperationDirectoryTail, intent); err != nil {
		return err
	}
	return s.registry.syncFilesystem(s.binding.Volume, int(s.root.Fd()))
}
