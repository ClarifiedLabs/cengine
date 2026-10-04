//go:build linux

package supervisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"unsafe"

	"dev.cengine/guest/internal/copycontract"
	"dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/protocol"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// This scope comes from the immutable authenticated launch, never the journal.
type managedCopyScope struct{ Store, Volume, Prepare, Attachment string }
type managedPrepareCall func(int, w.PrepareRequest) (w.PrepareReply, error)
type managedCopy struct {
	compatibility *preparecompat.Witness
	io            managedCopyIO
	sourceAtimes  *preparecompat.SourceAtimes
	root          *confinedRoot
	scope         managedCopyScope
	intent        a.CopyIntent
	call          managedPrepareCall
}
type managedCopyEntry = copycontract.Entry
type managedCopyManifest = copycontract.Manifest

func managedPrepareIoctl(fd int, request w.PrepareRequest) (w.PrepareReply, error) {
	buffer, err := w.EncodePrepareIoctl(request)
	if err != nil {
		return w.PrepareReply{}, err
	}
	if len(buffer) != w.PrepareIoctlSize {
		return w.PrepareReply{}, errors.New("invalid PREPARE ioctl size")
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(w.PrepareIoctl), uintptr(unsafe.Pointer(&buffer[0])))
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return w.PrepareReply{}, errno
	}
	return w.DecodePrepareIoctlReply(buffer)
}

func validManagedObject(object a.Ext4ObjectV1) bool {
	if object.Inode == 0 || object.HandleType != 1 || object.HandleSize != 8 || object.Inode != uint64(binary.LittleEndian.Uint32(object.Handle[:4])) || object.Generation != binary.LittleEndian.Uint32(object.Handle[4:]) {
		return false
	}
	switch object.FileType {
	case unix.S_IFDIR, unix.S_IFREG, unix.S_IFLNK:
		return true
	}
	return false
}
func (copy *managedCopy) validateIntent(intent a.CopyIntent) error {
	if copy.compatibility != nil {
		if err := copy.compatibility.ValidateIntent(intent); err != nil {
			return err
		}
	}
	root := intent.Root
	if !managedUUID(string(intent.ID)) || root.Store != a.ID(copy.scope.Store) || root.Volume != a.ID(copy.scope.Volume) || root.BackingUUID == [16]byte{} || !validManagedObject(root.Root) || root.Root.FileType != unix.S_IFDIR {
		return errors.New("managed copy-up physical scope mismatch")
	}
	owner := intent.Owner
	if owner.Store != root.Store || owner.Volume != root.Volume || owner.Prepare != a.ID(copy.scope.Prepare) || owner.Attachment != a.ID(copy.scope.Attachment) || owner.Role != a.PrepareRole || owner.Mode != a.ReadWrite {
		return errors.New("managed copy-up owner mismatch")
	}
	if copy.intent.ID != "" && (intent.ID != copy.intent.ID || root != copy.intent.Root) {
		return errors.New("managed copy-up intent changed")
	}
	return nil
}
func (copy *managedCopy) control(action w.PrepareAction) error {
	if action == w.BeginCopy {
		intent, err := beginManagedCopy(func(request w.PrepareRequest) (w.PrepareReply, error) {
			return copy.call(copy.root.fd, request)
		}, copy.validateIntent)
		if err == nil {
			copy.intent = intent
		}
		return err
	}
	reply, err := copy.call(copy.root.fd, w.PrepareRequest{Action: action, Intent: copy.intent.ID})
	if err != nil {
		return err
	}
	if err := copy.validateIntent(reply.Intent); err != nil {
		return err
	}
	switch action {
	case w.BindCopyTransaction:
		if reply.Intent.Phase != a.CopyBound {
			return errors.New("managed copy-up transaction was not bound")
		}
	case w.SealManifest:
		if reply.Intent.Phase != a.CopySealed {
			return errors.New("managed copy-up manifest was not sealed")
		}
	case w.StartCleanup:
		if reply.Intent.Phase != a.CopyCleaning {
			return errors.New("managed copy-up cleanup was not persisted")
		}
	case w.FinishCopy:
		if reply.Intent.Phase != a.CopyCompleted {
			return errors.New("managed copy-up completion was not persisted")
		}
	}
	copy.intent = reply.Intent
	return nil
}
func (copy *managedCopy) identity(relative string) (a.Ext4ObjectV1, error) {
	reply, err := copy.call(copy.root.fd, w.PrepareRequest{Action: w.IdentityAt, Intent: copy.intent.ID, Path: []byte(relative)})
	if err != nil {
		return a.Ext4ObjectV1{}, wrapManagedCopyOp(opIdentityQuery, err)
	}
	if !validManagedObject(reply.Identity) || (reply.Root != (a.CopyRootV1{}) && reply.Root != copy.intent.Root) {
		return a.Ext4ObjectV1{}, errConfinedCopyIdentityUncertain
	}
	return reply.Identity, nil
}
func (copy *managedCopy) checkRoot() error {
	identity, err := copy.identity("")
	if err != nil {
		return err
	}
	if identity != copy.intent.Root.Root {
		return errors.New("managed copy-up root changed")
	}
	return nil
}
func (copy *managedCopy) checkTransaction() error {
	if !validManagedObject(copy.intent.Transaction) || copy.intent.Transaction.FileType != unix.S_IFDIR {
		return errors.New("managed copy-up transaction is unbound")
	}
	identity, err := copy.identity(confinedCopyTransactionName)
	if err != nil {
		return err
	}
	if identity != copy.intent.Transaction {
		return errors.New("managed copy-up transaction changed")
	}
	return copy.checkRoot()
}
func (copy *managedCopy) finish() error {
	if copy.intent.Phase != a.CopyBegun && copy.intent.Phase != a.CopyCleaning {
		return errors.New("managed copy-up cleanup has not started")
	}
	// The server owns cleanup, root restoration, sync and durable completion.
	// In CLEANING even an absent transaction is expected: do not touch the root.
	// No deferred finish: every failed or uncertain operation retains the fence.
	return wrapManagedCopyOp(opFinishCopy, copy.control(w.FinishCopy))
}

func validateManagedInitial(initial a.CopyCleanupV1) error {
	if initial.Mode & ^uint32(07777) != 0 || initial.UID == ^uint32(0) || initial.GID == ^uint32(0) || initial.ATimeNanos >= 1e9 || initial.MTimeNanos >= 1e9 {
		return errors.New("invalid managed initial root metadata")
	}
	return nil
}

func (copy *managedCopy) restoreInitialTimes() error {
	initial := copy.intent.Initial
	if err := validateManagedInitial(initial); err != nil {
		return err
	}
	return unix.UtimesNanoAt(copy.root.fd, "", []unix.Timespec{
		{Sec: initial.ATimeSeconds, Nsec: int64(initial.ATimeNanos)},
		{Sec: initial.MTimeSeconds, Nsec: int64(initial.MTimeNanos)},
	}, unix.AT_EMPTY_PATH)
}

func (copy *managedCopy) restoreUnsealedRoot() error {
	initial := copy.intent.Initial
	if err := validateManagedInitial(initial); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(copy.root.fd, &stat); err != nil {
		return err
	}
	// Before sealing nothing changed root xattrs. Avoid unnecessary chown/chmod
	// (which can clear capabilities or rewrite ACLs).
	if stat.Uid != initial.UID || stat.Gid != initial.GID {
		if err := unix.Fchown(copy.root.fd, int(initial.UID), int(initial.GID)); err != nil {
			return err
		}
	}
	if stat.Mode&07777 != initial.Mode || stat.Uid != initial.UID || stat.Gid != initial.GID {
		if err := unix.Fchmod(copy.root.fd, initial.Mode); err != nil {
			return err
		}
	}
	if err := copy.restoreInitialTimes(); err != nil {
		return err
	}
	return syncConfinedDirectory(copy.root.fd)
}

func initializeManagedVolumeScopedAt(rootfs, base string, mount protocol.Mount, scope managedCopyScope, checkpoint ...*confinedPublication) error {
	return initializeManagedVolumeWithWitness(rootfs, base, mount, scope, nil, checkpoint...)
}

func initializeManagedVolumeWitnessedAt(rootfs, base string, mount protocol.Mount, scope managedCopyScope, witness *preparecompat.Witness) error {
	if !witness.Selected(scope.Attachment) {
		witness = nil
	}
	return initializeManagedVolumeWithWitness(rootfs, base, mount, scope, witness)
}

func initializeManagedVolumeWithWitness(rootfs, base string, mount protocol.Mount, scope managedCopyScope, witness *preparecompat.Witness, checkpoint ...*confinedPublication) error {
	if !managedUUID(scope.Store) || !managedUUID(scope.Volume) || !managedUUID(scope.Prepare) || !managedUUID(scope.Attachment) || scope.Attachment != mount.ManagedAttachment {
		return errors.New("invalid managed copy-up launch scope")
	}
	parent, err := openConfinedRoot(base)
	if err != nil {
		return wrapManagedCopyOp(opVolumeBaseOpen, err)
	}
	defer parent.close()
	// FUSE directory ioctl requires a real open root handle, not O_PATH.
	fd, err := openConfinedAt(parent.fd, scope.Attachment+"/root", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return wrapManagedCopyOp(opRootGrantOpen, err)
	}
	root := &confinedRoot{fd: fd}
	defer root.close()
	if len(checkpoint) == 1 {
		root.publication = checkpoint[0]
	}
	copy := &managedCopy{root: root, scope: scope, call: managedPrepareIoctl, compatibility: witness}
	copy.io = copy.compatibilityIO()
	return copy.initialize(rootfs, mount)
}

func (copy *managedCopy) initialize(rootfs string, mount protocol.Mount) error {
	// Opening the root grant is the only operation before the service fence.
	// No readdir, metadata snapshot, journal read, or atime-changing read precedes it.
	if err := copy.control(w.BeginCopy); err != nil {
		return wrapManagedCopyOp(opBeginCopy, err)
	}
	if copy.intent.Phase != a.CopyCleaning {
		if err := copy.checkRoot(); err != nil {
			return wrapManagedCopyOp(opCheckRoot, err)
		}
	}
	recovered, err := copy.recover()
	if err != nil {
		return fmt.Errorf("recover managed copy-up: %w", wrapManagedCopyOp(opRecover, err))
	}
	if recovered {
		if err := copy.finish(); err != nil {
			return err
		}
		copy.intent = a.CopyIntent{}
		if err := copy.control(w.BeginCopy); err != nil {
			return wrapManagedCopyOp(opBeginCopy, err)
		}
	}
	if mount.NoCopy {
		return wrapManagedCopyOp(opFinishNoCopy, copy.finishWithoutPublication())
	}
	empty, err := copy.isEmpty()
	if err != nil {
		return wrapManagedCopyOp(opEmptinessProbe, err)
	}
	if !empty {
		return wrapManagedCopyOp(opFinishNoCopy, copy.finishWithoutPublication())
	}
	relative, err := absoluteMountDestinationRelative(mount.Destination)
	if err != nil {
		return err
	}
	sourceRoot, err := openConfinedRoot(rootfs)
	if err != nil {
		return wrapManagedCopyOp(opSourceRootOpen, err)
	}
	defer sourceRoot.close()
	fd, stat, err := pinConfinedSubpath(sourceRoot, relative)
	if errors.Is(err, unix.ENOENT) {
		return wrapManagedCopyOp(opFinishNoCopy, copy.finishWithoutPublication())
	}
	if err != nil {
		return wrapManagedCopyOp(opSourcePin, err)
	}
	source := &confinedRoot{fd: fd}
	defer source.close()
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return wrapManagedCopyOp(opFinishNoCopy, copy.finishWithoutPublication())
	}
	if err := copy.copyDirectory(source); err != nil {
		return err
	}
	return copy.finish()
}

// Preserve root atime across empty/nonempty probes, including a fresh Begin after
// resumed cleanup. No fallback may silently change the snapshot being protected.
func (copy *managedCopy) isEmpty() (bool, error) {
	fd, err := unix.Openat(copy.root.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), "managed-volume-emptiness")
	defer file.Close()
	entries, err := file.ReadDir(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return len(entries) == 0, err
}

func (copy *managedCopy) copyDirectory(source *confinedRoot) error {
	if err := copy.compatibilitySource(source); err != nil {
		return err
	}
	var sourceStat unix.Stat_t
	if err := unix.Fstat(source.fd, &sourceStat); err != nil {
		return err
	}
	sourceMetadata, err := confinedRootMetadata(source.fd)
	if err != nil {
		return err
	}
	original, err := confinedRootMetadata(copy.root.fd)
	if err != nil {
		return err
	}
	// The authority provisions privately, durably binds, then publishes. Never
	// create or adopt a public unbound transaction directory in the supervisor.
	if err := copy.control(w.BindCopyTransaction); err != nil {
		return wrapManagedCopyOp(opTransactionBind, err)
	}
	if err := copy.checkTransaction(); err != nil {
		return wrapManagedCopyOp(opTransactionCheck, err)
	}
	if err := validateManagedInitial(copy.intent.Initial); err != nil {
		return err
	}
	original.UID, original.GID, original.Mode = copy.intent.Initial.UID, copy.intent.Initial.GID, copy.intent.Initial.Mode
	transactionFD, err := openConfinedAt(copy.root.fd, confinedCopyTransactionName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return wrapManagedCopyOp(opTransactionOpen, err)
	}
	defer unix.Close(transactionFD)
	if err := unix.Mkdirat(transactionFD, confinedCopyStagingName, 0700); err != nil {
		return wrapManagedCopyOp(opStagingMkdir, err)
	}
	stagingFD, err := openConfinedAt(transactionFD, confinedCopyStagingName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return wrapManagedCopyOp(opStagingOpen, err)
	}
	defer unix.Close(stagingFD)
	state := &confinedCopyState{hardlinks: make(map[confinedInode]confinedHardlink), beforeRegularSync: copy.io.childSync()}
	defer state.close()
	// On any staging failure retain bound evidence. A later owner may clean it
	// only through the authority's still-unsealed transaction binding.
	if err := state.copyDirectoryContents(source.fd, stagingFD, ""); err != nil {
		return wrapManagedCopyOp(opCopyContents, err)
	}
	if err := syncConfinedDirectory(stagingFD); err != nil {
		return wrapManagedCopyOp(opStagingSync, err)
	}
	manifest := managedCopyManifest{Version: 4, Intent: copy.intent.ID, Physical: copy.intent.Root, Root: &original, Entries: make([]managedCopyEntry, 0, len(state.created))}
	if len(state.created) > maxConfinedCopyManifestEntries {
		return errors.New("managed copy-up entry bound")
	}
	for _, entry := range state.created {
		identity, err := copy.identity(confinedCopyTransactionName + "/" + confinedCopyStagingName + "/" + entry.path)
		if err != nil {
			return err
		}
		if identity.FileType != entry.mode {
			return errConfinedCopyIdentityUncertain
		}
		manifest.Entries = append(manifest.Entries, managedCopyEntry{Path: entry.path, Identity: identity})
	}
	if err := validateManagedManifest(manifest); err != nil {
		return err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if len(encoded)+1 > a.MaxCopyManifestBytes {
		return errors.New("managed copy-up manifest byte bound")
	}
	if err := writeManagedManifestWithIO(transactionFD, encoded, copy.io); err != nil {
		return wrapManagedCopyOp(opManifestWrite, err)
	}
	if err := copy.control(w.SealManifest); err != nil {
		return wrapManagedCopyOp(opSealManifest, err)
	}
	// Authenticate the exact persisted bytes before publishing even one child.
	authenticated, err := copy.authenticatedManifest(transactionFD)
	if err != nil {
		return wrapManagedCopyOp(opAuthenticateManifest, err)
	}
	if err := copy.compatibilityManifest(authenticated); err != nil {
		return err
	}
	entries, err := readConfinedDirectory(stagingFD)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for index, entry := range entries {
		var publicationIO managedCopyIO
		if index == 0 && entry.Name() == "a" {
			publicationIO = copy.io
		}
		if err := publicationIO.before("public-child-rename"); err != nil {
			return wrapManagedCopyOp(opPublicationIO, err)
		}
		if err := renameConfinedNoReplace(stagingFD, entry.Name(), copy.root.fd, entry.Name()); err != nil {
			return wrapManagedCopyOp(opPublicChildRename, err)
		}
		if err := publicationIO.syncDirectory(copy.root.fd, "public-directory-sync"); err != nil {
			return wrapManagedCopyOp(opPublicDirSync, err)
		}
		if index == 0 {
			if err := copy.compatibilityPublished(authenticated, entry.Name()); err != nil {
				return err
			}
		}
		if err := copy.root.publication.afterPublication(copy.root.fd); err != nil {
			return err
		}
	}
	if err := applyConfinedRootMetadataBeforeChown(copy.root.fd, sourceMetadata, confinedXattrSyscalls(), func() error {
		return copy.io.before("root-metadata")
	}); err != nil {
		return wrapManagedCopyOp(opRootMetadata, err)
	}
	if err := unix.UtimesNanoAt(copy.root.fd, "", []unix.Timespec{sourceStat.Atim, sourceStat.Mtim}, unix.AT_EMPTY_PATH); err != nil {
		return wrapManagedCopyOp(opRootTimes, err)
	}
	if err := copy.io.syncDirectory(copy.root.fd, "root-fsync"); err != nil {
		return wrapManagedCopyOp(opRootFsync, err)
	}
	if err := copy.compatibilityRootSynced(authenticated, sourceMetadata, sourceStat); err != nil {
		return wrapManagedCopyOp(opRootWitness, err)
	}
	return wrapManagedCopyOp(opStartCleanup, copy.control(w.StartCleanup))
}

// Unlike the direct legacy writer, retain every private object on failure.
// Only server-owned FinishCopy may delete transaction contents.
func writeManagedManifest(transactionFD int, encoded []byte) error {
	return writeManagedManifestWithIO(transactionFD, encoded, nil)
}

func writeManagedManifestWithIO(transactionFD int, encoded []byte, cut managedCopyIO) (result error) {
	stage := manifestOpen
	defer func() {
		result = wrapManifestFailure(stage, result)
		if cut != nil {
			reportManifestFailure(os.Stderr, result)
		}
	}()
	fd, err := unix.Openat(transactionFD, confinedCopyManifestTemporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "managed-copy-up-manifest")
	defer file.Close()
	stage = manifestWriteCut
	if err := cut.before("manifest-write"); err != nil {
		return err
	}
	stage = manifestWrite
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	stage = manifestSyncCut
	if err := cut.before("manifest-fsync"); err != nil {
		return err
	}
	stage = manifestSync
	if err := file.Sync(); err != nil {
		return err
	}
	stage = manifestClose
	if err := file.Close(); err != nil {
		return err
	}
	stage = manifestRename
	if err := renameConfinedNoReplace(transactionFD, confinedCopyManifestTemporary, transactionFD, confinedCopyManifestName); err != nil {
		return err
	}
	return cut.syncDirectory(transactionFD, "manifest-rename-parent-sync")
}

func validateManagedManifest(manifest managedCopyManifest) error {
	return copycontract.ValidateManifest(manifest)
}
func (copy *managedCopy) authenticatedManifest(transactionFD int) (managedCopyManifest, error) {
	var manifest managedCopyManifest
	if err := copy.control(w.AuthenticateManifest); err != nil {
		return manifest, err
	}
	if err := copy.checkTransaction(); err != nil {
		return manifest, err
	}
	fd, err := unix.Openat(transactionFD, confinedCopyManifestName, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return manifest, err
	}
	file, err := managedManifestFile(fd)
	if err != nil {
		return manifest, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, a.MaxCopyManifestBytes+1))
	if err != nil {
		return manifest, err
	}
	if len(raw) > a.MaxCopyManifestBytes || uint64(len(raw)) != copy.intent.ManifestSize || sha256.Sum256(raw) != copy.intent.ManifestDigest {
		return manifest, errors.New("managed journal digest mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return manifest, errors.New("managed journal trailing content")
	}
	if err := validateManagedManifest(manifest); err != nil {
		return manifest, err
	}
	if manifest.Intent != copy.intent.ID || manifest.Physical != copy.intent.Root {
		return manifest, errors.New("managed journal provenance mismatch")
	}
	return manifest, nil
}

func (copy *managedCopy) entryIdentity(relative string, expected a.Ext4ObjectV1) (confinedManifestIdentity, error) {
	identity, err := copy.identity(relative)
	if errors.Is(err, unix.ENOENT) {
		return confinedManifestAbsent, nil
	}
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return confinedManifestReplacement, nil
	}
	if err != nil {
		return confinedManifestUncertain, err
	}
	if identity != expected {
		return confinedManifestReplacement, nil
	}
	return confinedManifestMatching, nil
}
func (copy *managedCopy) removeEntry(entry managedCopyEntry) error {
	parent, name, err := openConfinedManifestParent(copy.root, entry.Path)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	// Full ext4 identity, including generation and all handle bytes, is checked
	// again immediately before unlink under the service-owned snapshot fence.
	state, err := copy.entryIdentity(entry.Path, entry.Identity)
	if err != nil {
		return err
	}
	if state != confinedManifestMatching {
		return nil
	}
	flags := 0
	if entry.Identity.FileType == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
	}
	err = unix.Unlinkat(parent, name, flags)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTEMPTY) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncConfinedDirectory(parent)
}

func (copy *managedCopy) recover() (bool, error) {
	if copy.intent.Phase == a.CopyCleaning {
		return true, nil // finish() resumes entirely through the authority.
	}
	if copy.intent.Phase == a.CopySealed {
		// The service owns the complete undo operation and durable replay fence.
		// Ordinary FUSE mutations must not reopen a pending DATA obligation.
		return true, copy.control(w.RollbackCopy)
	}
	// Provisioning can be interrupted after private creation/binding but before
	// public rename. Resume only the authority's private recorded provenance;
	// this cannot adopt a BEGUN public directory or translate legacy handles.
	if copy.intent.InitialCaptured && (copy.intent.Phase == a.CopyBegun || copy.intent.Phase == a.CopyBound) {
		if err := copy.control(w.BindCopyTransaction); err != nil {
			return false, err
		}
	}
	transactionFD, err := openConfinedAt(copy.root.fd, confinedCopyTransactionName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		if copy.intent.Transaction != (a.Ext4ObjectV1{}) {
			return false, errors.New("bound managed transaction missing; retain fence")
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(transactionFD)
	if err := copy.checkTransaction(); err != nil {
		return false, err
	}
	if copy.intent.Phase == a.CopyBound {
		// Authenticate private ownership, never unsealed JSON deletion instructions.
		// The same path handles absent, partial, malformed and present manifests.
		if copy.intent.ManifestSize != 0 || copy.intent.ManifestDigest != [32]byte{} {
			return false, errors.New("invalid bound managed manifest state")
		}
		if err := copy.control(w.AuthenticateManifest); err != nil {
			return false, err
		}
		if copy.intent.Phase != a.CopyBound {
			return false, errors.New("managed prepublication phase changed")
		}
		if err := copy.checkTransaction(); err != nil {
			return false, err
		}
		if err := copy.restoreUnsealedRoot(); err != nil {
			return false, err
		}
		return true, copy.control(w.StartCleanup)
	}
	return false, errors.New("unsupported managed recovery phase")
}

// Preflight every private cleanup object before published rollback mutations.
// The server alone validates/deletes these objects during durable cleanup.
func (copy *managedCopy) validatePrivateSnapshot(manifest managedCopyManifest, snapshot []managedCopyEntry) error {
	expected := make(map[string]a.Ext4ObjectV1, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		expected[confinedCopyTransactionName+"/"+confinedCopyStagingName+"/"+entry.Path] = entry.Identity
	}
	for _, entry := range snapshot {
		switch entry.Path {
		case confinedCopyTransactionName:
			if entry.Identity != copy.intent.Transaction {
				return errConfinedCopyIdentityUncertain
			}
		case confinedCopyTransactionName + "/" + confinedCopyManifestName:
			if entry.Identity.FileType != unix.S_IFREG {
				return errConfinedCopyIdentityUncertain
			}
		case confinedCopyTransactionName + "/" + confinedCopyStagingName:
			if entry.Identity.FileType != unix.S_IFDIR {
				return errConfinedCopyIdentityUncertain
			}
		default:
			if expected[entry.Path] != entry.Identity {
				return errConfinedCopyIdentityUncertain
			}
		}
	}
	return nil
}

func (copy *managedCopy) transactionSnapshot() ([]managedCopyEntry, error) {
	if err := copy.checkTransaction(); err != nil {
		return nil, err
	}
	var entries []managedCopyEntry
	var walk func(string, int) error
	walk = func(relative string, depth int) error {
		if depth > maxConfinedPathDepth || len(entries) >= maxConfinedCopyManifestEntries+4 {
			return errors.New("managed cleanup bound")
		}
		identity, err := copy.identity(relative)
		if err != nil {
			return err
		}
		entries = append(entries, managedCopyEntry{Path: relative, Identity: identity})
		if identity.FileType != unix.S_IFDIR {
			return nil
		}
		fd, err := openConfinedAt(copy.root.fd, relative, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		children, err := readConfinedDirectory(fd)
		if err != nil {
			return err
		}
		// Reverse-order deletion keeps the authenticated manifest until staging
		// cleanup and its sync have succeeded. Any later uncertainty stays fenced.
		if relative == confinedCopyTransactionName {
			sort.SliceStable(children, func(i, j int) bool {
				return children[i].Name() == confinedCopyManifestName && children[j].Name() != confinedCopyManifestName
			})
		}
		for _, child := range children {
			if err := walk(relative+"/"+child.Name(), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(confinedCopyTransactionName, 0); err != nil {
		return nil, err
	}
	return entries, nil
}
