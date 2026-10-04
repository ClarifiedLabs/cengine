//go:build linux

package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"dev.cengine/guest/internal/copycontract"
	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

const (
	maxConfinedPathDepth           = 255
	confinedCopyTransactionName    = ".cengine-copyup-transaction"
	confinedCopyStagingName        = "staging"
	confinedCopyManifestName       = "manifest.json"
	confinedCopyManifestTemporary  = "manifest.tmp"
	maxConfinedCopyManifestBytes   = 64 * 1024 * 1024
	maxConfinedCopyManifestEntries = 1_000_000
	maxConfinedCopyFileHandleBytes = 128
)

type openat2Operation func(dirfd int, path string, how *unix.OpenHow) (int, error)

type confinedRoot struct {
	fd          int
	publication *confinedPublication
}

func openConfinedRoot(path string) (*confinedRoot, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return nil, unix.ENOTDIR
	}
	return &confinedRoot{fd: fd}, nil
}

func (root *confinedRoot) close() error {
	if root == nil || root.fd < 0 {
		return nil
	}
	err := unix.Close(root.fd)
	root.fd = -1
	return err
}

func validateConfinedRelativePath(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("confined path is empty")
	}
	if strings.HasPrefix(path, "/") {
		return nil, errors.New("confined path must be relative")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("confined path contains NUL")
	}
	if len(path) >= unix.PathMax {
		return nil, fmt.Errorf("confined path exceeds %d bytes", unix.PathMax-1)
	}
	components := strings.Split(path, "/")
	if len(components) > maxConfinedPathDepth {
		return nil, fmt.Errorf("confined path exceeds %d components", maxConfinedPathDepth)
	}
	for _, component := range components {
		switch component {
		case "":
			return nil, errors.New("confined path contains an empty component")
		case ".", "..":
			return nil, fmt.Errorf("confined path contains invalid component %q", component)
		}
		if len(component) > unix.NAME_MAX {
			return nil, fmt.Errorf("confined path component exceeds %d bytes", unix.NAME_MAX)
		}
	}
	return components, nil
}

func absoluteMountDestinationRelative(destination string) (string, error) {
	if !strings.HasPrefix(destination, "/") || destination == "/" {
		return "", errors.New("mount destination must be an absolute non-root path")
	}
	relative := destination[1:]
	if _, err := validateConfinedRelativePath(relative); err != nil {
		return "", fmt.Errorf("invalid mount destination %q: %w", destination, err)
	}
	return relative, nil
}

func openConfinedAt(rootFD int, path string, flags int, mode uint32) (int, error) {
	return openConfinedAtWith(rootFD, path, flags, mode, unix.Openat2)
}

func openConfinedAtWith(
	rootFD int,
	path string,
	flags int,
	mode uint32,
	openat2 openat2Operation,
) (int, error) {
	components, err := validateConfinedRelativePath(path)
	if err != nil {
		return -1, err
	}
	how := &unix.OpenHow{
		Flags: uint64(flags | unix.O_CLOEXEC),
		Mode:  uint64(mode),
		Resolve: unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := openat2(rootFD, path, how)
	if errors.Is(err, unix.ENOSYS) {
		return openConfinedAtFallback(rootFD, components, flags, mode)
	}
	if err != nil {
		return -1, err
	}
	if err := rejectSymlinkFD(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openConfinedFollowingAt(rootFD int, path string, flags int, mode uint32) (int, error) {
	components, err := validateConfinedRelativePath(path)
	if err != nil {
		return -1, err
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rootFD, path, how)
	if errors.Is(err, unix.ENOSYS) {
		// The fallback deliberately rejects symlinks because component-by-component
		// traversal cannot safely reproduce RESOLVE_BENEATH symlink resolution.
		return openConfinedAtFallback(rootFD, components, flags, mode)
	}
	return fd, err
}

func openConfinedAtFallback(rootFD int, components []string, flags int, mode uint32) (int, error) {
	parentFD := rootFD
	ownedParent := false
	for _, component := range components[:len(components)-1] {
		fd, err := unix.Openat(
			parentFD,
			component,
			unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if ownedParent {
			_ = unix.Close(parentFD)
		}
		if err != nil {
			return -1, err
		}
		parentFD = fd
		ownedParent = true
	}
	fd, err := unix.Openat(
		parentFD,
		components[len(components)-1],
		flags|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		mode,
	)
	if ownedParent {
		_ = unix.Close(parentFD)
	}
	if err != nil {
		return -1, err
	}
	if err := rejectSymlinkFD(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func rejectSymlinkFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.ELOOP
	}
	return nil
}

func duplicateCloexec(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}

func procFDPath(fd int) string {
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}

func procFDRelativePath(fd int, relative string) string {
	return procFDPath(fd) + "/" + relative
}

func pinConfinedSubpath(root *confinedRoot, subpath string) (int, unix.Stat_t, error) {
	var stat unix.Stat_t
	var (
		fd  int
		err error
	)
	if subpath == "" {
		fd, err = duplicateCloexec(root.fd)
	} else {
		fd, err = openConfinedAt(root.fd, subpath, unix.O_PATH|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return -1, stat, err
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, stat, err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = unix.Close(fd)
		return -1, stat, unix.ELOOP
	}
	return fd, stat, nil
}

func pinConfinedMountpoint(root *confinedRoot, relative string, sourceMode uint32) (int, error) {
	components, err := validateConfinedRelativePath(relative)
	if err != nil {
		return -1, err
	}
	parentFD, err := duplicateCloexec(root.fd)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	for index, component := range components[:len(components)-1] {
		prefix := strings.Join(components[:index+1], "/")
		nextFD, err := openConfinedFollowingAt(root.fd, prefix, unix.O_PATH|unix.O_DIRECTORY, 0)
		if errors.Is(err, unix.ENOENT) {
			if err := unix.Mkdirat(parentFD, component, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
				return -1, err
			}
			nextFD, err = openConfinedFollowingAt(root.fd, prefix, unix.O_PATH|unix.O_DIRECTORY, 0)
		}
		if err != nil {
			return -1, err
		}
		_ = unix.Close(parentFD)
		parentFD = nextFD
	}
	name := components[len(components)-1]
	switch sourceMode & unix.S_IFMT {
	case unix.S_IFDIR:
		return openOrCreateConfinedDirectory(parentFD, name)
	case unix.S_IFREG:
		fd, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			createdFD, createErr := unix.Openat(
				parentFD,
				name,
				unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0644,
			)
			if createErr != nil {
				return -1, createErr
			}
			_ = unix.Close(createdFD)
			fd, err = unix.Openat(parentFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return -1, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("mountpoint %q is not a regular file", name)
		}
		return fd, nil
	default:
		return -1, fmt.Errorf("unsupported volume mount source mode %#o", sourceMode)
	}
}

func openOrCreateConfinedDirectory(parentFD int, name string) (int, error) {
	fd, err := unix.Openat(
		parentFD,
		name,
		unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(parentFD, name, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
		fd, err = unix.Openat(
			parentFD,
			name,
			unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
	}
	return fd, err
}

func mountConfinedVolume(
	sourceRootPath string,
	destinationRootPath string,
	spec protocol.Mount,
	mount mountOperation,
	mountSetattr mountSetattrOperation,
) error {
	sourceRoot, err := openConfinedRoot(sourceRootPath)
	if err != nil {
		return fmt.Errorf("pin volume root: %w", err)
	}
	defer sourceRoot.close()
	sourceFD, sourceStat, err := pinConfinedSubpath(sourceRoot, spec.Subpath)
	if err != nil {
		return fmt.Errorf("pin volume subpath: %w", err)
	}
	defer unix.Close(sourceFD)
	if sourceStat.Mode&unix.S_IFMT != unix.S_IFDIR && sourceStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("volume subpath has unsupported mode %#o", sourceStat.Mode)
	}

	destinationRelative, err := absoluteMountDestinationRelative(spec.Destination)
	if err != nil {
		return err
	}
	destinationRoot, err := openConfinedRoot(destinationRootPath)
	if err != nil {
		return fmt.Errorf("pin workload root: %w", err)
	}
	defer destinationRoot.close()
	destinationFD, err := pinConfinedMountpoint(destinationRoot, destinationRelative, sourceStat.Mode)
	if err != nil {
		return fmt.Errorf("pin volume mountpoint: %w", err)
	}
	defer unix.Close(destinationFD)

	source := procFDPath(sourceFD)
	// Linux mount(2) follows an O_PATH descriptor when it is used as a
	// source, but does not accept the descriptor symlink itself as a mount
	// target. Resolve the already-validated relative target through the pinned
	// root descriptor instead. The stage-2 process is the sole mutator of this
	// private mount namespace until setup completes.
	destination := procFDRelativePath(destinationRoot.fd, destinationRelative)
	if err := mount(source, destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	return applyVolumeMountAttributes(destination, spec, mountSetattr)
}

func mountConfinedBind(
	sourceRootPath string,
	destinationRootPath string,
	spec protocol.Mount,
	mount mountOperation,
	mountSetattr mountSetattrOperation,
) error {
	sourceRoot, err := openConfinedRoot(sourceRootPath)
	if err != nil {
		return fmt.Errorf("pin bind root: %w", err)
	}
	defer sourceRoot.close()
	sourceFD, sourceStat, err := pinConfinedSubpath(sourceRoot, spec.Subpath)
	if err != nil {
		return fmt.Errorf("pin bind subpath: %w", err)
	}
	defer unix.Close(sourceFD)
	if sourceStat.Mode&unix.S_IFMT != unix.S_IFDIR && sourceStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("bind subpath has unsupported mode %#o", sourceStat.Mode)
	}

	destinationRelative, err := absoluteMountDestinationRelative(spec.Destination)
	if err != nil {
		return err
	}
	destinationRoot, err := openConfinedRoot(destinationRootPath)
	if err != nil {
		return fmt.Errorf("pin workload root: %w", err)
	}
	defer destinationRoot.close()
	destinationFD, err := pinConfinedMountpoint(destinationRoot, destinationRelative, sourceStat.Mode)
	if err != nil {
		return fmt.Errorf("pin bind mountpoint: %w", err)
	}
	defer unix.Close(destinationFD)

	source := procFDPath(sourceFD)
	destination := procFDRelativePath(destinationRoot.fd, destinationRelative)
	if err := mount(source, destination, "", bindMountFlags(spec), ""); err != nil {
		return err
	}
	return applyBindMountAttributes(destination, spec, mount, mountSetattr)
}

func mountConfinedTmpfs(
	destinationRootPath string,
	destinationPath string,
	flags uintptr,
	data string,
	mount mountOperation,
) error {
	destinationRelative, err := absoluteMountDestinationRelative(destinationPath)
	if err != nil {
		return err
	}
	destinationRoot, err := openConfinedRoot(destinationRootPath)
	if err != nil {
		return fmt.Errorf("pin workload root: %w", err)
	}
	defer destinationRoot.close()
	destinationFD, err := pinConfinedMountpoint(destinationRoot, destinationRelative, unix.S_IFDIR)
	if err != nil {
		return fmt.Errorf("pin tmpfs mountpoint: %w", err)
	}
	defer unix.Close(destinationFD)
	return mount(
		"tmpfs", procFDRelativePath(destinationRoot.fd, destinationRelative),
		"tmpfs", flags, data,
	)
}

func confinedDirectoryIsEmpty(root *confinedRoot, ignoredNames ...string) (bool, error) {
	entries, err := readConfinedDirectory(root.fd)
	if err != nil {
		return false, err
	}
	ignored := make(map[string]struct{}, len(ignoredNames))
	for _, name := range ignoredNames {
		ignored[name] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := ignored[entry.Name()]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func readConfinedDirectory(fd int) ([]os.DirEntry, error) {
	readFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(readFD), "confined-directory")
	if file == nil {
		_ = unix.Close(readFD)
		return nil, errors.New("create confined directory file")
	}
	defer file.Close()
	return file.ReadDir(-1)
}

type confinedInode struct {
	device uint64
	inode  uint64
}

type confinedHardlink struct {
	directoryFD int
	name        string
}

type confinedCreatedEntry struct {
	directoryFD int
	name        string
	path        string
	identity    confinedInode
	mode        uint32
}

type confinedCopyManifestEntry struct {
	Path       string `json:"path"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Mode       uint32 `json:"mode"`
	HandleType int32  `json:"handleType"`
	Handle     []byte `json:"handle"`
}

type confinedCopyRootMetadata = copycontract.RootMetadata

type confinedCopyManifest struct {
	Version uint32                      `json:"version"`
	Entries []confinedCopyManifestEntry `json:"entries"`
	Root    *confinedCopyRootMetadata   `json:"root,omitempty"`
}

func confinedRootMetadata(fd int) (confinedCopyRootMetadata, error) {
	return confinedRootMetadataWithXattrs(fd, confinedXattrSyscalls())
}

func confinedRootMetadataWithXattrs(fd int, operations confinedXattrOperations) (confinedCopyRootMetadata, error) {
	// O_PATH roots cannot use f*xattr. Reopen only the pinned directory itself,
	// never its original pathname (which may have been replaced).
	readFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return confinedCopyRootMetadata{}, err
	}
	defer unix.Close(readFD)
	metadata, err := confinedRootStat(readFD)
	if err != nil {
		return metadata, err
	}
	metadata.Xattrs, err = snapshotConfinedXattrsWith(readFD, operations)
	return metadata, err
}

func confinedRootStat(fd int) (confinedCopyRootMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return confinedCopyRootMetadata{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return confinedCopyRootMetadata{}, unix.ENOTDIR
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return confinedCopyRootMetadata{}, err
	}
	return confinedCopyRootMetadata{
		Filesystem: filesystem.Fsid.Val, Device: stat.Dev, Inode: stat.Ino,
		UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode & 07777,
	}, nil
}

func applyConfinedRootMetadata(fd int, metadata confinedCopyRootMetadata) error {
	return applyConfinedRootMetadataWithXattrs(fd, metadata, confinedXattrSyscalls())
}

func applyConfinedRootMetadataWithXattrs(fd int, metadata confinedCopyRootMetadata, operations confinedXattrOperations) error {
	return applyConfinedRootMetadataBeforeChown(fd, metadata, operations, nil)
}

func applyConfinedRootMetadataBeforeChown(fd int, metadata confinedCopyRootMetadata, operations confinedXattrOperations, before func() error) error {
	if metadata.Xattrs != nil {
		if err := validateConfinedXattrs(metadata.Xattrs); err != nil {
			return err
		}
	}
	// chown can clear set-ID bits and capabilities; chmod can rewrite the ACL
	// mask. Restore ACLs and capabilities only after ownership and mode.
	if before != nil {
		if err := before(); err != nil {
			return err
		}
	}
	if err := unix.Fchown(fd, int(metadata.UID), int(metadata.GID)); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, metadata.Mode); err != nil {
		return err
	}
	// nil is reserved for legacy v1/v2 journals, which did not record xattrs.
	if metadata.Xattrs == nil {
		return nil
	}
	return restoreConfinedXattrsWith(fd, metadata.Xattrs, operations)
}

type confinedCopyState struct {
	// Bound only by the selected managed copy; never installed globally.
	beforeRegularSync func(string) error
	hardlinks         map[confinedInode]confinedHardlink
	created           []confinedCreatedEntry
}

func copyConfinedDirectory(source *confinedRoot, destination *confinedRoot) error {
	return copyConfinedDirectoryWithRootXattrs(source, destination, confinedXattrSyscalls())
}

// Keep root-xattr operations local to one transaction, including its rollback.
// Child copying and all non-xattr filesystem operations always use real syscalls.
func copyConfinedDirectoryWithRootXattrs(source *confinedRoot, destination *confinedRoot, operations confinedXattrOperations) error {
	// Snapshot times before source enumeration can update atime. They are copy
	// output, not rollback identity; keep the existing journal schema unchanged.
	var sourceStat unix.Stat_t
	if err := unix.Fstat(source.fd, &sourceStat); err != nil {
		return fmt.Errorf("stat copy-up source root times: %w", err)
	}
	sourceMetadata, err := confinedRootMetadataWithXattrs(source.fd, operations)
	if err != nil {
		return fmt.Errorf("stat copy-up source root: %w", err)
	}
	originalMetadata, err := confinedRootMetadataWithXattrs(destination.fd, operations)
	if err != nil {
		return fmt.Errorf("stat copy-up destination root: %w", err)
	}
	// Retain a usable descriptor before applying possibly restrictive root modes.
	metadataFD, err := unix.Openat(destination.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(metadataFD)
	if err := unix.Mkdirat(destination.fd, confinedCopyTransactionName, 0700); err != nil {
		return fmt.Errorf("create copy-up transaction: %w", err)
	}
	if err := syncConfinedDirectory(destination.fd); err != nil {
		_ = removeConfinedTreeAt(destination.fd, confinedCopyTransactionName)
		return fmt.Errorf("sync copy-up transaction: %w", err)
	}
	transactionFD, err := unix.Openat(
		destination.fd,
		confinedCopyTransactionName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open copy-up transaction: %w", err)
	}
	transaction := &confinedRoot{fd: transactionFD}
	defer transaction.close()
	if err := unix.Mkdirat(transaction.fd, confinedCopyStagingName, 0700); err != nil {
		_ = removeConfinedTreeAt(destination.fd, confinedCopyTransactionName)
		return fmt.Errorf("create copy-up staging directory: %w", err)
	}
	stagingFD, err := unix.Openat(
		transaction.fd,
		confinedCopyStagingName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		_ = removeConfinedTreeAt(destination.fd, confinedCopyTransactionName)
		return fmt.Errorf("open copy-up staging directory: %w", err)
	}
	staging := &confinedRoot{fd: stagingFD}
	defer staging.close()

	state := &confinedCopyState{hardlinks: make(map[confinedInode]confinedHardlink)}
	defer state.close()
	rollback := func(copyErr error) error {
		if rollbackErr := recoverConfinedCopyTransactionWithRootXattrs(destination, operations); rollbackErr != nil {
			return fmt.Errorf("%w (copy-up rollback: %v)", copyErr, rollbackErr)
		}
		return copyErr
	}
	if err := state.copyDirectoryContents(source.fd, staging.fd, ""); err != nil {
		if rollbackErr := state.rollback(); rollbackErr != nil {
			return fmt.Errorf("%w (staging rollback: %v)", err, rollbackErr)
		}
		if cleanupErr := removeConfinedTreeAt(destination.fd, confinedCopyTransactionName); cleanupErr != nil {
			return fmt.Errorf("%w (copy-up cleanup: %v)", err, cleanupErr)
		}
		return err
	}
	if err := syncConfinedDirectory(staging.fd); err != nil {
		return rollback(fmt.Errorf("sync copy-up staging directory: %w", err))
	}
	if err := writeConfinedCopyManifest(transaction.fd, state.created, &originalMetadata); err != nil {
		return rollback(fmt.Errorf("commit copy-up manifest: %w", err))
	}

	entries, err := readConfinedDirectory(staging.fd)
	if err != nil {
		return rollback(fmt.Errorf("enumerate copy-up staging directory: %w", err))
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})
	for _, entry := range entries {
		name := entry.Name()
		components, validateErr := validateConfinedRelativePath(name)
		if validateErr != nil || len(components) != 1 {
			return rollback(fmt.Errorf("invalid staged copy-up entry %q", name))
		}
		if err := renameConfinedNoReplace(
			staging.fd, name, destination.fd, name,
		); err != nil {
			return rollback(fmt.Errorf("publish copy-up entry %q: %w", name, err))
		}
		if err := destination.publication.afterPublication(destination.fd); err != nil {
			return rollback(err)
		}
	}
	// The durable manifest covers root metadata as well as published entries,
	// including an empty source. Keep the destination writable until publication.
	if err := applyConfinedRootMetadataWithXattrs(metadataFD, sourceMetadata, operations); err != nil {
		return rollback(fmt.Errorf("apply copy-up root metadata: %w", err))
	}
	return finalizeConfinedCopy(
		func() error {
			return unix.UtimesNanoAt(metadataFD, "", []unix.Timespec{sourceStat.Atim, sourceStat.Mtim}, unix.AT_EMPTY_PATH)
		},
		func() error { return unix.Fsync(metadataFD) },
		func() error { return removeConfinedTreeAt(destination.fd, confinedCopyTransactionName) },
		rollback,
	)
}

func renameConfinedNoReplace(oldDirectory int, oldName string, newDirectory int, newName string) error {
	err := unix.Renameat2(
		oldDirectory, oldName, newDirectory, newName, unix.RENAME_NOREPLACE,
	)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOSYS) {
		return err
	}
	var oldFilesystem, newFilesystem unix.Statfs_t
	if statErr := unix.Fstatfs(oldDirectory, &oldFilesystem); statErr != nil {
		return fmt.Errorf("identify exclusive-rename source filesystem: %w", statErr)
	}
	if statErr := unix.Fstatfs(newDirectory, &newFilesystem); statErr != nil {
		return fmt.Errorf("identify exclusive-rename destination filesystem: %w", statErr)
	}
	if oldFilesystem.Type != unix.NFS_SUPER_MAGIC || newFilesystem.Type != unix.NFS_SUPER_MAGIC {
		return err
	}
	// NFSv3 has no wire representation for RENAME_NOREPLACE. CEngine's
	// dedicated volume server recognizes the reserved copy-up source paths
	// and performs this ordinary NFS rename as a descriptor-confined
	// RENAME_NOREPLACE on the backing filesystem.
	return unix.Renameat(oldDirectory, oldName, newDirectory, newName)
}

func writeConfinedCopyManifest(transactionFD int, created []confinedCreatedEntry, root *confinedCopyRootMetadata) error {
	if len(created) > maxConfinedCopyManifestEntries {
		return fmt.Errorf("copy-up manifest exceeds %d entries", maxConfinedCopyManifestEntries)
	}
	manifest := confinedCopyManifest{Version: 3, Root: root}
	if err := validateConfinedCopyRootMetadata(manifest); err != nil {
		return err
	}
	manifest.Entries = make([]confinedCopyManifestEntry, 0, len(created))
	for _, entry := range created {
		var stat unix.Stat_t
		if err := unix.Fstatat(
			entry.directoryFD, entry.name, &stat, unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			return fmt.Errorf("stat copy-up manifest entry %q: %w", entry.path, err)
		}
		if stat.Dev != entry.identity.device || stat.Ino != entry.identity.inode || stat.Mode&unix.S_IFMT != entry.mode {
			return fmt.Errorf("copy-up manifest entry %q changed before commit", entry.path)
		}
		handle, _, err := unix.NameToHandleAt(entry.directoryFD, entry.name, 0)
		if err != nil {
			return fmt.Errorf("identify copy-up manifest entry %q: %w", entry.path, err)
		}
		handleBytes := handle.Bytes()
		if len(handleBytes) == 0 || len(handleBytes) > maxConfinedCopyFileHandleBytes {
			return fmt.Errorf("copy-up manifest entry %q has an invalid file handle", entry.path)
		}
		manifest.Entries = append(manifest.Entries, confinedCopyManifestEntry{
			Path:       entry.path,
			Device:     stat.Dev,
			Inode:      stat.Ino,
			Mode:       stat.Mode & unix.S_IFMT,
			HandleType: handle.Type(),
			Handle:     append([]byte(nil), handleBytes...),
		})
	}
	return writeConfinedManifestValue(transactionFD, manifest)
}

func writeConfinedManifestValue(transactionFD int, manifest any) error {
	fd, err := unix.Openat(
		transactionFD,
		confinedCopyManifestTemporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "copy-up-manifest")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("create copy-up manifest file")
	}
	writeErr := json.NewEncoder(file).Encode(manifest)
	if writeErr != nil {
		writeErr = fmt.Errorf("write temporary manifest: %w", writeErr)
	}
	if writeErr == nil {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			writeErr = fmt.Errorf("stat temporary manifest: %w", err)
		} else if stat.Size < 0 || stat.Size > maxConfinedCopyManifestBytes {
			writeErr = fmt.Errorf("copy-up manifest exceeds %d bytes", maxConfinedCopyManifestBytes)
		}
	}
	if writeErr == nil {
		if err := file.Sync(); err != nil {
			writeErr = fmt.Errorf("sync temporary manifest: %w", err)
		}
	}
	closeErr := file.Close()
	if writeErr == nil && closeErr != nil {
		writeErr = fmt.Errorf("close temporary manifest: %w", closeErr)
	}
	if writeErr != nil {
		_ = unix.Unlinkat(transactionFD, confinedCopyManifestTemporary, 0)
		return writeErr
	}
	if err := renameConfinedNoReplace(
		transactionFD,
		confinedCopyManifestTemporary,
		transactionFD,
		confinedCopyManifestName,
	); err != nil {
		_ = unix.Unlinkat(transactionFD, confinedCopyManifestTemporary, 0)
		return fmt.Errorf("publish manifest: %w", err)
	}
	if err := syncConfinedDirectory(transactionFD); err != nil {
		return fmt.Errorf("sync manifest directory: %w", err)
	}
	return nil
}

func readConfinedCopyManifest(transactionFD int) (confinedCopyManifest, error) {
	var manifest confinedCopyManifest
	fd, err := unix.Openat(
		transactionFD,
		confinedCopyManifestName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return manifest, err
	}
	file := os.NewFile(uintptr(fd), "copy-up-manifest")
	if file == nil {
		_ = unix.Close(fd)
		return manifest, errors.New("open copy-up manifest file")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return manifest, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || stat.Size > maxConfinedCopyManifestBytes {
		return manifest, errors.New("copy-up manifest is not a bounded regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxConfinedCopyManifestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return manifest, errors.New("copy-up manifest has trailing content")
		}
		return manifest, err
	}
	if (manifest.Version < 1 || manifest.Version > 3) || manifest.Entries == nil || len(manifest.Entries) > maxConfinedCopyManifestEntries {
		return manifest, errors.New("copy-up manifest has an unsupported version or entry count")
	}
	if err := validateConfinedCopyRootMetadata(manifest); err != nil {
		return manifest, err
	}
	seen := make(map[string]uint32, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		components, err := validateConfinedRelativePath(entry.Path)
		if err != nil || components[0] == confinedCopyTransactionName {
			return manifest, fmt.Errorf("copy-up manifest contains invalid path %q", entry.Path)
		}
		switch entry.Mode {
		case unix.S_IFDIR, unix.S_IFREG, unix.S_IFLNK:
		default:
			return manifest, fmt.Errorf("copy-up manifest contains invalid mode %#o", entry.Mode)
		}
		if len(entry.Handle) == 0 || len(entry.Handle) > maxConfinedCopyFileHandleBytes {
			return manifest, fmt.Errorf("copy-up manifest contains invalid file handle for %q", entry.Path)
		}
		if _, exists := seen[entry.Path]; exists {
			return manifest, fmt.Errorf("copy-up manifest repeats path %q", entry.Path)
		}
		if len(components) > 1 {
			parent := path.Dir(entry.Path)
			if seen[parent] != unix.S_IFDIR {
				return manifest, fmt.Errorf("copy-up manifest lacks directory parent %q", parent)
			}
		}
		seen[entry.Path] = entry.Mode
	}
	return manifest, nil
}

func validateConfinedCopyRootMetadata(manifest confinedCopyManifest) error {
	root := manifest.Root
	if manifest.Version == 1 {
		if root != nil {
			return errors.New("v1 copy-up manifest contains root metadata")
		}
		return nil
	}
	if root == nil || root.Mode & ^uint32(07777) != 0 || root.UID == ^uint32(0) || root.GID == ^uint32(0) {
		return errors.New("copy-up manifest has invalid root metadata")
	}
	if manifest.Version == 2 {
		if root.Xattrs != nil {
			return errors.New("v2 copy-up manifest contains xattrs")
		}
		return nil
	}
	return validateConfinedXattrs(root.Xattrs)
}

// recoverConfinedCopyTransaction requires the caller to exclude every active
// initializer. A missing manifest identifies staging, not whether its owner is
// alive; recovery must not run concurrently with that owner.
func recoverConfinedCopyTransaction(destination *confinedRoot) error {
	return recoverConfinedCopyTransactionWithRootXattrs(destination, confinedXattrSyscalls())
}

func recoverConfinedCopyTransactionWithRootXattrs(destination *confinedRoot, operations confinedXattrOperations) error {
	transactionFD, err := unix.Openat(
		destination.fd,
		confinedCopyTransactionName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open stale copy-up transaction: %w", err)
	}
	transaction := &confinedRoot{fd: transactionFD}
	// The journal lives in a workload-writable volume, but only a private
	// supervisor-owned directory is authoritative. Guest root is trusted (as
	// for NFS no-root-squash); an unprivileged writer cannot forge recovery.
	var transactionStat unix.Stat_t
	if err := unix.Fstat(transaction.fd, &transactionStat); err != nil {
		_ = transaction.close()
		return err
	}
	if transactionStat.Uid != uint32(os.Geteuid()) || transactionStat.Mode&0777 != 0700 {
		_ = transaction.close()
		return errors.New("copy-up transaction is not supervisor-owned and private")
	}
	manifest, manifestErr := readConfinedCopyManifest(transaction.fd)
	if errors.Is(manifestErr, unix.ENOENT) {
		_ = transaction.close()
		if err := removeConfinedTreeAt(destination.fd, confinedCopyTransactionName); err != nil {
			return fmt.Errorf("remove abandoned copy-up staging: %w", err)
		}
		return syncConfinedDirectory(destination.fd)
	}
	if manifestErr != nil {
		_ = transaction.close()
		return fmt.Errorf("read stale copy-up transaction: %w", manifestErr)
	}
	_ = transaction.close()

	if manifest.Root != nil {
		current, err := confinedRootStat(destination.fd)
		if err != nil {
			return err
		}
		// st_dev depends on the VM's attachment order. The filesystem ID and
		// root inode remain stable when the same volume moves from vdb to vdc.
		if current.Filesystem != manifest.Root.Filesystem || current.Inode != manifest.Root.Inode {
			return errors.New("copy-up destination root changed before recovery")
		}
		for index := range manifest.Entries {
			if manifest.Entries[index].Device != manifest.Root.Device {
				return errors.New("copy-up manifest entry belongs to another filesystem")
			}
			manifest.Entries[index].Device = current.Device
		}
	}
	matching := make([]bool, len(manifest.Entries))
	var first error
	for index, entry := range manifest.Entries {
		state, err := confinedManifestEntryIdentity(destination, entry)
		if err != nil && first == nil {
			first = fmt.Errorf("preflight copy-up entry %q: %w", entry.Path, err)
		}
		matching[index] = state == confinedManifestMatching
	}
	// Identity uncertainty must leave the entire transaction and root metadata
	// intact. In particular, do not roll back earlier matching entries when a
	// later entry cannot be identified. This is containment, not a durable
	// identity solution for filesystems whose handles change across lookups.
	if first != nil {
		return first
	}
	if manifest.Root != nil {
		fd, err := unix.Openat(destination.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		// An unsupported snapshot is authoritative only on a filesystem that
		// still reports no xattr support. Never accept that downgrade on ext4.
		if manifest.Root.Xattrs != nil {
			_, supported, supportErr := listConfinedXattrs(fd, operations)
			if supportErr == nil && supported != (manifest.Root.Xattrs.State == "supported") {
				supportErr = errors.New("copy-up root xattr support changed before recovery")
			}
			if supportErr != nil {
				_ = unix.Close(fd)
				return supportErr
			}
		}
		// Rollback always restores the pre-transaction ownership and mode, even
		// if only chown completed before interruption. Preserve the journal on
		// failure so the next initialization cannot accept a partial rollback.
		err = applyConfinedRootMetadataWithXattrs(fd, *manifest.Root, operations)
		if err == nil {
			err = unix.Fsync(fd)
		}
		_ = unix.Close(fd)
		if err != nil {
			return fmt.Errorf("restore copy-up root metadata: %w", err)
		}
	}
	for index := len(manifest.Entries) - 1; index >= 0; index-- {
		if !matching[index] {
			continue
		}
		if err := rollbackConfinedManifestEntry(destination, manifest.Entries[index]); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return first
	}
	if err := removeConfinedTreeAt(destination.fd, confinedCopyTransactionName); err != nil {
		first = err
	}
	if err := syncConfinedDirectory(destination.fd); err != nil && first == nil {
		first = err
	}
	return first
}

// Equal stat identity with a different handle is ambiguous: it can mean inode
// reuse, or a filesystem exposing a non-durable handle for the same object.
// Neither interpretation permits destructive recovery without stronger proof.
var errConfinedCopyIdentityUncertain = errors.New("copy-up entry identity uncertain")

type confinedManifestIdentity uint8

const (
	confinedManifestUncertain confinedManifestIdentity = iota
	confinedManifestAbsent
	confinedManifestReplacement
	confinedManifestMatching
)

func confinedManifestEntryIdentity(
	destination *confinedRoot,
	entry confinedCopyManifestEntry,
) (confinedManifestIdentity, error) {
	parentFD, name, err := openConfinedManifestParent(destination, entry.Path)
	if errors.Is(err, unix.ENOENT) {
		return confinedManifestAbsent, nil
	}
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return confinedManifestReplacement, nil
	}
	if err != nil {
		return confinedManifestUncertain, err
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return confinedManifestAbsent, nil
	} else if err != nil {
		return confinedManifestUncertain, err
	}
	if stat.Dev != entry.Device || stat.Ino != entry.Inode || stat.Mode&unix.S_IFMT != entry.Mode {
		return confinedManifestReplacement, nil
	}
	handle, _, err := unix.NameToHandleAt(parentFD, name, 0)
	if errors.Is(err, unix.ENOENT) {
		return confinedManifestAbsent, nil
	}
	if err != nil {
		return confinedManifestUncertain, err
	}
	if handle.Type() != entry.HandleType || !bytes.Equal(handle.Bytes(), entry.Handle) {
		return confinedManifestUncertain, errConfinedCopyIdentityUncertain
	}
	return confinedManifestMatching, nil
}

func rollbackConfinedManifestEntry(
	destination *confinedRoot,
	entry confinedCopyManifestEntry,
) error {
	parentFD, name, err := openConfinedManifestParent(destination, entry.Path)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if stat.Dev != entry.Device || stat.Ino != entry.Inode || stat.Mode&unix.S_IFMT != entry.Mode {
		return nil
	}
	flags := 0
	if entry.Mode == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
	}
	if err := unix.Unlinkat(parentFD, name, flags); errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTEMPTY) {
		return nil
	} else {
		return err
	}
}

func openConfinedManifestParent(
	destination *confinedRoot,
	relativePath string,
) (int, string, error) {
	components, err := validateConfinedRelativePath(relativePath)
	if err != nil {
		return -1, "", err
	}
	if len(components) == 1 {
		fd, err := duplicateCloexec(destination.fd)
		return fd, components[0], err
	}
	fd, err := openConfinedAt(
		destination.fd,
		path.Dir(relativePath),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	return fd, components[len(components)-1], err
}

func removeConfinedTreeAt(parentFD int, name string) error {
	return removeConfinedTreeAtDepth(parentFD, name, 0)
}

func removeConfinedTreeAtDepth(parentFD int, name string, depth int) error {
	if depth > maxConfinedPathDepth {
		return errors.New("copy-up transaction tree exceeds maximum depth")
	}
	components, err := validateConfinedRelativePath(name)
	if err != nil || len(components) != 1 {
		return fmt.Errorf("invalid copy-up transaction entry %q", name)
	}
	var initial unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &initial, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	flags := 0
	if initial.Mode&unix.S_IFMT == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
		directoryFD, err := unix.Openat(
			parentFD,
			name,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return err
		}
		var pinned unix.Stat_t
		if err := unix.Fstat(directoryFD, &pinned); err != nil {
			_ = unix.Close(directoryFD)
			return err
		}
		if !sameConfinedEntry(initial, pinned) {
			_ = unix.Close(directoryFD)
			return nil
		}
		entries, err := readConfinedDirectory(directoryFD)
		if err == nil {
			for _, entry := range entries {
				if removeErr := removeConfinedTreeAtDepth(directoryFD, entry.Name(), depth+1); removeErr != nil {
					err = removeErr
					break
				}
			}
		}
		_ = unix.Close(directoryFD)
		if err != nil {
			return err
		}
	}
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if !sameConfinedEntry(initial, current) {
		return nil
	}
	return unix.Unlinkat(parentFD, name, flags)
}

func syncConfinedDirectory(directoryFD int) error {
	fd, err := unix.Openat(
		directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func (state *confinedCopyState) close() {
	for _, link := range state.hardlinks {
		_ = unix.Close(link.directoryFD)
	}
	for _, entry := range state.created {
		_ = unix.Close(entry.directoryFD)
	}
}

func (state *confinedCopyState) recordCreated(directoryFD int, name string, relativePath string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	pinnedDirectory, err := duplicateCloexec(directoryFD)
	if err != nil {
		return err
	}
	state.created = append(state.created, confinedCreatedEntry{
		directoryFD: pinnedDirectory,
		name:        name,
		path:        relativePath,
		identity:    confinedInode{device: stat.Dev, inode: stat.Ino},
		mode:        stat.Mode & unix.S_IFMT,
	})
	return nil
}

func (state *confinedCopyState) rollback() error {
	var first error
	for index := len(state.created) - 1; index >= 0; index-- {
		entry := state.created[index]
		var stat unix.Stat_t
		if err := unix.Fstatat(entry.directoryFD, entry.name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if !errors.Is(err, unix.ENOENT) && first == nil {
				first = err
			}
			continue
		}
		if stat.Dev != entry.identity.device || stat.Ino != entry.identity.inode || stat.Mode&unix.S_IFMT != entry.mode {
			continue
		}
		flags := 0
		if entry.mode == unix.S_IFDIR {
			flags = unix.AT_REMOVEDIR
		}
		if err := unix.Unlinkat(entry.directoryFD, entry.name, flags); err != nil && !errors.Is(err, unix.ENOENT) && first == nil {
			first = err
		}
	}
	return first
}

func (state *confinedCopyState) copyDirectoryContents(
	sourceFD int,
	destinationFD int,
	prefix string,
) error {
	entries, err := readConfinedDirectory(sourceFD)
	if err != nil {
		return err
	}
	if state.beforeRegularSync != nil {
		// The selected fixture cuts the first top-level child, a.
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	}
	for _, entry := range entries {
		name := entry.Name()
		components, err := validateConfinedRelativePath(name)
		if err != nil || len(components) != 1 {
			return fmt.Errorf("invalid directory entry %q", name)
		}
		if prefix == "" && name == confinedCopyTransactionName {
			return fmt.Errorf("source contains reserved copy-up entry %q", name)
		}
		relativePath := name
		if prefix != "" {
			relativePath = path.Join(prefix, name)
		}
		if err := state.copyEntry(sourceFD, destinationFD, name, relativePath); err != nil {
			return fmt.Errorf("copy volume entry %q: %w", relativePath, err)
		}
	}
	return nil
}

func (state *confinedCopyState) copyEntry(
	sourceDirectoryFD int,
	destinationDirectoryFD int,
	name string,
	relativePath string,
) error {
	var initial unix.Stat_t
	if err := unix.Fstatat(sourceDirectoryFD, name, &initial, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch initial.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return state.copyDirectory(
			sourceDirectoryFD, destinationDirectoryFD, name, relativePath, initial,
		)
	case unix.S_IFREG:
		return state.copyRegular(
			sourceDirectoryFD, destinationDirectoryFD, name, relativePath, initial,
		)
	case unix.S_IFLNK:
		return state.copySymlink(
			sourceDirectoryFD, destinationDirectoryFD, name, relativePath, initial,
		)
	default:
		return fmt.Errorf("special file mode %#o is not allowed", initial.Mode)
	}
}

func (state *confinedCopyState) copyDirectory(
	sourceDirectoryFD int,
	destinationDirectoryFD int,
	name string,
	relativePath string,
	initial unix.Stat_t,
) error {
	sourceFD, err := unix.Openat(
		sourceDirectoryFD,
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(sourceFD)
	var sourceStat unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceStat); err != nil {
		return err
	}
	if !sameConfinedEntry(initial, sourceStat) || sourceStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("source directory changed during copy")
	}
	if err := unix.Mkdirat(destinationDirectoryFD, name, 0700); err != nil {
		return err
	}
	destinationFD, err := unix.Openat(
		destinationDirectoryFD,
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(destinationFD)
	if err := state.recordCreated(destinationDirectoryFD, name, relativePath); err != nil {
		return err
	}
	if err := state.copyDirectoryContents(sourceFD, destinationFD, relativePath); err != nil {
		return err
	}
	if err := copyConfinedFDMetadata(sourceFD, destinationFD, sourceStat); err != nil {
		return err
	}
	return unix.Fsync(destinationFD)
}

func (state *confinedCopyState) copyRegular(
	sourceDirectoryFD int,
	destinationDirectoryFD int,
	name string,
	relativePath string,
	initial unix.Stat_t,
) error {
	sourceFD, err := unix.Openat(
		sourceDirectoryFD,
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	sourceFile := os.NewFile(uintptr(sourceFD), "confined-copy-source")
	if sourceFile == nil {
		_ = unix.Close(sourceFD)
		return errors.New("create confined source file")
	}
	defer sourceFile.Close()
	var sourceStat unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceStat); err != nil {
		return err
	}
	if !sameConfinedEntry(initial, sourceStat) || sourceStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("source file changed during copy")
	}
	key := confinedInode{device: sourceStat.Dev, inode: sourceStat.Ino}
	if link, exists := state.hardlinks[key]; exists {
		if err := unix.Linkat(link.directoryFD, link.name, destinationDirectoryFD, name, 0); err != nil {
			return err
		}
		return state.recordCreated(destinationDirectoryFD, name, relativePath)
	}

	destinationFD, err := unix.Openat(
		destinationDirectoryFD,
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return err
	}
	if err := state.recordCreated(destinationDirectoryFD, name, relativePath); err != nil {
		_ = unix.Close(destinationFD)
		return err
	}
	destinationFile := os.NewFile(uintptr(destinationFD), "confined-copy-destination")
	if destinationFile == nil {
		_ = unix.Close(destinationFD)
		return errors.New("create confined destination file")
	}
	_, copyErr := io.Copy(destinationFile, sourceFile)
	if copyErr == nil {
		copyErr = copyConfinedFDMetadata(sourceFD, destinationFD, sourceStat)
	}
	if copyErr == nil && state.beforeRegularSync != nil {
		copyErr = state.beforeRegularSync(relativePath)
	}
	if copyErr == nil {
		copyErr = unix.Fsync(destinationFD)
	}
	closeErr := destinationFile.Close()
	if copyErr != nil {
		_ = unix.Unlinkat(destinationDirectoryFD, name, 0)
		return copyErr
	}
	if closeErr != nil {
		_ = unix.Unlinkat(destinationDirectoryFD, name, 0)
		return closeErr
	}
	if sourceStat.Nlink > 1 {
		pinnedDirectoryFD, err := duplicateCloexec(destinationDirectoryFD)
		if err != nil {
			return err
		}
		state.hardlinks[key] = confinedHardlink{directoryFD: pinnedDirectoryFD, name: name}
	}
	return nil
}

func (state *confinedCopyState) copySymlink(
	sourceDirectoryFD int,
	destinationDirectoryFD int,
	name string,
	relativePath string,
	initial unix.Stat_t,
) error {
	sourceFD, err := unix.Openat(sourceDirectoryFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sourceFD)
	var sourceStat unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceStat); err != nil {
		return err
	}
	if !sameConfinedEntry(initial, sourceStat) || sourceStat.Mode&unix.S_IFMT != unix.S_IFLNK {
		return errors.New("source symlink changed during copy")
	}
	// Read the literal from the same inode that supplies metadata, including
	// when the source name is concurrently renamed, unlinked, or replaced.
	target, err := readlinkat(sourceFD, "")
	if err != nil {
		return err
	}
	if err := unix.Symlinkat(target, destinationDirectoryFD, name); err != nil {
		return err
	}
	if err := state.recordCreated(destinationDirectoryFD, name, relativePath); err != nil {
		_ = unix.Unlinkat(destinationDirectoryFD, name, 0)
		return err
	}
	// Creation occurs in private staging. Pin and verify the recorded inode
	// before any metadata mutation; never reopen through the symlink target.
	destinationFD, err := unix.Openat(destinationDirectoryFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(destinationFD)
	var destinationStat unix.Stat_t
	if err := unix.Fstat(destinationFD, &destinationStat); err != nil {
		return err
	}
	created := state.created[len(state.created)-1]
	if destinationStat.Mode&unix.S_IFMT != unix.S_IFLNK || destinationStat.Dev != created.identity.device || destinationStat.Ino != created.identity.inode {
		return errors.New("destination symlink changed during copy")
	}
	return copyConfinedSymlinkMetadata(sourceFD, destinationFD, sourceStat)
}

func copyConfinedSymlinkMetadata(sourceFD, destinationFD int, stat unix.Stat_t) error {
	operations := confinedSymlinkXattrSyscalls()
	snapshot, err := snapshotConfinedXattrsWith(sourceFD, operations)
	if err != nil {
		return err
	}
	// chown can clear capabilities. Restore attrs afterwards, and propagate
	// every failure so the enclosing copy-up transaction rolls back.
	if err := unix.Fchownat(destinationFD, "", int(stat.Uid), int(stat.Gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("chown copy-up symlink: %w", err)
	}
	if err := restoreConfinedXattrsWith(destinationFD, snapshot, operations); err != nil {
		return err
	}
	if err := unix.UtimesNanoAt(destinationFD, "", []unix.Timespec{stat.Atim, stat.Mtim}, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("set copy-up symlink times: %w", err)
	}
	return nil
}

func readlinkat(directoryFD int, name string) (string, error) {
	size := 256
	for size <= unix.PathMax {
		buffer := make([]byte, size)
		length, err := unix.Readlinkat(directoryFD, name, buffer)
		if err != nil {
			return "", err
		}
		if length < len(buffer) {
			return string(buffer[:length]), nil
		}
		size *= 2
	}
	return "", unix.ENAMETOOLONG
}

func sameConfinedEntry(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func copyConfinedFDMetadata(sourceFD int, destinationFD int, stat unix.Stat_t) error {
	if err := unix.Fchown(destinationFD, int(stat.Uid), int(stat.Gid)); err != nil {
		return err
	}
	if err := unix.Fchmod(destinationFD, stat.Mode&07777); err != nil {
		return err
	}
	if err := copyConfinedXattrs(sourceFD, destinationFD); err != nil {
		return err
	}
	return unix.UtimesNanoAt(
		destinationFD,
		"",
		[]unix.Timespec{stat.Atim, stat.Mtim},
		unix.AT_EMPTY_PATH,
	)
}

func copyConfinedXattrs(sourceFD int, destinationFD int) error {
	snapshot, err := snapshotConfinedXattrs(sourceFD)
	if err != nil {
		return err
	}
	return restoreConfinedXattrs(destinationFD, snapshot)
}
