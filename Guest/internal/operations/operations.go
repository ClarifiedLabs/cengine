//go:build linux

package operations

import (
	"crypto/rand"
	"dev.cengine/guest/internal/disk"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Statistics struct {
	CPUTotalNanoseconds  uint64              `json:"cpuTotalNanoseconds"`
	CPUUserNanoseconds   uint64              `json:"cpuUserNanoseconds"`
	CPUSystemNanoseconds uint64              `json:"cpuSystemNanoseconds"`
	MemoryUsage          uint64              `json:"memoryUsage"`
	MemoryCache          uint64              `json:"memoryCache"`
	PIDs                 uint64              `json:"pids"`
	BlockReadBytes       uint64              `json:"blockReadBytes"`
	BlockWriteBytes      uint64              `json:"blockWriteBytes"`
	Networks             []NetworkStatistics `json:"networks"`
}
type NetworkStatistics struct {
	Name      string `json:"name"`
	RXBytes   uint64 `json:"rxBytes"`
	RXPackets uint64 `json:"rxPackets"`
	RXErrors  uint64 `json:"rxErrors"`
	TXBytes   uint64 `json:"txBytes"`
	TXPackets uint64 `json:"txPackets"`
	TXErrors  uint64 `json:"txErrors"`
}
type Process struct {
	PID     int    `json:"pid"`
	User    string `json:"user"`
	Command string `json:"command"`
}
type Ownership struct {
	Path  string `json:"path"`
	User  uint32 `json:"user"`
	Group uint32 `json:"group"`
}

var copyInFreezeMutex sync.Mutex

func CopyIn(pid int, source, destination string, ownership []Ownership) error {
	// The temporary removal namespace must live on the same mount as the copy
	// destination. That makes it visible from the workload mount namespace, and
	// Linux has no unlink-by-descriptor operation for directories. Serialize
	// copy-in operations and freeze the entire workload cgroup so even a
	// privileged workload cannot replace namespace pathnames between mkdir/open
	// or identity-check/rmdir. Namespace helpers still validate identities and
	// fail closed for corruption by actors outside the workload cgroup.
	copyInFreezeMutex.Lock()
	defer copyInFreezeMutex.Unlock()
	return withWorkloadFrozenForCopy(
		pid, systemWorkloadFreezeOperations(),
		func() error {
			root, err := openContainerRoot(pid)
			if err != nil {
				return err
			}
			defer root.Close()
			transfer, err := openTransferDirectory("/run/cengine/io", source)
			if err != nil {
				return err
			}
			defer transfer.close()
			if err := copyIntoRoot(root, transfer.directory, destination, ownership); err != nil {
				return err
			}
			if err := transfer.validate(); err != nil {
				return err
			}
			return unix.Syncfs(int(root.Fd()))
		},
	)
}

type workloadFreezeOperations struct {
	cgroupPath func(int) (string, error)
	readFile   func(string) ([]byte, error)
	writeFile  func(string, []byte, os.FileMode) error
	wait       func(string, bool) error
}

func systemWorkloadFreezeOperations() workloadFreezeOperations {
	return workloadFreezeOperations{
		cgroupPath: workloadCgroupPath,
		readFile:   os.ReadFile,
		writeFile:  os.WriteFile,
		wait:       waitForCgroupFreezeState,
	}
}

type workloadFreeze struct {
	path       string
	changed    bool
	operations workloadFreezeOperations
}

func withWorkloadFrozenForCopy(
	pid int, operations workloadFreezeOperations, copyOperation func() error,
) (resultErr error) {
	freeze, acquireErr := freezeWorkloadForCopy(pid, operations)
	if acquireErr != nil {
		if freeze != nil && freeze.changed {
			if retryErr := freeze.resume(); retryErr != nil {
				return errors.Join(
					acquireErr,
					fmt.Errorf("retry restoration after failed workload freeze acquisition: %w", retryErr),
				)
			}
		}
		return acquireErr
	}
	defer func() {
		if resumeErr := resumeWorkloadAfterCopy(freeze); resumeErr != nil {
			resultErr = errors.Join(resultErr, resumeErr)
		}
	}()
	return copyOperation()
}

func freezeWorkloadForCopy(
	pid int, operations workloadFreezeOperations,
) (*workloadFreeze, error) {
	freeze := &workloadFreeze{operations: operations}
	if pid <= 0 {
		return freeze, nil
	}
	cgroup, err := operations.cgroupPath(pid)
	if err != nil {
		return freeze, err
	}
	freeze.path = cgroup
	state, err := operations.readFile(filepath.Join(cgroup, "cgroup.freeze"))
	if err != nil {
		return freeze, fmt.Errorf("read workload freeze state: %w", err)
	}
	switch strings.TrimSpace(string(state)) {
	case "1":
		if err := operations.wait(cgroup, true); err != nil {
			return freeze, fmt.Errorf("confirm previously frozen workload state: %w", err)
		}
		return freeze, nil
	case "0":
	default:
		return freeze, errors.New("invalid workload freeze state")
	}
	// Set changed before the write attempt. A failed cgroupfs write is not
	// assumed to be side-effect free; every failure from this point restores the
	// prior running state and preserves the guard for a retry if restoration
	// itself fails.
	freeze.changed = true
	if err := operations.writeFile(
		filepath.Join(cgroup, "cgroup.freeze"), []byte("1"), 0o644,
	); err != nil {
		return restoreAfterFreezeAcquisitionFailure(
			freeze, fmt.Errorf("set workload freeze state for copy: %w", err),
		)
	}
	if err := operations.wait(cgroup, true); err != nil {
		return restoreAfterFreezeAcquisitionFailure(
			freeze, fmt.Errorf("confirm workload frozen for copy: %w", err),
		)
	}
	return freeze, nil
}

func (freeze *workloadFreeze) resume() error {
	if freeze == nil || !freeze.changed {
		return nil
	}
	if err := freeze.operations.writeFile(
		filepath.Join(freeze.path, "cgroup.freeze"), []byte("0"), 0o644,
	); err != nil {
		return fmt.Errorf("set workload freeze state to running: %w", err)
	}
	if err := freeze.operations.wait(freeze.path, false); err != nil {
		return fmt.Errorf("confirm workload resumed: %w", err)
	}
	freeze.changed = false
	return nil
}

func restoreAfterFreezeAcquisitionFailure(
	freeze *workloadFreeze, acquisitionErr error,
) (*workloadFreeze, error) {
	if restorationErr := freeze.resume(); restorationErr != nil {
		return freeze, errors.Join(
			acquisitionErr,
			fmt.Errorf("restore prior workload state after failed freeze acquisition: %w", restorationErr),
		)
	}
	return freeze, acquisitionErr
}

func resumeWorkloadAfterCopy(freeze *workloadFreeze) error {
	resumeErr := freeze.resume()
	if resumeErr == nil {
		return nil
	}
	result := fmt.Errorf("resume workload after copy: %w", resumeErr)
	if freeze.changed {
		if retryErr := freeze.resume(); retryErr != nil {
			return errors.Join(
				result,
				fmt.Errorf("retry resume workload after copy: %w", retryErr),
			)
		}
	}
	return result
}

func workloadCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("read workload cgroup: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		relative := filepath.Clean("/" + strings.TrimPrefix(parts[2], "/"))
		if relative == "/" {
			return "", errors.New("refusing to freeze the guest root cgroup")
		}
		return filepath.Join("/sys/fs/cgroup", relative), nil
	}
	return "", errors.New("workload unified cgroup was not found")
}

func waitForCgroupFreezeState(cgroup string, frozen bool) error {
	want := "0"
	if frozen {
		want = "1"
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(filepath.Join(cgroup, "cgroup.events"))
		if err != nil {
			return fmt.Errorf("read workload cgroup events: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "frozen" && fields[1] == want {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for workload frozen=%s", want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func CopyOut(pid int, source, destination string) error {
	root, err := openContainerRoot(pid)
	if err != nil {
		return err
	}
	defer root.Close()
	transfer, err := openTransferDirectory("/run/cengine/io", destination)
	if err != nil {
		return err
	}
	defer transfer.close()
	entries, err := transfer.directory.ReadDir(-1)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("copy-out transfer directory is not empty")
	}
	if err := copyOutOfRoot(root, source, transfer.directory); err != nil {
		return err
	}
	return transfer.validate()
}

func copyIntoRoot(root, source *os.File, destination string, ownership []Ownership) error {
	target, err := openOrCreateDirectoryInRoot(root, destination)
	if err != nil {
		return err
	}
	defer target.Close()
	if err := copyDirectoryContents(source, target); err != nil {
		return err
	}
	return applyOwnership(target, ownership)
}

func copyOutOfRoot(root *os.File, source string, target *os.File) error {
	relative, err := containerRelativePath(source)
	if err != nil {
		return err
	}
	if relative == "." {
		return copyOpenDirectory(
			root, int(target.Fd()), filepath.Base(filepath.Clean(root.Name())),
		)
	}
	parent, err := openDirectoryInRoot(root, filepath.Dir(relative))
	if err != nil {
		return err
	}
	defer parent.Close()
	return copyEntryAt(
		int(parent.Fd()), filepath.Base(relative),
		int(target.Fd()), filepath.Base(relative),
	)
}

func copyOpenDirectory(source *os.File, targetParent int, targetName string) error {
	var original unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &original); err != nil {
		return err
	}
	if original.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("copy source root is not a directory")
	}
	if err := unix.Mkdirat(targetParent, targetName, 0o700); err != nil {
		return err
	}
	target, err := unix.Openat(
		targetParent, targetName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	targetDirectory := os.NewFile(uintptr(target), targetName)
	defer targetDirectory.Close()
	if err := copyDirectoryContents(source, targetDirectory); err != nil {
		return err
	}
	if err := unix.Fchmod(target, original.Mode&07777); err != nil {
		return err
	}
	return requireIdentity(int(source.Fd()), original)
}

type transferDirectory struct {
	parent    *os.File
	directory *os.File
	name      string
	identity  unix.Stat_t
}

func openTransferDirectory(root, name string) (*transferDirectory, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, syscall.EINVAL
	}
	parent, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	descriptor, err := unix.Openat(
		int(parent.Fd()), name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		parent.Close()
		return nil, err
	}
	directory := os.NewFile(uintptr(descriptor), name)
	var identity unix.Stat_t
	if err := unix.Fstat(descriptor, &identity); err != nil {
		directory.Close()
		parent.Close()
		return nil, err
	}
	return &transferDirectory{
		parent: parent, directory: directory, name: name, identity: identity,
	}, nil
}

func (directory *transferDirectory) close() {
	directory.directory.Close()
	directory.parent.Close()
}

func (directory *transferDirectory) validate() error {
	var current unix.Stat_t
	if err := unix.Fstatat(
		int(directory.parent.Fd()), directory.name, &current, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("copy transfer directory changed: %w", err)
	}
	if current.Mode&unix.S_IFMT != unix.S_IFDIR ||
		current.Dev != directory.identity.Dev || current.Ino != directory.identity.Ino {
		return errors.New("copy transfer directory changed")
	}
	return nil
}

func copyDirectoryContents(source, target *os.File) error {
	entries, err := source.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := copyEntryAt(
			int(source.Fd()), entry.Name(), int(target.Fd()), entry.Name(),
		); err != nil {
			return err
		}
	}
	return nil
}

func copyEntryAt(sourceParent int, sourceName string, targetParent int, targetName string) error {
	return copyEntryAtWithHooks(sourceParent, sourceName, targetParent, targetName, nil, nil, nil)
}

func copyEntryAtWithHooks(
	sourceParent int,
	sourceName string,
	targetParent int,
	targetName string,
	afterSymlinkOpen func() error,
	beforeFinalValidation func() error,
	afterDestinationIdentityValidation func() error,
) error {
	var original unix.Stat_t
	if err := unix.Fstatat(sourceParent, sourceName, &original, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	destinationExisting, destinationExists, err := optionalIdentityAt(targetParent, targetName)
	if err != nil {
		return err
	}
	var destinationOriginal unix.Stat_t
	destinationCaptured := false
	destinationDescriptor := -1
	var copiedSymlinkTarget string

	switch original.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		source, err := unix.Openat(
			sourceParent, sourceName,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return err
		}
		sourceDirectory := os.NewFile(uintptr(source), sourceName)
		defer sourceDirectory.Close()
		if err := requireIdentity(source, original); err != nil {
			return err
		}
		var targetNameTemporary string
		openedTargetName := targetName
		temporaryIdentity := unix.Stat_t{}
		temporaryExists := false
		if destinationExists && destinationExisting.Mode&unix.S_IFMT != unix.S_IFDIR {
			targetNameTemporary, err = createTemporaryDirectoryAt(targetParent)
			if err != nil {
				return err
			}
			temporaryExists = true
			defer func() {
				if temporaryExists {
					_ = removeExactEntryAt(targetParent, targetNameTemporary, temporaryIdentity)
				}
			}()
			openedTargetName = targetNameTemporary
		} else if !destinationExists {
			if err := unix.Mkdirat(targetParent, targetName, 0o700); err != nil {
				return err
			}
		}
		target, err := unix.Openat(
			targetParent, openedTargetName,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return err
		}
		targetDirectory := os.NewFile(uintptr(target), targetName)
		defer targetDirectory.Close()
		if err := unix.Fstat(target, &destinationOriginal); err != nil {
			return err
		}
		if temporaryExists {
			temporaryIdentity = destinationOriginal
		} else if destinationExists && !sameIdentity(destinationOriginal, destinationExisting) {
			return errors.New("copy destination entry changed")
		}
		destinationCaptured = true
		if err := copyDirectoryContents(sourceDirectory, targetDirectory); err != nil {
			return err
		}
		if err := unix.Fchmod(target, original.Mode&07777); err != nil {
			return err
		}
		if temporaryExists {
			if err := installStagedEntry(
				targetParent, targetNameTemporary, targetName, temporaryIdentity,
				destinationExisting, true,
			); err != nil {
				return err
			}
			temporaryExists = false
			destinationOriginal = temporaryIdentity
		}

	case unix.S_IFREG:
		source, err := unix.Openat(
			sourceParent, sourceName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if err != nil {
			return err
		}
		input := os.NewFile(uintptr(source), sourceName)
		defer input.Close()
		if err := requireIdentity(source, original); err != nil {
			return err
		}
		targetNameTemporary, target, err := createTemporaryRegularAt(targetParent)
		if err != nil {
			return err
		}
		temporaryIdentity := unix.Stat_t{}
		temporaryExists := true
		defer func() {
			if temporaryExists {
				_ = removeExactEntryAt(targetParent, targetNameTemporary, temporaryIdentity)
			}
		}()
		output := os.NewFile(uintptr(target), targetNameTemporary)
		if err := unix.Fstat(target, &temporaryIdentity); err != nil {
			output.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		if copyErr == nil {
			copyErr = unix.Fchmod(target, original.Mode&07777)
		}
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err := installStagedEntry(
			targetParent, targetNameTemporary, targetName, temporaryIdentity,
			destinationExisting, destinationExists,
		); err != nil {
			return err
		}
		temporaryExists = false
		destinationOriginal = temporaryIdentity
		destinationCaptured = true

	case unix.S_IFLNK:
		descriptor, err := unix.Openat(
			sourceParent, sourceName, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if err != nil {
			return err
		}
		sourceLink := os.NewFile(uintptr(descriptor), sourceName)
		defer sourceLink.Close()
		if err := requireIdentity(descriptor, original); err != nil {
			return err
		}
		if afterSymlinkOpen != nil {
			if err := afterSymlinkOpen(); err != nil {
				return err
			}
		}
		linkTarget, err := readLinkAt(descriptor, "")
		if err != nil {
			return err
		}
		targetNameTemporary, err := createTemporarySymlinkAt(targetParent, linkTarget)
		if err != nil {
			return err
		}
		temporaryIdentity, temporaryCaptured, err := optionalIdentityAt(targetParent, targetNameTemporary)
		if err != nil {
			_ = unix.Unlinkat(targetParent, targetNameTemporary, 0)
			return err
		}
		if !temporaryCaptured {
			return errors.New("copy destination symbolic link changed")
		}
		temporaryExists := true
		defer func() {
			if temporaryExists {
				_ = removeExactEntryAt(targetParent, targetNameTemporary, temporaryIdentity)
			}
		}()
		targetDescriptor, err := unix.Openat(
			targetParent, targetNameTemporary, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if err != nil {
			return err
		}
		destinationDescriptor = targetDescriptor
		targetLink := os.NewFile(uintptr(targetDescriptor), targetNameTemporary)
		defer targetLink.Close()
		if err := requireIdentity(targetDescriptor, temporaryIdentity); err != nil {
			return err
		}
		createdTarget, err := readLinkAt(targetDescriptor, "")
		if err != nil {
			return err
		}
		if createdTarget != linkTarget {
			return errors.New("copy destination symbolic link changed")
		}
		if err := installStagedEntry(
			targetParent, targetNameTemporary, targetName, temporaryIdentity,
			destinationExisting, destinationExists,
		); err != nil {
			return err
		}
		temporaryExists = false
		destinationOriginal = temporaryIdentity
		destinationCaptured = true
		copiedSymlinkTarget = linkTarget

	default:
		return fmt.Errorf("unsupported transfer entry %s", sourceName)
	}
	if beforeFinalValidation != nil {
		if err := beforeFinalValidation(); err != nil {
			return err
		}
	}

	var current unix.Stat_t
	if err := unix.Fstatat(sourceParent, sourceName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("copy source entry changed: %w", err)
	}
	if !sameIdentity(current, original) {
		return errors.New("copy source entry changed")
	}
	if !destinationCaptured {
		return errors.New("copy destination identity was not captured")
	}
	var destinationCurrent unix.Stat_t
	if err := unix.Fstatat(
		targetParent, targetName, &destinationCurrent, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("copy destination entry changed: %w", err)
	}
	if !sameIdentity(destinationCurrent, destinationOriginal) {
		return errors.New("copy destination entry changed")
	}
	if afterDestinationIdentityValidation != nil {
		if err := afterDestinationIdentityValidation(); err != nil {
			return err
		}
	}
	if destinationOriginal.Mode&unix.S_IFMT == unix.S_IFLNK {
		expectedTarget, err := readLinkAt(destinationDescriptor, "")
		if err != nil {
			return err
		}
		if expectedTarget != copiedSymlinkTarget {
			return errors.New("copy destination symbolic link changed")
		}
	}
	if err := unix.Fstatat(
		targetParent, targetName, &destinationCurrent, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("copy destination entry changed: %w", err)
	}
	if !sameIdentity(destinationCurrent, destinationOriginal) {
		return errors.New("copy destination entry changed")
	}
	return nil
}

func optionalIdentityAt(parent int, name string) (unix.Stat_t, bool, error) {
	var identity unix.Stat_t
	if err := unix.Fstatat(parent, name, &identity, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return unix.Stat_t{}, false, nil
		}
		return unix.Stat_t{}, false, err
	}
	return identity, true, nil
}

func sameIdentity(current, expected unix.Stat_t) bool {
	return current.Mode&unix.S_IFMT == expected.Mode&unix.S_IFMT &&
		current.Dev == expected.Dev && current.Ino == expected.Ino
}

func temporaryEntryName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".cengine-copy-" + hex.EncodeToString(random[:]), nil
}

func createTemporaryRegularAt(parent int) (string, int, error) {
	for attempts := 0; attempts < 16; attempts++ {
		name, err := temporaryEntryName()
		if err != nil {
			return "", -1, err
		}
		descriptor, err := unix.Openat(
			parent, name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0o600,
		)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return "", -1, err
		}
		return name, descriptor, nil
	}
	return "", -1, errors.New("could not allocate temporary copy destination")
}

func createTemporarySymlinkAt(parent int, target string) (string, error) {
	for attempts := 0; attempts < 16; attempts++ {
		name, err := temporaryEntryName()
		if err != nil {
			return "", err
		}
		err = unix.Symlinkat(target, parent, name)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("could not allocate temporary copy destination")
}

func createTemporaryDirectoryAt(parent int) (string, error) {
	for attempts := 0; attempts < 16; attempts++ {
		name, err := temporaryEntryName()
		if err != nil {
			return "", err
		}
		err = unix.Mkdirat(parent, name, 0o700)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("could not allocate temporary copy destination")
}

func installStagedEntry(
	parent int,
	temporaryName string,
	targetName string,
	temporaryIdentity unix.Stat_t,
	existingIdentity unix.Stat_t,
	existing bool,
) error {
	return installStagedEntryWithHook(
		parent, temporaryName, targetName, temporaryIdentity,
		existingIdentity, existing, nil,
	)
}

func installStagedEntryWithHook(
	parent int,
	temporaryName string,
	targetName string,
	temporaryIdentity unix.Stat_t,
	existingIdentity unix.Stat_t,
	existing bool,
	beforeExchange func() error,
) error {
	if !existing {
		if err := unix.Renameat2(
			parent, temporaryName, parent, targetName, unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("copy destination entry changed: %w", err)
		}
		return nil
	}
	current, exists, err := optionalIdentityAt(parent, targetName)
	if err != nil {
		return err
	}
	if !exists || !sameIdentity(current, existingIdentity) {
		return errors.New("copy destination entry changed")
	}
	if beforeExchange != nil {
		if err := beforeExchange(); err != nil {
			return err
		}
	}
	if err := unix.Renameat2(
		parent, temporaryName, parent, targetName, unix.RENAME_EXCHANGE,
	); err != nil {
		return err
	}
	displaced, exists, err := optionalIdentityAt(parent, temporaryName)
	if err != nil || !exists || !sameIdentity(displaced, existingIdentity) {
		rollbackErr := rollbackStagedExchange(
			parent, temporaryName, targetName, temporaryIdentity,
		)
		if rollbackErr != nil {
			return fmt.Errorf("copy destination entry changed; rollback failed: %w", rollbackErr)
		}
		if err != nil {
			return fmt.Errorf("copy destination entry changed: %w", err)
		}
		return errors.New("copy destination entry changed")
	}
	if err := removeExactEntryAt(parent, temporaryName, existingIdentity); err != nil {
		return fmt.Errorf("remove replaced copy destination: %w", err)
	}
	return nil
}

func rollbackStagedExchange(
	parent int, temporaryName, targetName string, temporaryIdentity unix.Stat_t,
) error {
	current, exists, err := optionalIdentityAt(parent, targetName)
	if err != nil {
		return err
	}
	if !exists || !sameIdentity(current, temporaryIdentity) {
		return errors.New("installed copy destination changed")
	}
	return unix.Renameat2(
		parent, temporaryName, parent, targetName, unix.RENAME_EXCHANGE,
	)
}

func removeExactEntryAt(parent int, name string, expected unix.Stat_t) error {
	return removeExactEntryAtWithHook(parent, name, expected, nil)
}

type removalHook func(parent int, name string, expected unix.Stat_t) error

type removalNamespace struct {
	parent    int
	name      string
	directory *os.File
	identity  unix.Stat_t
}

func createRemovalNamespaceAt(parent int) (*removalNamespace, error) {
	return createRemovalNamespaceAtWithHook(parent, nil)
}

type namespaceCreateHook func(parent int, name string, expected unix.Stat_t) error

func createRemovalNamespaceAtWithHook(
	parent int, afterIdentity namespaceCreateHook,
) (*removalNamespace, error) {
	for attempts := 0; attempts < 16; attempts++ {
		name, err := temporaryEntryName()
		if err != nil {
			return nil, err
		}
		if err := unix.Mkdirat(parent, name, 0o700); errors.Is(err, syscall.EEXIST) {
			continue
		} else if err != nil {
			return nil, err
		}
		// mkdirat does not return an inode descriptor. CopyIn holds the workload
		// cgroup frozen across this capture/open sequence; this identity check
		// additionally detects substitution by an actor outside that cgroup and
		// deliberately leaves either directory untouched on ambiguity.
		identity, exists, err := optionalIdentityAt(parent, name)
		if err != nil || !exists || identity.Mode&unix.S_IFMT != unix.S_IFDIR {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("copy removal namespace changed during creation")
		}
		if afterIdentity != nil {
			if err := afterIdentity(parent, name, identity); err != nil {
				return nil, err
			}
		}
		descriptor, err := unix.Openat(
			parent, name,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("open copy removal namespace: %w", err)
		}
		directory := os.NewFile(uintptr(descriptor), name)
		if err := requireIdentity(descriptor, identity); err != nil {
			directory.Close()
			return nil, errors.New("copy removal namespace changed during creation")
		}
		return &removalNamespace{
			parent: parent, name: name, directory: directory, identity: identity,
		}, nil
	}
	return nil, errors.New("could not allocate copy removal namespace")
}

func (namespace *removalNamespace) close() error {
	return namespace.closeWithHook(nil)
}

func (namespace *removalNamespace) closeWithHook(beforeRemove namespaceCreateHook) error {
	defer namespace.directory.Close()
	current, exists, err := optionalIdentityAt(namespace.parent, namespace.name)
	if err != nil {
		return err
	}
	if !exists || !sameIdentity(current, namespace.identity) {
		return errors.New("copy removal namespace changed")
	}
	if beforeRemove != nil {
		if err := beforeRemove(namespace.parent, namespace.name, namespace.identity); err != nil {
			return err
		}
	}
	current, exists, err = optionalIdentityAt(namespace.parent, namespace.name)
	if err != nil {
		return err
	}
	if !exists || !sameIdentity(current, namespace.identity) {
		return errors.New("copy removal namespace changed")
	}
	// This is intentionally not described as a compare-and-unlink operation:
	// Linux provides no such primitive for an open directory. Production calls
	// reach this point only while the workload cgroup is frozen. A nonempty or
	// ambiguous namespace is retained rather than recursively cleaned by name.
	if err := unix.Unlinkat(namespace.parent, namespace.name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove copy removal namespace: %w", err)
	}
	return nil
}

func removeExactEntryAtWithHook(
	parent int, name string, expected unix.Stat_t, hook removalHook,
) error {
	namespace, err := createRemovalNamespaceAt(parent)
	if err != nil {
		return err
	}
	removeErr := namespace.claimAndRemove(parent, name, expected, hook)
	closeErr := namespace.close()
	if removeErr != nil {
		if closeErr != nil {
			return fmt.Errorf("%w; removal quarantine retained: %v", removeErr, closeErr)
		}
		return removeErr
	}
	return closeErr
}

func (namespace *removalNamespace) claimAndRemove(
	sourceParent int, sourceName string, expected unix.Stat_t, hook removalHook,
) error {
	claimName, err := temporaryEntryName()
	if err != nil {
		return err
	}
	if err := unix.Renameat2(
		sourceParent, sourceName,
		int(namespace.directory.Fd()), claimName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("claim copy destination for removal: %w", err)
	}
	claimed, exists, err := optionalIdentityAt(int(namespace.directory.Fd()), claimName)
	if err != nil || !exists || !sameIdentity(claimed, expected) {
		restoreErr := unix.Renameat2(
			int(namespace.directory.Fd()), claimName,
			sourceParent, sourceName,
			unix.RENAME_NOREPLACE,
		)
		if restoreErr != nil {
			return fmt.Errorf("copy destination changed; foreign entry quarantined: %w", restoreErr)
		}
		if err != nil {
			return fmt.Errorf("copy destination changed: %w", err)
		}
		return errors.New("copy destination changed")
	}
	if hook != nil {
		if err := hook(sourceParent, sourceName, expected); err != nil {
			return err
		}
	}
	if expected.Mode&unix.S_IFMT == unix.S_IFDIR {
		if err := namespace.removeClaimedDirectory(claimName, expected, hook); err != nil {
			return err
		}
	} else {
		current, exists, err := optionalIdentityAt(int(namespace.directory.Fd()), claimName)
		if err != nil {
			return err
		}
		if !exists || !sameIdentity(current, expected) {
			return errors.New("claimed copy destination changed")
		}
		if err := unix.Unlinkat(int(namespace.directory.Fd()), claimName, 0); err != nil {
			return err
		}
	}
	if _, exists, err := optionalIdentityAt(sourceParent, sourceName); err != nil {
		return err
	} else if exists {
		return errors.New("copy destination changed during removal")
	}
	return nil
}

func (namespace *removalNamespace) removeClaimedDirectory(
	claimName string, expected unix.Stat_t, hook removalHook,
) error {
	descriptor, err := unix.Openat(
		int(namespace.directory.Fd()), claimName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(descriptor), claimName)
	defer directory.Close()
	if err := requireIdentity(descriptor, expected); err != nil {
		return errors.New("claimed copy destination changed")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		identity, exists, err := optionalIdentityAt(descriptor, entry.Name())
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := namespace.claimAndRemove(descriptor, entry.Name(), identity, hook); err != nil {
			return err
		}
	}
	current, exists, err := optionalIdentityAt(int(namespace.directory.Fd()), claimName)
	if err != nil {
		return err
	}
	if !exists || !sameIdentity(current, expected) {
		return errors.New("claimed copy destination changed")
	}
	return unix.Unlinkat(int(namespace.directory.Fd()), claimName, unix.AT_REMOVEDIR)
}

func requireIdentity(descriptor int, expected unix.Stat_t) error {
	var current unix.Stat_t
	if err := unix.Fstat(descriptor, &current); err != nil {
		return err
	}
	if current.Mode&unix.S_IFMT != expected.Mode&unix.S_IFMT ||
		current.Dev != expected.Dev || current.Ino != expected.Ino {
		return errors.New("copy source entry changed")
	}
	return nil
}

func readLinkAt(parent int, name string) (string, error) {
	size := 256
	for size <= 64*1024 {
		buffer := make([]byte, size)
		count, err := unix.Readlinkat(parent, name, buffer)
		if err != nil {
			return "", err
		}
		if count < len(buffer) {
			return string(buffer[:count]), nil
		}
		size *= 2
	}
	return "", syscall.ENAMETOOLONG
}

func Stats(pid int) (Statistics, error) {
	var result Statistics
	fields, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return result, err
	}
	parts := strings.Fields(string(fields))
	if len(parts) < 15 {
		return result, errors.New("invalid process stat")
	}
	user, _ := strconv.ParseUint(parts[13], 10, 64)
	system, _ := strconv.ParseUint(parts[14], 10, 64)
	result.CPUUserNanoseconds = user * 10_000_000
	result.CPUSystemNanoseconds = system * 10_000_000
	result.CPUTotalNanoseconds = result.CPUUserNanoseconds + result.CPUSystemNanoseconds
	status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			result.MemoryUsage = parseKB(line)
		}
	}
	ioData, _ := os.ReadFile(fmt.Sprintf("/proc/%d/io", pid))
	for _, line := range strings.Split(string(ioData), "\n") {
		if strings.HasPrefix(line, "read_bytes:") {
			result.BlockReadBytes = parseValue(line)
		}
		if strings.HasPrefix(line, "write_bytes:") {
			result.BlockWriteBytes = parseValue(line)
		}
	}
	processes, _ := os.ReadDir(fmt.Sprintf("/proc/%d/root/proc", pid))
	for _, entry := range processes {
		if entry.IsDir() {
			if _, err := strconv.Atoi(entry.Name()); err == nil {
				result.PIDs++
			}
		}
	}
	networkRoot := fmt.Sprintf("/proc/%d/root/sys/class/net", pid)
	interfaces, _ := os.ReadDir(networkRoot)
	for _, entry := range interfaces {
		if entry.Name() == "lo" {
			continue
		}
		base := filepath.Join(networkRoot, entry.Name(), "statistics")
		result.Networks = append(result.Networks, NetworkStatistics{Name: entry.Name(), RXBytes: readUint(base + "/rx_bytes"), RXPackets: readUint(base + "/rx_packets"), RXErrors: readUint(base + "/rx_errors"), TXBytes: readUint(base + "/tx_bytes"), TXPackets: readUint(base + "/tx_packets"), TXErrors: readUint(base + "/tx_errors")})
	}
	return result, nil
}

func Top(pid int) ([]Process, error) {
	root := fmt.Sprintf("/proc/%d/root/proc", pid)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []Process
	for _, entry := range entries {
		number, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		command, _ := os.ReadFile(filepath.Join(root, entry.Name(), "cmdline"))
		command = stringsToSpaces(command)
		status, _ := os.ReadFile(filepath.Join(root, entry.Name(), "status"))
		user := "0"
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					user = fields[1]
				}
				break
			}
		}
		result = append(result, Process{PID: number, User: user, Command: string(command)})
	}
	return result, nil
}

func mountedRoot() (string, error) {
	root := "/run/cengine/rootfs"
	if err := disk.EnsureExt4("/dev/vda", root, "cengine-root"); err != nil {
		return "", err
	}
	return root, nil
}
func containerRoot(pid int) (string, error) {
	if pid <= 0 {
		return mountedRoot()
	}
	root := fmt.Sprintf("/proc/%d/root", pid)
	if _, err := os.Stat(root); err != nil {
		return "", fmt.Errorf("open workload root: %w", err)
	}
	return root, nil
}

func openContainerRoot(pid int) (*os.File, error) {
	root, err := containerRoot(pid)
	if err != nil {
		return nil, err
	}
	descriptor, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open workload root: %w", err)
	}
	return os.NewFile(uintptr(descriptor), root), nil
}

func containerRelativePath(value string) (string, error) {
	if !filepath.IsAbs(value) {
		return "", syscall.EINVAL
	}
	clean := filepath.Clean(value)
	if clean == "/" {
		return ".", nil
	}
	relative := strings.TrimPrefix(clean, "/")
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return "", syscall.EPERM
	}
	return relative, nil
}

func openDirectoryInRoot(root *os.File, relative string) (*os.File, error) {
	return openPathInRoot(root, relative, unix.O_RDONLY|unix.O_DIRECTORY)
}

func openPathInRoot(root *os.File, relative string, flags int) (*os.File, error) {
	descriptor, err := unix.Openat2(
		int(root.Fd()), relative,
		&unix.OpenHow{
			Flags:   uint64(flags | unix.O_CLOEXEC),
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		},
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), relative), nil
}

func openOrCreateDirectoryInRoot(root *os.File, value string) (*os.File, error) {
	relative, err := containerRelativePath(value)
	if err != nil {
		return nil, err
	}
	current, err := openDirectoryInRoot(root, ".")
	if err != nil {
		return nil, err
	}
	if relative == "." {
		return current, nil
	}
	var components []string
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		components = append(components, component)
		next, openErr := openDirectoryInRoot(root, filepath.Join(components...))
		if openErr != nil {
			if !errors.Is(openErr, syscall.ENOENT) {
				current.Close()
				return nil, openErr
			}
			if mkdirErr := unix.Mkdirat(int(current.Fd()), component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				current.Close()
				return nil, mkdirErr
			}
			next, openErr = openDirectoryInRoot(root, filepath.Join(components...))
			if openErr != nil {
				current.Close()
				return nil, openErr
			}
		}
		current.Close()
		current = next
	}
	return current, nil
}

func applyOwnership(root *os.File, ownership []Ownership) error {
	for _, owner := range ownership {
		relative, err := archiveRelativePath(owner.Path)
		if err != nil {
			return err
		}
		target, err := openPathInRoot(root, relative, unix.O_PATH|unix.O_NOFOLLOW)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		chownErr := unix.Fchownat(
			int(target.Fd()), "", int(owner.User), int(owner.Group),
			unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		)
		target.Close()
		if chownErr != nil {
			return chownErr
		}
	}
	return nil
}

func archivePath(root, value string) (string, error) {
	relative, err := archiveRelativePath(value)
	if err != nil {
		return "", err
	}
	if relative == "." {
		return root, nil
	}
	return filepath.Join(root, relative), nil
}

func archiveRelativePath(value string) (string, error) {
	if value == "" || filepath.IsAbs(value) {
		return "", syscall.EINVAL
	}
	clean := filepath.Clean(value)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", syscall.EPERM
	}
	return clean, nil
}
func parseKB(line string) uint64 { return parseValue(line) * 1024 }
func parseValue(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	value, _ := strconv.ParseUint(fields[1], 10, 64)
	return value
}
func readUint(path string) uint64 {
	data, _ := os.ReadFile(path)
	value, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return value
}
func stringsToSpaces(value []byte) []byte {
	for index := range value {
		if value[index] == 0 {
			value[index] = ' '
		}
	}
	return []byte(strings.TrimSpace(string(value)))
}
