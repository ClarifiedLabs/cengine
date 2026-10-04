//go:build linux

// RTM-081/082/083/085/087 only: setup and one selected native test inside an owned guest VM.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Closed selection: neither environment nor caller input supplies a test pattern.
func selectedTest(caseID string) (string, error) {
	switch caseID {
	case "RTM-081":
		return "TestNativeMountedManagedV3InterruptGraceful", nil
	case "RTM-082":
		return "TestNativeMountedManagedV3WriteBurstGraceful", nil
	case "RTM-083":
		return "TestNativeMountedManagedV3SparseMmapGraceful", nil
	case "RTM-085":
		return "TestNativeMountedManagedV3FsxGraceful", nil
	case "RTM-087":
		return "TestNativeIssuedDataTLSRejectsRetiredAndPreviousServiceCredentials", nil
	case "RTM-089":
		return "TestNativeServiceFaults|TestNativeServiceFaultPlanClosed", nil
	case "RTM-090":
		return "TestNativeFaultFinalSyncTupleUnderGate", nil
	case "RTM-091":
		return "TestDirectExt4CopyupSymlinkDoesNotTouchTargetXattrs|TestDirectExt4SymlinkXattrsRetainPinnedIdentity|TestDirectExt4SymlinkXattrFailureRollsBack|TestDirectExt4EmptySymlinkMetadataFailureRollsBack|TestDirectExt4CopyupPartialRootXattrFailureRollsBack", nil
	case "RTM-092":
		return "TestSymlinkValidCapabilityXattrsMatchDirectExt4", nil
	case "RTM-093":
		return "TestNativeIssuedPrepareInitializerPreflightV4", nil
	case "RTM-094":
		return "TestNativePendingProvisionFreshMountReplayV4", nil
	case "RTM-101":
		return "TestNativeSnapshot101DeadInitializerConsumers|TestNativeSnapshot101DirtyMmapWriteback|TestNativeSnapshot101HungAcceptedGuard|TestNativeSnapshot101PreBeginRenameUnlink|TestNativeSnapshot101ReadReaddirAtime|TestNativeSnapshot101RetainedWritableFD|TestNativeSnapshot101RuntimePoolSaturation|TestNativeSnapshot101SameUIDForeignTGID", nil
	case "RTM-095":
		return "TestCopyCleanupServerCrashRestoresExactRoot|TestCopyPendingReplayFreshSessionRootBootstrap|TestPrepareExt4IdentityRealFilesystem|TestPrepareIdentityAtRejectsIntermediateSymlink", nil
	case "RTM-102":
		return "TestNativePrepareIdentity102AuthorityJournal|TestNativePrepareIdentity102CrossFilesystem|TestNativePrepareIdentity102ForgetRelookup|TestNativePrepareIdentity102LargeManifestRecovery|TestNativePrepareIdentity102ManifestAuthenticity|TestNativePrepareIdentity102PublicationAuthenticity|TestNativePrepareIdentity102RegisteredRootReuse|TestNativePrepareIdentity102Reuse|TestNativePrepareIdentity102SameNameVolume|TestPrepareManifestPreserves64MiBBoundWithStreamingDigest", nil
	case "RTM-104":
		return "TestPrepareProcessLinuxPollEINTR|TestPrepareProcessLinuxThreadMembership|TestPrepareProcessLinuxDeathRetainsDeadOwner", nil
	case "RTM-107":
		return "TestDurabilityPolicyHelpers|TestNativeDurabilityPolicyProcessDeath", nil
	case "RTM-108":
		return "TestNativeRetirementRecoveryHelpers|TestNativeRetirementRecoveryProcessDeath", nil
	case "RTM-109":
		return "TestNativeCopyDataRecoveryHelpers|TestNativeCopyDataRecoveryProcessDeath", nil
	case "RTM-110":
		return "TestNativePrepareRetirementHelpers|TestNativePrepareRetirementProcessDeath", nil
	case "RTM-113":
		return "TestNativeLifecycleCheckpointAndTerminalSeal", nil
	default:
		return "", errors.New("unknown native case")
	}
}

// Fixed test wall budgets only. RTM-085 retains the full pinned fsx workload;
// other cases and the enclosing campaign/cleanup budgets are unchanged.
func selectedCaseBudget(caseID string) (string, time.Duration, error) {
	switch caseID {
	case "RTM-081", "RTM-082", "RTM-083", "RTM-087", "RTM-104":
		return "-test.timeout=90s", 95 * time.Second, nil
	case "RTM-085", "RTM-089", "RTM-091", "RTM-092", "RTM-093", "RTM-094", "RTM-095", "RTM-101", "RTM-102", "RTM-107", "RTM-108", "RTM-109", "RTM-110":
		return "-test.timeout=180s", 190 * time.Second, nil
	case "RTM-090":
		return "-test.timeout=120s", 130 * time.Second, nil
	case "RTM-113": // 65 real TLS takeovers; no widening of existing cases.
		return "-test.timeout=180s", 190 * time.Second, nil
	default:
		return "", 0, errors.New("unknown native case")
	}
}

const maxLog = 128 * 1024
const backingBytes = 128 << 20
const backingName = "rtm081-backing.img"
const logName = "rtm081-native.log"
const boundedPath = "/scratch/bounded"
const nodeDirName = "rtm081-loop"
const nodeDirPath = "/dev/" + nodeDirName

type filesystem struct {
	Type     int64  `json:"type"`
	Device   uint64 `json:"device"`
	ReadOnly bool   `json:"read_only"`
	Bytes    uint64 `json:"bytes"`
}
type result struct {
	PassedTests      []string   `json:"passed_tests"`
	Case             string     `json:"case"`
	Test             string     `json:"test"`
	Success          bool       `json:"success"`
	Exit             int        `json:"exit"`
	Passes           int        `json:"passes"`
	Skips            int        `json:"skips"`
	Kernel           string     `json:"kernel"`
	Architecture     string     `json:"architecture"`
	Root             filesystem `json:"root"`
	Scratch          filesystem `json:"scratch"`
	Tmp              filesystem `json:"tmp"`
	Bounded          filesystem `json:"bounded"`
	BackingBytes     uint64     `json:"backing_bytes"`
	LoopAutoclear    bool       `json:"loop_autoclear"`
	LoopClean        bool       `json:"loop_clean"`
	FormatterSHA     string     `json:"formatter_sha256"`
	FormatterChecked bool       `json:"formatter_checked"`
	Fusectl          bool       `json:"fusectl"`
	Uring            bool       `json:"uring_enabled"`
	Hardlinks        bool       `json:"protected_hardlinks"`
	TestSHA          string     `json:"test_sha256"`
	LogSHA           string     `json:"log_sha256"`
	LogBytes         int        `json:"log_bytes"`
	Failure          string     `json:"failure,omitempty"`
}

func fs(path string) (filesystem, error) {
	var s syscall.Statfs_t
	var st syscall.Stat_t
	if err := syscall.Statfs(path, &s); err != nil {
		return filesystem{}, err
	}
	if err := syscall.Stat(path, &st); err != nil {
		return filesystem{}, err
	}
	return filesystem{int64(s.Type), uint64(st.Dev), s.Flags&1 != 0, s.Blocks * uint64(s.Bsize)}, nil
}
func read(path string, maximum int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if len(b) > int(maximum) {
		return nil, errors.New("read bound")
	}
	return b, err
}
func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func setup(r *result) error {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" || runtime.GOARCH != "arm64" {
		return errors.New("guest identity")
	}
	var err error
	r.Architecture = runtime.GOARCH
	kernel, err := read("/proc/sys/kernel/osrelease", 256)
	if err != nil {
		return err
	}
	r.Kernel = strings.TrimSpace(string(kernel))
	if !regexp.MustCompile(`^6\.18\.[0-9A-Za-z.+_-]+$`).MatchString(r.Kernel) {
		return errors.New("kernel profile")
	}
	if r.Root, err = fs("/"); err != nil {
		return err
	}
	if r.Scratch, err = fs("/scratch"); err != nil {
		return err
	}
	if r.Tmp, err = fs("/tmp"); err != nil {
		return err
	}
	if r.Root.Type != 0xef53 || !r.Root.ReadOnly || r.Scratch.Type != 0xef53 || r.Scratch.ReadOnly || r.Root.Device == r.Scratch.Device || r.Scratch.Bytes == 0 || r.Scratch.Bytes > 512<<30 || r.Tmp.Type != 0x01021994 || r.Tmp.Bytes > 32<<20 || r.Tmp.ReadOnly {
		return errors.New("filesystem profile")
	}
	// Statfs alone is insufficient: /scratch must be a distinct direct ext4 mount.
	mountinfo, err := read("/proc/self/mountinfo", 65536)
	if err != nil {
		return err
	}
	matches := 0
	for _, line := range strings.Split(string(mountinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && strings.HasPrefix(fields[4], "/scratch/") {
			return errors.New("preexisting scratch submount")
		}
		if len(fields) > 7 && fields[4] == "/scratch" {
			separator := -1
			for i, field := range fields {
				if field == "-" {
					separator = i
					break
				}
			}
			if separator < 6 || len(fields) <= separator+2 || fields[3] != "/" || fields[separator+1] != "ext4" {
				return errors.New("scratch mount")
			}
			matches++
		}
	}
	if matches != 1 {
		return errors.New("scratch mount count")
	}
	info, err := os.Lstat("/dev/fuse")
	if os.IsNotExist(err) {
		if err = syscall.Mknod("/dev/fuse", syscall.S_IFCHR|0600, 10<<8|229); err != nil {
			return err
		}
		info, err = os.Lstat("/dev/fuse")
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice == 0 || info.Sys().(*syscall.Stat_t).Rdev != 10<<8|229 {
		return errors.New("fuse device")
	}
	for path, value := range map[string]string{"/sys/module/fuse/parameters/enable_uring": "Y\n", "/proc/sys/fs/protected_hardlinks": "1\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			return err
		}
		got, err := read(path, 32)
		if err != nil || string(got) != value {
			return errors.New("kernel setting")
		}
	}
	r.Uring, r.Hardlinks = true, true
	control, err := fs("/sys/fs/fuse/connections")
	if err != nil {
		return err
	}
	if control.Type != 0x65735543 {
		if control.Type != 0x62656572 {
			return errors.New("fusectl target")
		}
		if err := syscall.Mount("fusectl", "/sys/fs/fuse/connections", "fusectl", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
			return err
		}
	}
	control, err = fs("/sys/fs/fuse/connections")
	if err != nil || control.Type != 0x65735543 {
		return errors.New("fusectl mount")
	}
	r.Fusectl = true
	// Formatting may touch the entire backing, but may never extend it.
	// Only the native child lowers this further to the original 64 MiB/file.
	return syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: backingBytes, Max: backingBytes})
}

// regularBytes rejects links/devices and bounds reads of packed, read-only inputs.
func regularBytes(path string, maximum int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, named unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Mode&0022 != 0 || before.Size <= 0 || before.Size > maximum {
		return nil, errors.New("packed file profile")
	}
	b, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if err := unix.Lstat(path, &named); err != nil {
		return nil, err
	}
	if int64(len(b)) != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || after.Dev != named.Dev || after.Ino != named.Ino || after.Mode != named.Mode {
		return nil, errors.New("packed file changed")
	}
	return b, nil
}

func formatterDigest() (string, error) {
	b, err := regularBytes("/mke2fs", 32<<20)
	if err != nil {
		return "", err
	}
	image, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer image.Close()
	if image.Class != elf.ELFCLASS64 || image.Data != elf.ELFDATA2LSB || image.Machine != elf.EM_AARCH64 || (image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN) {
		return "", errors.New("formatter ELF profile")
	}
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			return "", errors.New("dynamic formatter interpreter")
		}
	}
	libraries, err := image.ImportedLibraries()
	if err != nil || len(libraries) != 0 {
		return "", errors.New("dynamic formatter dependencies")
	}
	return hash(b), nil
}

// Same ownership contract as Guest/internal/disk/explicit_runtime_linux_test.go:
// only successful atomic LOOP_CONFIGURE grants a lease; a busy candidate never does.
// All nonzero-sized data on the original direct scratch is this one 128 MiB backing
// and the one <=128 KiB log. The single scratch mountpoint is fixed metadata.
// Scratch remains nodev: private loop nodes live only in one fresh /dev directory.
type ownedLoop struct {
	scratch, backing, file, log *os.File
	devDir, nodeDir             *os.File
	devDirStat, nodeDirStat     unix.Stat_t
	dev, inode                  uint64
	minor                       uint32
	mountID                     string
	mounted                     bool
	nodes                       map[string]unix.Stat_t
	target                      unix.Stat_t
}

func exclusiveFile(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Size != 0 {
		f.Close()
		return nil, errors.New("fresh regular file identity")
	}
	return f, nil
}

func sameEntry(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Rdev == b.Rdev
}

func (l *ownedLoop) createNodeDirectory() error {
	fd, err := unix.Open("/dev", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	l.devDir = os.NewFile(uintptr(fd), "/dev")
	if err := unix.Fstat(fd, &l.devDirStat); err != nil {
		return err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return err
	}
	if l.devDirStat.Uid != 0 || l.devDirStat.Mode&0022 != 0 || filesystem.Flags&(unix.ST_NODEV|unix.ST_RDONLY) != 0 {
		return errors.New("device-capable trusted /dev required")
	}
	// mkdirat is exclusive: an existing directory or link is a hard failure.
	if err := unix.Mkdirat(fd, nodeDirName, 0700); err != nil {
		return err
	}
	nodeFD, err := unix.Openat(fd, nodeDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	l.nodeDir = os.NewFile(uintptr(nodeFD), nodeDirPath)
	if err := unix.Fstat(nodeFD, &l.nodeDirStat); err != nil {
		return err
	}
	if l.nodeDirStat.Dev != l.devDirStat.Dev || l.nodeDirStat.Mode != unix.S_IFDIR|0700 || l.nodeDirStat.Uid != 0 {
		return errors.New("fresh private node directory identity")
	}
	return l.validateNodeDirectory()
}

func (l *ownedLoop) validateNodeDirectory() error {
	var pinned, named unix.Stat_t
	if err := unix.Fstat(int(l.devDir.Fd()), &pinned); err != nil {
		return err
	}
	if err := unix.Lstat("/dev", &named); err != nil {
		return err
	}
	if !sameEntry(pinned, l.devDirStat) || !sameEntry(named, l.devDirStat) {
		return errors.New("device directory changed")
	}
	if err := unix.Fstat(int(l.nodeDir.Fd()), &pinned); err != nil {
		return err
	}
	if err := unix.Fstatat(int(l.devDir.Fd()), nodeDirName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameEntry(pinned, l.nodeDirStat) || !sameEntry(named, l.nodeDirStat) {
		return errors.New("private node directory changed")
	}
	return nil
}

func (l *ownedLoop) node(name string, kind uint32, major, minor uint32) (*os.File, error) {
	if err := l.validateNodeDirectory(); err != nil {
		return nil, err
	}
	device := unix.Mkdev(major, minor)
	// mknodat is exclusive: EEXIST is fatal, never open/adopt a supplied node.
	if err := unix.Mknodat(int(l.nodeDir.Fd()), name, kind|0600, int(device)); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(l.nodeDir.Fd()), name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Mode != kind|0600 || st.Rdev != device || st.Dev != l.nodeDirStat.Dev || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("private loop node identity")
	}
	l.nodes[name] = st
	return f, nil
}

func newOwnedLoop(r *result) (*ownedLoop, error) {
	l := &ownedLoop{nodes: make(map[string]unix.Stat_t)}
	// On every failure keep all newly created artifacts and live pins until exit.
	fd, err := unix.Open("/scratch", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return l, err
	}
	l.scratch = os.NewFile(uintptr(fd), "/scratch")
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return l, err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 || st.Dev != r.Scratch.Device {
		return l, errors.New("scratch directory identity")
	}
	l.dev = st.Dev
	l.backing, err = exclusiveFile(l.scratch, backingName)
	if err != nil {
		return l, err
	}
	if err := l.backing.Truncate(backingBytes); err != nil {
		return l, err
	}
	if err := unix.Fstat(int(l.backing.Fd()), &st); err != nil {
		return l, err
	}
	l.inode = st.Ino
	r.BackingBytes = uint64(st.Size)
	l.log, err = exclusiveFile(l.scratch, logName)
	if err != nil {
		return l, err
	}
	if err := l.createNodeDirectory(); err != nil {
		return l, err
	}
	control, err := l.node("rtm081-loop-control", unix.S_IFCHR, 10, 237)
	if err != nil {
		return l, err
	}
	defer control.Close()
	seen := map[int]bool{}
	for attempt := 0; attempt < 8; attempt++ {
		number, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return l, err
		}
		if number < 0 || number >= 1<<20 {
			return l, errors.New("loop number bound")
		}
		if seen[number] {
			continue
		}
		seen[number] = true
		file, err := l.node(fmt.Sprintf("rtm081-loop-%d", number), unix.S_IFBLK, 7, uint32(number))
		if err != nil {
			return l, err
		}
		config := unix.LoopConfig{Fd: uint32(l.backing.Fd()), Info: unix.LoopInfo64{Flags: unix.LO_FLAGS_AUTOCLEAR, Sizelimit: backingBytes}}
		if err := unix.IoctlLoopConfigure(int(file.Fd()), &config); err != nil {
			file.Close() // Failed configure is NEVER ownership: no detach or status adoption.
			if errors.Is(err, unix.EBUSY) {
				continue
			}
			return l, err
		}
		l.file, l.minor = file, uint32(number)
		if err := l.validate(); err != nil {
			return l, err
		}
		r.LoopAutoclear = true
		return l, nil
	}
	return l, errors.New("no freshly owned loop in eight attempts")
}

func (l *ownedLoop) validate() error {
	if err := l.validateNodeDirectory(); err != nil {
		return err
	}
	var st, named unix.Stat_t
	if err := unix.Fstat(int(l.backing.Fd()), &st); err != nil {
		return err
	}
	if err := unix.Fstatat(int(l.scratch.Fd()), backingName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Dev != l.dev || st.Ino != l.inode || st.Size != backingBytes || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Nlink != 1 || named.Dev != st.Dev || named.Ino != st.Ino {
		return errors.New("owned backing identity/size changed")
	}
	info, err := unix.IoctlLoopGetStatus64(int(l.file.Fd()))
	if err != nil {
		return err
	}
	if info.Device != l.dev || info.Inode != l.inode || info.Rdevice != 0 || info.Number != l.minor || info.Offset != 0 || info.Sizelimit != backingBytes || info.Flags != unix.LO_FLAGS_AUTOCLEAR || info.Encrypt_type != 0 || info.Encrypt_key_size != 0 {
		return errors.New("owned loop binding changed")
	}
	var size uint64 // BLKGETSIZE64 writes __u64, not an int.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, l.file.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return errno
	}
	if size != backingBytes {
		return errors.New("owned loop capacity changed")
	}
	return nil
}

// A single direct mount, not a bind of another directory, with no child mounts.
// Return its ID so teardown rejects an overmount/replacement, not merely a dev_t.
func boundedMount(device uint64) (string, error) {
	b, err := read("/proc/self/mountinfo", 65536)
	if err != nil {
		return "", err
	}
	id := ""
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		if strings.HasPrefix(fields[4], boundedPath+"/") {
			return "", errors.New("bounded child mount")
		}
		if fields[4] != boundedPath {
			continue
		}
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		opts := "," + fields[5] + ","
		if id != "" || separator < 6 || len(fields) <= separator+2 || fields[3] != "/" || fields[separator+1] != "ext4" || fields[2] != fmt.Sprintf("%d:%d", unix.Major(device), unix.Minor(device)) || !strings.Contains(opts, ",nosuid,") || !strings.Contains(opts, ",nodev,") || !strings.Contains(opts, ",rw,") {
			return "", errors.New("bounded mount identity/options")
		}
		id = fields[0]
	}
	if id == "" {
		return "", errors.New("bounded mount absent")
	}
	return id, nil
}

func (l *ownedLoop) formatAndMount(r *result) error {
	expected, err := regularBytes("/mke2fs.sha256", 65)
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`^[0-9a-fA-F]{64}\n$`).Match(expected) {
		return errors.New("formatter hash envelope")
	}
	before, err := formatterDigest()
	if err != nil {
		return err
	}
	if before != strings.ToLower(string(expected[:64])) {
		return errors.New("formatter hash mismatch")
	}
	r.FormatterSHA = before
	if err := l.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// No supplied block/path is ever formatted. fd 3 is ONLY our fresh regular
	// backing FD. Explicit ext4 features retain journal/xattrs/ACL/capability support;
	// all journal/inode initialization is synchronous and stays inside the backing.
	command := exec.CommandContext(ctx, "/mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256", "-m", "0", "-N", "4096", "-J", "size=4",
		"-O", "none,has_journal,extent,ext_attr,filetype,dir_index,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum,64bit,flex_bg",
		"-E", "lazy_itable_init=0,lazy_journal_init=0,nodiscard", "/proc/self/fd/3", "32768")
	command.ExtraFiles = []*os.File{l.backing}
	command.Env = []string{"PATH=/", "HOME=/tmp", "TMPDIR=/tmp", "MKE2FS_CONFIG=/dev/null", "LC_ALL=C"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	output := &boundedOutput{}
	command.Stdout, command.Stderr = output, output
	exit, runErr := execute(ctx, command)
	_, overflow := output.snapshot() // Private bounded memory only; never public formatter output.
	after, hashErr := formatterDigest()
	if hashErr != nil || after != before {
		return errors.New("formatter changed")
	}
	r.FormatterChecked = true
	if runErr != nil || ctx.Err() != nil || exit != 0 || overflow {
		return errors.New("format failed")
	}
	if err := l.backing.Sync(); err != nil {
		return err
	}
	if err := l.validate(); err != nil {
		return err
	}
	if err := unix.Mkdirat(int(l.scratch.Fd()), "bounded", 0700); err != nil {
		return err
	}
	if err := unix.Fstatat(int(l.scratch.Fd()), "bounded", &l.target, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if l.target.Dev != l.dev || l.target.Mode != unix.S_IFDIR|0700 || l.target.Uid != 0 {
		return errors.New("mountpoint identity")
	}
	// Mount through the held owned loop descriptor, not a replaceable device path.
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", l.file.Fd()), boundedPath, "ext4", unix.MS_NOSUID|unix.MS_NODEV, "acl,user_xattr"); err != nil {
		return err
	}
	l.mounted = true
	if r.Bounded, err = fs(boundedPath); err != nil {
		return err
	}
	if r.Bounded.Type != 0xef53 || r.Bounded.ReadOnly || r.Bounded.Bytes == 0 || r.Bounded.Bytes > backingBytes || r.Bounded.Device != unix.Mkdev(7, l.minor) || r.Bounded.Device == r.Scratch.Device || r.Bounded.Device == r.Root.Device {
		return errors.New("bounded filesystem profile")
	}
	l.mountID, err = boundedMount(r.Bounded.Device)
	return err
}

func (l *ownedLoop) cleanup(r *result) error {
	if err := l.validate(); err != nil {
		return err
	}
	original, err := fs("/scratch")
	if err != nil || original != r.Scratch {
		return errors.New("parent scratch changed")
	}
	id, err := boundedMount(r.Bounded.Device)
	if err != nil || !l.mounted || id != l.mountID {
		return errors.New("cleanup mount identity")
	}
	if err := unix.Unmount(boundedPath, 0); err != nil {
		return err
	} // No lazy/forced detach, ever.
	l.mounted = false
	mountinfo, err := read("/proc/self/mountinfo", 65536)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(mountinfo), "\n") {
		p := strings.Fields(line)
		if len(p) > 4 && (p[2] == fmt.Sprintf("7:%d", l.minor) || p[4] == boundedPath || strings.HasPrefix(p[4], boundedPath+"/")) {
			return errors.New("remaining owned mount; preserve backing")
		}
	}
	if err := l.validate(); err != nil {
		return err
	}
	// AUTOCLEAR is already armed. Request release only of the still-proven lease;
	// ENXIO must prove actual detach (not merely deferred autoclear with other users).
	if err := unix.IoctlSetInt(int(l.file.Fd()), unix.LOOP_CLR_FD, 0); err != nil {
		return err
	}
	if _, err := unix.IoctlLoopGetStatus64(int(l.file.Fd())); !errors.Is(err, unix.ENXIO) {
		return errors.New("loop still bound")
	}
	if err := l.file.Close(); err != nil {
		return err
	}
	if err := l.backing.Sync(); err != nil {
		return err
	}
	if err := l.log.Sync(); err != nil {
		return err
	}
	// Check every path before deleting any artifact. No recursive removal.
	var named unix.Stat_t
	if err := unix.Fstatat(int(l.scratch.Fd()), "bounded", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if named.Dev != l.target.Dev || named.Ino != l.target.Ino || named.Mode != l.target.Mode {
		return errors.New("mountpoint changed")
	}
	if err := l.validateNodeDirectory(); err != nil {
		return err
	}
	for name, before := range l.nodes {
		if err := unix.Fstatat(int(l.nodeDir.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if !sameEntry(named, before) || named.Nlink != 1 {
			return errors.New("node changed")
		}
	}
	if err := unix.Fstatat(int(l.scratch.Fd()), backingName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if named.Dev != l.dev || named.Ino != l.inode || named.Size != backingBytes {
		return errors.New("backing path changed")
	}
	if err := l.backing.Close(); err != nil {
		return err
	}
	if err := l.log.Close(); err != nil {
		return err
	}
	// Busy candidates are only our filesystem entries, never loop leases. Unlink
	// these exact private nodes without opening, adopting or detaching their loops.
	for name := range l.nodes {
		if err := unix.Unlinkat(int(l.nodeDir.Fd()), name, 0); err != nil {
			return err
		}
	}
	if err := l.validateNodeDirectory(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(l.devDir.Fd()), nodeDirName, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := l.nodeDir.Close(); err != nil {
		return err
	}
	if err := l.devDir.Close(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(l.scratch.Fd()), "bounded", unix.AT_REMOVEDIR); err != nil {
		return err
	}
	// Retain BOTH regular files until the parent validates the result and removes
	// its owned volume. Even a late close/JSON failure must not lose the backing.
	// loop_clean proves unmounted/unbound/closed, not deletion of private evidence.
	if err := l.scratch.Close(); err != nil {
		return err
	}
	r.LoopClean = true
	return nil
}

func nativeChild() error {
	if len(os.Args) != 3 || os.Args[0] != "/setup" || os.Args[1] != "--native-child" || os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		return errors.New("native child arguments/identity")
	}
	testName, err := selectedTest(os.Args[2])
	if err != nil {
		return err
	}
	testTimeout, _, err := selectedCaseBudget(os.Args[2])
	if err != nil {
		return err
	}
	childNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return err
	}
	parentNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", os.Getppid()))
	if err != nil {
		return err
	}
	inheritedNS, err := os.Readlink("/proc/self/fd/3")
	if err != nil {
		return err
	}
	nsType, err := unix.IoctlRetInt(3, unix.NS_GET_NSTYPE)
	if err != nil || nsType != unix.CLONE_NEWNS || inheritedNS != parentNS || childNS == parentNS {
		return errors.New("native namespace provenance")
	}
	parentExe, err := os.Stat(fmt.Sprintf("/proc/%d/exe", os.Getppid()))
	if err != nil {
		return err
	}
	selfExe, err := os.Stat("/proc/self/exe")
	if err != nil || !os.SameFile(parentExe, selfExe) {
		return errors.New("native parent executable")
	}
	if err := unix.Close(3); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	original, err := fs("/scratch")
	if err != nil {
		return err
	}
	bounded, err := fs(boundedPath)
	if err != nil {
		return err
	}
	if bounded.Type != 0xef53 || bounded.ReadOnly || bounded.Bytes == 0 || bounded.Bytes > backingBytes || unix.Major(bounded.Device) != 7 || bounded.Device == original.Device {
		return errors.New("native bounded source")
	}
	if _, err := boundedMount(bounded.Device); err != nil {
		return err
	}
	if err := unix.Mount(boundedPath, "/scratch", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	visible, err := fs("/scratch")
	if err != nil || visible != bounded {
		return errors.New("native bounded bind")
	}
	// Never carry a cwd or open descriptor into the hidden original scratch.
	if err := os.Chdir("/scratch"); err != nil {
		return err
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 64 << 20, Max: 64 << 20}); err != nil {
		return err
	}
	return syscall.Exec("/native.test", []string{"/native.test", "-test.v", "-test.count=1", testTimeout, "-test.run=^(" + testName + ")$"}, []string{"TMPDIR=/scratch", "HOME=/tmp", "PATH=/", "GOTRACEBACK=single"})
}

// Bound the wait for an already started command, including an unreapable sleep.
// Only this exec-created process group is signalled; failures preserve the lease.
func execute(ctx context.Context, command *exec.Cmd) (int, error) {
	command.WaitDelay = time.Second
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	if err := command.Start(); err != nil {
		return -1, err
	}
	type completion struct {
		exit int
		err  error
	}
	done := make(chan completion, 1)
	go func() {
		err := command.Wait()
		exit := -1
		if command.ProcessState != nil {
			exit = command.ProcessState.ExitCode()
		}
		done <- completion{exit, err}
	}()
	select {
	case result := <-done:
		if result.err != nil || ctx.Err() != nil {
			_ = command.Cancel()
		}
		return result.exit, result.err
	case <-ctx.Done():
		_ = command.Cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return -1, errors.New("owned command deadline")
	}
}

// Only this exact complete phase line can arm one fixed readback observation.
// The native timestamp is validated, never used to schedule work. Oversized or
// partial lines cannot accumulate memory or match a suffix after truncation.
type readbackPhaseParser struct {
	line    [64]byte
	used    int
	discard bool
	fired   bool
}

func (p *readbackPhaseParser) feed(raw []byte) bool {
	if p.fired {
		return false
	}
	for _, value := range raw {
		if value == '\n' {
			line := p.line[:p.used]
			const prefix = "P readback 0 b "
			valid := !p.discard && bytes.HasPrefix(line, []byte(prefix)) && len(line) > len(prefix)
			if valid {
				for _, digit := range line[len(prefix):] {
					if digit < '0' || digit > '9' {
						valid = false
					}
				}
				_, err := strconv.ParseInt(string(line[len(prefix):]), 10, 64)
				valid = valid && err == nil
			}
			p.used, p.discard = 0, false
			if valid {
				p.fired = true
				return true
			}
		} else if p.used < len(p.line) && !p.discard {
			p.line[p.used] = value
			p.used++
		} else {
			p.discard = true
		}
	}
	return false
}

type boundedOutput struct {
	limit    int // zero keeps the original maxLog bound; native phases reserve half.
	mu       sync.Mutex
	data     bytes.Buffer
	overflow bool
	readback chan time.Time      // private capacity-one channel; notification never blocks a write
	phase    readbackPhaseParser // guarded by mu, like the output buffer
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.limit
	if limit == 0 {
		limit = maxLog
	}
	if len(p) > limit-b.data.Len() {
		b.overflow = true
		return 0, errors.New("native output bound")
	}
	if b.readback != nil && b.phase.feed(p) {
		select {
		case b.readback <- time.Now():
		default:
		}
	}
	return b.data.Write(p)
}
func (b *boundedOutput) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data.Bytes()...), b.overflow
}

// procIdentity excludes comm: exec changes its text without changing the birth.
// stat comm may itself contain spaces and ')', so split after the last ') '.
type procIdentity struct {
	pid, parent, group int
	birth              uint64
}

func parseProcIdentity(raw []byte) (procIdentity, error) {
	var identity procIdentity
	open, end := bytes.IndexByte(raw, '('), bytes.LastIndex(raw, []byte(") "))
	if open < 2 || end < open || len(raw) > 4096 {
		return identity, errors.New("proc stat envelope")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw[:open])))
	fields := strings.Fields(string(raw[end+2:]))
	if err != nil || pid <= 0 || len(fields) < 20 {
		return identity, errors.New("proc stat fields")
	}
	parent, pErr := strconv.Atoi(fields[1])
	group, gErr := strconv.Atoi(fields[2])
	birth, bErr := strconv.ParseUint(fields[19], 10, 64)
	if pErr != nil || gErr != nil || bErr != nil || parent <= 0 || group <= 0 || birth == 0 {
		return identity, errors.New("proc stat identity")
	}
	return procIdentity{pid, parent, group, birth}, nil
}

func procRead(dir *os.File, name string, maximum int64) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "owned-proc")
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if int64(len(raw)) > maximum {
		return nil, errors.New("proc read bound")
	}
	return raw, err
}

type nativeProcessProbe struct {
	dir      *os.File
	identity procIdentity
}

// Called immediately after Start, BEFORE the sole Wait goroutine can reap it.
// This proc directory is pinned: after exit/reap openat cannot redirect to a
// replacement PID. No later observation resolves a numeric /proc/PID path.
func pinNativeProcess(command *exec.Cmd) (*nativeProcessProbe, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/%d", command.Process.Pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "owned-native-proc")
	raw, err := procRead(dir, "stat", 4096)
	identity, parseErr := parseProcIdentity(raw)
	if err != nil || parseErr != nil || identity.pid != command.Process.Pid || identity.parent != os.Getpid() || identity.group != command.Process.Pid {
		dir.Close()
		return nil, errors.New("owned native birth identity")
	}
	return &nativeProcessProbe{dir, identity}, nil
}

func (p *nativeProcessProbe) capture() []byte {
	out := &boundedOutput{limit: maxLog/4 - 256} // two snapshots plus bounded headers/outcome share 64 KiB
	fmt.Fprintf(out, "D owned pid=%d birth=%d\n", p.identity.pid, p.identity.birth)
	raw, err := procRead(p.dir, "stat", 4096)
	current, parseErr := parseProcIdentity(raw)
	if err != nil || parseErr != nil || current != p.identity {
		fmt.Fprintln(out, "D process-exited-or-identity-unavailable")
		data, _ := out.snapshot()
		return data
	}
	fd, err := unix.Openat(int(p.dir.Fd()), "task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		fmt.Fprintln(out, "D tasks-unavailable")
		data, _ := out.snapshot()
		return data
	}
	tasks := os.NewFile(uintptr(fd), "owned-native-tasks")
	defer tasks.Close()
	names, readErr := tasks.Readdirnames(33) // not an unbounded os.ReadDir allocation
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		fmt.Fprintln(out, "D task-list-incomplete")
	}
	if len(names) > 32 {
		names = names[:32]
		fmt.Fprintln(out, "D task-count-bound")
	}
	for _, name := range names {
		tid, err := strconv.Atoi(name)
		if err != nil || tid <= 0 || strconv.Itoa(tid) != name {
			continue
		}
		taskFD, err := unix.Openat(int(tasks.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		task := os.NewFile(uintptr(taskFD), "owned-native-thread")
		stat, err := procRead(task, "stat", 4096)
		identity, parseErr := parseProcIdentity(stat)
		if err == nil && parseErr == nil && identity.pid == tid && identity.parent == p.identity.parent && identity.group == p.identity.group {
			fmt.Fprintf(out, "D tid=%d birth=%d\n", tid, identity.birth)
			for _, field := range []string{"wchan", "syscall", "stack"} {
				data, err := procRead(task, field, 1024)
				if err != nil {
					data = []byte("unavailable")
				}
				fmt.Fprintf(out, "D %s %s\n", field, data)
			}
		}
		task.Close()
		_, overflow := out.snapshot()
		if overflow {
			break
		}
	}
	data, _ := out.snapshot()
	return data
}

// Independent of the native test's Go scheduler: setup observes at 30s and once
// 2s after detecting the exact first-readback begin line. Native elapsed times
// cannot choose a deadline; neither observation extends the selected fixed
// native/outer budgets. It never signals for diagnostics.
// SIGKILL cancellation uses the clone-returned pidfd, never a reused PID/group.
func executeNative(ctx context.Context, command *exec.Cmd, readback <-chan time.Time) (int, []byte, error) {
	started := time.Now()
	pidFD := -1
	command.SysProcAttr.PidFD = &pidFD
	command.WaitDelay = time.Second
	command.Cancel = func() error {
		if pidFD < 0 {
			return command.Process.Kill()
		}
		return unix.PidfdSendSignal(pidFD, unix.SIGKILL, nil, 0)
	}
	if err := command.Start(); err != nil {
		return -1, nil, err
	}
	probe, pinErr := pinNativeProcess(command)
	if pidFD < 0 {
		pinErr = errors.New("native pidfd unavailable")
	}
	type completion struct {
		exit int
		err  error
	}
	done := make(chan completion, 1)
	go func() {
		err := command.Wait() // sole reaper; Start's proc pin precedes this goroutine
		exit := -1
		if command.ProcessState != nil {
			exit = command.ProcessState.ExitCode()
		}
		done <- completion{exit, err}
	}()
	// Close pidfd only after Wait joins CommandContext's cancellation watcher.
	// If reaping stalls, keep descriptors alive through setup's failure exit.
	joined, observing := false, false
	defer func() {
		if joined && pidFD >= 0 {
			unix.Close(pidFD)
		}
		if probe != nil && !observing {
			probe.dir.Close()
		}
	}()
	finish := func(reason error, diagnostic []byte) (int, []byte, error) {
		_ = command.Cancel()
		select {
		case result := <-done:
			joined = true
			diagnostic = append(diagnostic, []byte("D reaped-after-cancel\n")...)
			return result.exit, diagnostic, reason
		case <-time.After(2 * time.Second):
			return -1, diagnostic, errors.New("owned native not reaped")
		}
	}
	if pinErr != nil {
		return finish(pinErr, []byte("D birth-pin-failed\n"))
	}
	diagnostic := []byte(fmt.Sprintf("D owned pid=%d birth=%d\n", probe.identity.pid, probe.identity.birth))
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	var readbackTimer *time.Timer
	var readbackDue <-chan time.Time
	defer func() {
		if readbackTimer != nil {
			readbackTimer.Stop()
		}
	}()
	for {
		label := ""
		select {
		case result := <-done:
			joined = true
			diagnostic = append(diagnostic, []byte("D reaped\n")...)
			return result.exit, diagnostic, result.err
		case <-ctx.Done():
			return finish(errors.New("owned native deadline"), diagnostic)
		case detected := <-readback:
			readback = nil // one fixed schedule; subsequent native output cannot rearm it
			readbackTimer = time.NewTimer(time.Until(detected.Add(2 * time.Second)))
			readbackDue = readbackTimer.C
			continue
		case <-readbackDue:
			readbackDue = nil
			label = "observation-readback-2s"
		case <-timer.C:
			label = "observation-30s"
		}
		if ctx.Err() != nil {
			return finish(errors.New("owned native deadline"), diagnostic)
		}
		diagnostic = append(diagnostic, []byte(fmt.Sprintf("D %s observed_ms=%d\n", label, time.Since(started).Milliseconds()))...)
		capture := make(chan []byte, 1)
		observing = true
		go func() { capture <- probe.capture() }()
		select {
		case snapshot := <-capture:
			diagnostic = append(diagnostic, snapshot...)
			observing = false
		case <-time.After(time.Second):
			return finish(errors.New("owned native observation deadline"), append(diagnostic, []byte("D observation-time-bound\n")...))
		case <-ctx.Done():
			return finish(errors.New("owned native deadline"), append(diagnostic, []byte("D observation-cancelled\n")...))
		}
	}
}

// Every Go RUN/PASS name, including parent tests, is fixed and case-bound.
func expectedNativeTests(caseID string) ([]string, error) {
	switch caseID {
	case "RTM-081":
		return []string{"TestNativeMountedManagedV3InterruptGraceful"}, nil
	case "RTM-082":
		return []string{"TestNativeMountedManagedV3WriteBurstGraceful"}, nil
	case "RTM-083":
		return []string{"TestNativeMountedManagedV3SparseMmapGraceful"}, nil
	case "RTM-085":
		return []string{"TestNativeMountedManagedV3FsxGraceful"}, nil
	case "RTM-087":
		return []string{"TestNativeIssuedDataTLSRejectsRetiredAndPreviousServiceCredentials"}, nil
	case "RTM-089":
		return []string{"TestNativeServiceFaultPlanClosed", "TestNativeServiceFaults", "TestNativeServiceFaults/stage-1-error-1", "TestNativeServiceFaults/stage-1-error-2", "TestNativeServiceFaults/stage-2-error-1", "TestNativeServiceFaults/stage-2-error-2", "TestNativeServiceFaults/stage-3-error-1", "TestNativeServiceFaults/stage-3-error-2", "TestNativeServiceFaults/stage-4-error-1", "TestNativeServiceFaults/stage-4-error-2", "TestNativeServiceFaults/stage-5-error-1", "TestNativeServiceFaults/stage-5-error-2", "TestNativeServiceFaults/stage-6-error-1", "TestNativeServiceFaults/stage-6-error-2", "TestNativeServiceFaults/stage-7-error-3"}, nil
	case "RTM-090":
		return []string{"TestNativeFaultFinalSyncTupleUnderGate", "TestNativeFaultFinalSyncTupleUnderGate/mutation-error-1", "TestNativeFaultFinalSyncTupleUnderGate/mutation-error-2", "TestNativeFaultFinalSyncTupleUnderGate/other-attachment-error-1", "TestNativeFaultFinalSyncTupleUnderGate/other-attachment-error-2", "TestNativeFaultFinalSyncTupleUnderGate/other-volume-error-1", "TestNativeFaultFinalSyncTupleUnderGate/other-volume-error-2"}, nil
	case "RTM-091":
		return []string{"TestDirectExt4CopyupPartialRootXattrFailureRollsBack", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=/populated=false", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=/populated=true", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=set/populated=false", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=set/populated=true", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=/populated=false", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=/populated=true", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=remove/populated=false", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=remove/populated=true", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=set/populated=false", "TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=set/populated=true", "TestDirectExt4CopyupSymlinkDoesNotTouchTargetXattrs", "TestDirectExt4EmptySymlinkMetadataFailureRollsBack", "TestDirectExt4EmptySymlinkMetadataFailureRollsBack/ownership", "TestDirectExt4EmptySymlinkMetadataFailureRollsBack/timestamps", "TestDirectExt4SymlinkXattrFailureRollsBack", "TestDirectExt4SymlinkXattrsRetainPinnedIdentity", "TestDirectExt4SymlinkXattrsRetainPinnedIdentity/rename", "TestDirectExt4SymlinkXattrsRetainPinnedIdentity/unlink"}, nil
	case "RTM-092":
		return []string{"TestSymlinkValidCapabilityXattrsMatchDirectExt4", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/get-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/list-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/remove-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/set-valid-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/get-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/list-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/remove-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/set-valid-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/get-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/list-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/remove-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/set-valid-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/get-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/list-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/remove-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/set-valid-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/get-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/list-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/remove-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/set-valid-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/get-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/list-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/remove-capability", "TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/set-valid-capability"}, nil
	case "RTM-093":
		return []string{"TestNativeIssuedPrepareInitializerPreflightV4", "TestNativeIssuedPrepareInitializerPreflightV4/first-publication-fresh-attachment", "TestNativeIssuedPrepareInitializerPreflightV4/positive"}, nil
	case "RTM-094":
		return []string{"TestNativePendingProvisionFreshMountReplayV4"}, nil
	case "RTM-101":
		return []string{"TestNativeSnapshot101DeadInitializerConsumers", "TestNativeSnapshot101DirtyMmapWriteback", "TestNativeSnapshot101HungAcceptedGuard", "TestNativeSnapshot101PreBeginRenameUnlink", "TestNativeSnapshot101ReadReaddirAtime", "TestNativeSnapshot101RetainedWritableFD", "TestNativeSnapshot101RuntimePoolSaturation", "TestNativeSnapshot101SameUIDForeignTGID"}, nil
	case "RTM-095":
		return []string{"TestCopyCleanupServerCrashRestoresExactRoot", "TestCopyCleanupServerCrashRestoresExactRoot/after-child-unlink", "TestCopyCleanupServerCrashRestoresExactRoot/after-finish-before-reply", "TestCopyCleanupServerCrashRestoresExactRoot/after-manifest-sync", "TestCopyCleanupServerCrashRestoresExactRoot/after-root-sync", "TestCopyCleanupServerCrashRestoresExactRoot/after-transaction-unlink", "TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-child-unlink", "TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-finish-before-reply", "TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-manifest-sync", "TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-root-sync", "TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-transaction-unlink", "TestCopyPendingReplayFreshSessionRootBootstrap", "TestPrepareExt4IdentityRealFilesystem", "TestPrepareIdentityAtRejectsIntermediateSymlink"}, nil
	case "RTM-102":
		return []string{"TestNativePrepareIdentity102AuthorityJournal", "TestNativePrepareIdentity102AuthorityJournal/exact-operation", "TestNativePrepareIdentity102AuthorityJournal/exact-operation/target", "TestNativePrepareIdentity102AuthorityJournal/foreign-operation", "TestNativePrepareIdentity102AuthorityJournal/foreign-operation/source", "TestNativePrepareIdentity102AuthorityJournal/foreign-operation/target", "TestNativePrepareIdentity102AuthorityJournal/foreign-state", "TestNativePrepareIdentity102AuthorityJournal/foreign-state/source", "TestNativePrepareIdentity102AuthorityJournal/foreign-state/target", "TestNativePrepareIdentity102AuthorityJournal/stale-operation", "TestNativePrepareIdentity102AuthorityJournal/stale-operation/advance", "TestNativePrepareIdentity102AuthorityJournal/stale-operation/target", "TestNativePrepareIdentity102CrossFilesystem", "TestNativePrepareIdentity102ForgetRelookup", "TestNativePrepareIdentity102LargeManifestRecovery", "TestNativePrepareIdentity102ManifestAuthenticity", "TestNativePrepareIdentity102ManifestAuthenticity/altered", "TestNativePrepareIdentity102ManifestAuthenticity/copied", "TestNativePrepareIdentity102ManifestAuthenticity/late-uncertain", "TestNativePrepareIdentity102PublicationAuthenticity", "TestNativePrepareIdentity102PublicationAuthenticity/all-published", "TestNativePrepareIdentity102PublicationAuthenticity/all-published/digest", "TestNativePrepareIdentity102PublicationAuthenticity/all-published/handle", "TestNativePrepareIdentity102PublicationAuthenticity/all-published/late-uncertain", "TestNativePrepareIdentity102PublicationAuthenticity/all-published/path", "TestNativePrepareIdentity102PublicationAuthenticity/all-published/root-metadata", "TestNativePrepareIdentity102PublicationAuthenticity/all-published/valid", "TestNativePrepareIdentity102PublicationAuthenticity/first-published", "TestNativePrepareIdentity102PublicationAuthenticity/first-published/digest", "TestNativePrepareIdentity102PublicationAuthenticity/first-published/handle", "TestNativePrepareIdentity102PublicationAuthenticity/first-published/late-uncertain", "TestNativePrepareIdentity102PublicationAuthenticity/first-published/path", "TestNativePrepareIdentity102PublicationAuthenticity/first-published/root-metadata", "TestNativePrepareIdentity102PublicationAuthenticity/first-published/valid", "TestNativePrepareIdentity102PublicationAuthenticity/private", "TestNativePrepareIdentity102PublicationAuthenticity/private/digest", "TestNativePrepareIdentity102PublicationAuthenticity/private/handle", "TestNativePrepareIdentity102PublicationAuthenticity/private/late-uncertain", "TestNativePrepareIdentity102PublicationAuthenticity/private/path", "TestNativePrepareIdentity102PublicationAuthenticity/private/root-metadata", "TestNativePrepareIdentity102PublicationAuthenticity/private/valid", "TestNativePrepareIdentity102RegisteredRootReuse", "TestNativePrepareIdentity102RegisteredRootReuse/capture", "TestNativePrepareIdentity102Reuse", "TestNativePrepareIdentity102Reuse/file", "TestNativePrepareIdentity102Reuse/root", "TestNativePrepareIdentity102SameNameVolume", "TestPrepareManifestPreserves64MiBBoundWithStreamingDigest"}, nil
	case "RTM-104":
		return []string{"TestPrepareProcessLinuxDeathRetainsDeadOwner", "TestPrepareProcessLinuxPollEINTR", "TestPrepareProcessLinuxPollEINTR/closed-owner", "TestPrepareProcessLinuxPollEINTR/error-after-interrupt", "TestPrepareProcessLinuxPollEINTR/exhausted-final", "TestPrepareProcessLinuxPollEINTR/exhausted-first", "TestPrepareProcessLinuxPollEINTR/final", "TestPrepareProcessLinuxPollEINTR/first", "TestPrepareProcessLinuxPollEINTR/foreign-thread", "TestPrepareProcessLinuxPollEINTR/last-attempt", "TestPrepareProcessLinuxPollEINTR/ready-after-interrupt", "TestPrepareProcessLinuxPollEINTR/starttime-after-interrupt", "TestPrepareProcessLinuxThreadMembership"}, nil
	case "RTM-107":
		return []string{
			"TestDurabilityPolicyHelpers",
			"TestNativeDurabilityPolicyProcessDeath",
			"TestNativeDurabilityPolicyProcessDeath/barrier",
			"TestNativeDurabilityPolicyProcessDeath/barrier/completed",
			"TestNativeDurabilityPolicyProcessDeath/barrier/uncertain",
			"TestNativeDurabilityPolicyProcessDeath/data",
			"TestNativeDurabilityPolicyProcessDeath/data/completed",
			"TestNativeDurabilityPolicyProcessDeath/data/uncertain",
		}, nil
	case "RTM-108":
		return []string{
			"TestNativeRetirementRecoveryHelpers",
			"TestNativeRetirementRecoveryProcessDeath",
			"TestNativeRetirementRecoveryProcessDeath/candidate",
			"TestNativeRetirementRecoveryProcessDeath/certified",
			"TestNativeRetirementRecoveryProcessDeath/completed",
			"TestNativeRetirementRecoveryProcessDeath/prepared",
			"TestNativeRetirementRecoveryProcessDeath/published",
		}, nil
	case "RTM-109":
		return []string{
			"TestNativeCopyDataRecoveryHelpers",
			"TestNativeCopyDataRecoveryProcessDeath",
			"TestNativeCopyDataRecoveryProcessDeath/cleaning-tail",
			"TestNativeCopyDataRecoveryProcessDeath/completed-tail",
			"TestNativeCopyDataRecoveryProcessDeath/rename",
			"TestNativeCopyDataRecoveryProcessDeath/root-metadata",
			"TestNativeCopyDataRecoveryProcessDeath/sealed-tail",
		}, nil
	case "RTM-110":
		return []string{
			"TestNativePrepareRetirementHelpers",
			"TestNativePrepareRetirementProcessDeath",
			"TestNativePrepareRetirementProcessDeath/completed",
			"TestNativePrepareRetirementProcessDeath/inside-barrier",
			"TestNativePrepareRetirementProcessDeath/published",
		}, nil
	case "RTM-113":
		return []string{"TestNativeLifecycleCheckpointAndTerminalSeal"}, nil
	default:
		return nil, errors.New("unknown native case")
	}
}

// Parse only the bounded native output, before adding private diagnostic text.
// A parent PASS alone, duplicate, foreign test, missing child or any skip fails.
func nativePassProof(raw []byte, caseID string) ([]string, error) {
	expected, err := expectedNativeTests(caseID)
	if err != nil {
		return nil, err
	}
	runs, passes := map[string]bool{}, map[string]bool{}
	allowed := map[string]bool{}
	for _, name := range expected {
		allowed[name] = true
	}
	final := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "SKIP") || strings.HasPrefix(line, "--- FAIL:") || line == "FAIL" {
			return nil, errors.New("native skip/failure")
		}
		if strings.HasPrefix(line, "=== RUN") {
			name := strings.TrimPrefix(line, "=== RUN   ")
			if !allowed[name] || runs[name] {
				return nil, errors.New("unexpected/duplicate native run")
			}
			runs[name] = true
		}
		if strings.HasPrefix(line, "--- PASS:") {
			fields := strings.Fields(line)
			if len(fields) != 4 || fields[0] != "---" || fields[1] != "PASS:" || !regexp.MustCompile(`^\([0-9]+\.[0-9]+s\)$`).MatchString(fields[3]) {
				return nil, errors.New("native pass envelope")
			}
			name := fields[2]
			if !allowed[name] || !runs[name] || passes[name] {
				return nil, errors.New("unexpected/duplicate native pass")
			}
			passes[name] = true
		}
		if line == "PASS" {
			final++
		}
	}
	if len(runs) != len(expected) || len(passes) != len(expected) || final != 1 {
		return nil, errors.New("incomplete native subcases")
	}
	return expected, nil
}

func run(r *result, l *ownedLoop) error {
	testName, err := selectedTest(r.Case)
	if err != nil || r.Test != testName {
		return errors.New("native case/test mismatch")
	}
	_, outerLimit, err := selectedCaseBudget(r.Case)
	if err != nil {
		return err
	}
	binary, err := regularBytes("/native.test", 32<<20)
	if err != nil {
		return err
	}
	r.TestSHA = hash(binary)
	ctx, cancel := context.WithTimeout(context.Background(), outerLimit)
	defer cancel()
	if err := l.validate(); err != nil {
		return err
	}
	parentNS, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return err
	}
	defer parentNS.Close()
	command := exec.CommandContext(ctx, "/setup", "--native-child", r.Case)
	command.ExtraFiles = []*os.File{parentNS} // ONLY fd 3, not backing/log/loop/directory pins.
	command.Env = []string{"TMPDIR=/scratch", "HOME=/tmp", "PATH=/", "GOTRACEBACK=single"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	readback := make(chan time.Time, 1)
	output := &boundedOutput{limit: maxLog / 2, readback: readback}
	command.Stdout, command.Stderr = output, output
	var diagnostic []byte
	r.Exit, diagnostic, err = executeNative(ctx, command, readback)
	raw, overflow := output.snapshot()
	passed, proofErr := nativePassProof(raw, r.Case)
	raw = append(raw, diagnostic...) // Each half is independently <=64 KiB.
	if len(raw) > maxLog {
		return errors.New("combined native log bound")
	}
	r.LogBytes, r.LogSHA = len(raw), hash(raw)
	// The parent alone writes its pinned, exclusive original-scratch log. Native
	// stdout/stderr are pipes, never public streams or descriptors for that volume.
	if _, logErr := l.log.Write(raw); logErr != nil {
		return logErr
	}
	if logErr := l.log.Sync(); logErr != nil {
		return logErr
	}
	var logged, named unix.Stat_t
	if err := unix.Fstat(int(l.log.Fd()), &logged); err != nil {
		return err
	}
	if err := unix.Fstatat(int(l.scratch.Fd()), logName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if logged.Dev != l.dev || logged.Mode != unix.S_IFREG|0600 || logged.Uid != 0 || logged.Nlink != 1 || logged.Size != int64(len(raw)) || logged.Size > maxLog || named.Dev != logged.Dev || named.Ino != logged.Ino {
		return errors.New("private log identity/bound")
	}
	if err != nil || ctx.Err() != nil || overflow || r.Exit != 0 || proofErr != nil {
		return errors.New("native test failed")
	}
	r.PassedTests = passed
	r.Passes = len(passed)
	return nil
}
func main() {
	if len(os.Args) == 3 && os.Args[1] == "--native-child" {
		if err := nativeChild(); err != nil {
			os.Exit(1)
		}
		os.Exit(1) // Successful exec never returns; no child setup/JSON path exists.
	}
	r := result{Exit: -1}
	var lease *ownedLoop
	err := errors.New("parent arguments")
	if len(os.Args) == 2 && os.Args[0] == "/setup" {
		if testName, selectionErr := selectedTest(os.Args[1]); selectionErr == nil {
			r.Case, r.Test = os.Args[1], testName
			err = setup(&r)
		}
	}
	if err == nil {
		lease, err = newOwnedLoop(&r)
	}
	if err == nil {
		err = lease.formatAndMount(&r)
	}
	if err != nil {
		r.Failure = "setup"
	} else if err = run(&r, lease); err != nil {
		r.Failure = "native"
	} else if err = lease.cleanup(&r); err != nil {
		r.Failure = "cleanup"
	}
	r.Success = err == nil
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		os.Exit(1)
	}
	if !r.Success {
		fmt.Fprintln(os.Stderr, "managed native test failed; raw evidence retained on owned scratch")
	}
	// On failure do not guess at ownership or remove artifacts. Keep uncertain
	// lease FDs alive through output and until exit (AUTOCLEAR stays armed).
	runtime.KeepAlive(lease)
	if !r.Success {
		os.Exit(1)
	}
}
