package disk

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// This policy/state machine has no native side effects except through its private,
// per-instance operations. Exported Linux entry points share only a transition lock.
type pinnedDevice struct {
	file         *os.File
	major, minor uint32
}
type pinnedTarget struct {
	file *os.File
	path string
}
type mountRecord struct {
	id                    uint64
	major, minor          uint32
	root, point, fs       string
	options, superOptions string
	parent                uint64
}
type mountSnapshot struct {
	visible uint64
	records []mountRecord
}
type ext4Ops interface {
	pinDevice(string, bool) (*pinnedDevice, error)
	pinTarget(string) (*pinnedTarget, error)
	trustedTarget(*pinnedTarget) error
	// dupDirectory returns a new readable descriptor for the directory held by
	// target: the lease root pin is O_PATH (pinning only), so consumers that
	// read the mount need a real descriptor opened relative to the pin,
	// inheriting its exact mount.
	dupDirectory(*pinnedTarget) (*os.File, error)
	snapshot(*pinnedTarget, bool) (mountSnapshot, error)
	capacity(*pinnedDevice) (uint64, error)
	format(*pinnedDevice, string, string) error
	uuid(*pinnedDevice) (string, error)
	mount(*pinnedDevice, *pinnedTarget) error
	sync(*pinnedDevice, *pinnedTarget) error
	// superblock observes identity and clean-state strictly for the read-only
	// probe; a formatter, replay or repair is never derived from it.
	superblock(*pinnedDevice) (ext4SuperSummary, error)
	// mountReadOnly mounts MS_RDONLY|MS_NODEV|MS_NOSUID with noload: no journal
	// replay, never a remount read-write. The source is the pinned device FD.
	mountReadOnly(*pinnedDevice, *pinnedTarget) error
	// unmountReadOnly detaches the exact owned probe mount after the caller
	// proved from a fresh snapshot that the visible mount is still ours. It is
	// never used for a changed or foreign mount.
	unmountReadOnly(*pinnedDevice, string) error
}
type ext4Transition struct {
	mu  *sync.Mutex
	ops ext4Ops
}

func directoryMetadataPolicy(uid, mode uint32) error {
	if uid != 0 || mode&0022 != 0 {
		return fmt.Errorf("unsafe directory owner/mode")
	}
	return nil
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}
func validateIdentity(uuid string, size uint64) error {
	if size < 16<<20 || size > uint64(1<<63-1) || size%4096 != 0 {
		return fmt.Errorf("expected size must be 4KiB-aligned, at least 16MiB, and fit int64")
	}
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' || strings.ToLower(uuid) != uuid {
		return fmt.Errorf("UUID must be canonical lowercase hexadecimal")
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(raw) != 16 || uuid == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("UUID must be a nonzero 128-bit value")
	}
	return nil
}
func validateInitialization(label, uuid string, size uint64) error {
	if err := validateIdentity(uuid, size); err != nil {
		return err
	}
	if len(label) < 1 || len(label) > 16 {
		return fmt.Errorf("label must be 1..16 printable ASCII bytes")
	}
	for _, b := range []byte(label) {
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("label must be printable ASCII")
		}
	}
	return nil
}
func hasOption(options, want string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == want {
			return true
		}
	}
	return false
}

// hasAnyOption accepts any one of several equivalent option spellings. The
// ext4 superblock option "noload" is kernel-documented under its "norecovery"
// alias; both are accepted for the read-only no-replay probe.
func hasAnyOption(options string, wants ...string) bool {
	for _, want := range wants {
		if hasOption(options, want) {
			return true
		}
	}
	return false
}

// destinationState selects by the mount ID observed on a freshly held directory,
// never by the first mountinfo line at a pathname. Hidden stacks fail closed.
func destinationState(s mountSnapshot, d *pinnedDevice, target string) (bool, error) {
	visible, mounted, err := resolveVisibleMount(s, target)
	if err != nil {
		return false, err
	}
	if !mounted {
		return false, nil
	}
	if visible.fs != "ext4" || visible.major != d.major || visible.minor != d.minor || visible.root != "/" ||
		!hasOption(visible.options, "nodev") || !hasOption(visible.options, "nosuid") || !hasOption(visible.superOptions, "errors=remount-ro") {
		return false, fmt.Errorf("destination is not the exact ext4 disk root with required safety policy")
	}
	return true, nil
}

// probeDestinationState is destinationState for the read-only/no-replay probe:
// the visible mount must be the exact ext4 disk root, mounted ro with
// nodev,nosuid and the noload journal option. A read-write mount or any
// missing flag fails closed, so a successful probe never replayed the journal.
func probeDestinationState(s mountSnapshot, d *pinnedDevice, target string) (bool, error) {
	visible, mounted, err := resolveVisibleMount(s, target)
	if err != nil {
		return false, err
	}
	if !mounted {
		return false, nil
	}
	if visible.fs != "ext4" || visible.major != d.major || visible.minor != d.minor || visible.root != "/" ||
		!hasOption(visible.options, "ro") || !hasOption(visible.options, "nodev") || !hasOption(visible.options, "nosuid") ||
		hasOption(visible.options, "rw") || !hasAnyOption(visible.superOptions, "noload", "norecovery") || hasOption(visible.superOptions, "rw") {
		return false, fmt.Errorf("destination is not the exact ext4 disk root with required read-only no-replay policy")
	}
	return true, nil
}

// resolveVisibleMount matches the mount ID observed on the held directory
// against mountinfo and rejects hidden, stacked or nested mounts. It returns
// the visible record and whether that record is mounted exactly at target.
func resolveVisibleMount(s mountSnapshot, target string) (*mountRecord, bool, error) {
	var visible *mountRecord
	counts := map[string]int{}
	byID := map[uint64]*mountRecord{}
	for i := range s.records {
		r := &s.records[i]
		byID[r.id] = r
		if r.id == s.visible {
			visible = r
		}
		if r.point == target || strings.HasPrefix(target, strings.TrimSuffix(r.point, "/")+"/") {
			counts[r.point]++
			if counts[r.point] > 1 {
				return nil, false, fmt.Errorf("mount stack at %s", r.point)
			}
		}
		if strings.HasPrefix(r.point, target+"/") {
			return nil, false, fmt.Errorf("nested mount beneath destination")
		}
	}
	if visible == nil {
		return nil, false, fmt.Errorf("visible mount ID absent from mountinfo")
	}
	// Distinct-path overmounts can hide an ancestor without duplicate pathnames:
	// e.g. /a covers an older /a/b. Every mount on the destination path must
	// belong to the actual visible mount's parent chain, not just a path prefix.
	ancestry := map[uint64]bool{}
	for r := visible; r != nil; r = byID[r.parent] {
		if ancestry[r.id] {
			return nil, false, fmt.Errorf("cyclic mount ancestry")
		}
		ancestry[r.id] = true
		if r.parent == r.id && r.point == "/" {
			break
		}
	}
	for _, r := range s.records {
		if (r.point == target || strings.HasPrefix(target, strings.TrimSuffix(r.point, "/")+"/")) && !ancestry[r.id] {
			return nil, false, fmt.Errorf("hidden ancestor mount at %s", r.point)
		}
	}
	if visible.point != target {
		if counts[target] != 0 {
			return nil, false, fmt.Errorf("hidden mount at destination")
		}
		return visible, false, nil
	}
	return visible, true, nil
}
func notMounted(s mountSnapshot, d *pinnedDevice) error {
	for _, r := range s.records {
		if r.major == d.major && r.minor == d.minor {
			return fmt.Errorf("refuse initialization: device already mounted at %s (ID %d)", r.point, r.id)
		}
	}
	return nil
}
func (t ext4Transition) run(device, destination, label, uuid string, size uint64, initialize bool) error {
	return t.runRetained(device, destination, label, uuid, size, initialize, nil)
}

// retained is used only by storage fresh initialization. Ordinary container and
// volume transitions retain their existing descriptor lifetime and semantics.
func (t ext4Transition) runRetained(device, destination, label, uuid string, size uint64, initialize bool, retained *Ext4ShutdownLease) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !cleanAbsolute(device) || !cleanAbsolute(destination) {
		return fmt.Errorf("device and destination must be clean absolute non-root paths")
	}
	if initialize {
		if err := validateInitialization(label, uuid, size); err != nil {
			return err
		}
	}
	d, err := t.ops.pinDevice(device, initialize)
	if err != nil {
		return fmt.Errorf("pin block device: %w", err)
	}
	if retained == nil {
		defer d.file.Close()
	} else {
		// Failure grants cleanup only, never a writable root capability.
		retained.lease = &ext4ReadOnlyLease{ops: t.ops, device: d,
			devicePath: device, dest: destination, identity: Ext4Identity{uuid, size},
			state: leaseProbeFailed, mayWrite: true}
	}
	target, err := t.ops.pinTarget(destination)
	if err != nil {
		return fmt.Errorf("pin destination: %w", err)
	}
	defer target.file.Close()
	s, err := t.ops.snapshot(target, true)
	if err != nil {
		return err
	}
	mounted, err := destinationState(s, d, destination)
	if err != nil {
		return err
	}
	if !mounted {
		if err := t.ops.trustedTarget(target); err != nil {
			return err
		}
	}
	if initialize {
		if err := notMounted(s, d); err != nil {
			return err
		}
		checkCapacity := func() error {
			current, err := t.ops.capacity(d)
			if err != nil {
				return fmt.Errorf("block capacity: %w", err)
			}
			if current != size {
				return fmt.Errorf("block capacity %d differs from authorized size %d", current, size)
			}
			return nil
		}
		if err := checkCapacity(); err != nil {
			return err
		}
		// Last pre-destructive check: detect a replaced destination and all mounts,
		// including hidden mounts and mounts at other destinations in this namespace.
		s, err = t.ops.snapshot(target, true)
		if err != nil {
			return err
		}
		if _, err = destinationState(s, d, destination); err != nil {
			return err
		}
		if err = notMounted(s, d); err != nil {
			return err
		}
		if err = t.ops.trustedTarget(target); err != nil {
			return err
		}
		if err = checkCapacity(); err != nil {
			return err
		}
		if err = t.ops.format(d, label, uuid); err != nil {
			return fmt.Errorf("initialization failed; authorization must not be retried: %w", err)
		}
		actual, err := t.ops.uuid(d)
		if err != nil {
			return err
		}
		if actual != uuid {
			return fmt.Errorf("formatted UUID differs from authorized UUID")
		}
	} else if mounted {
		return nil
	}
	// EBUSY (and every other errno) is an error, never evidence of success/freshness.
	if err := t.ops.mount(d, target); err != nil {
		return fmt.Errorf("mount ext4 disk: %w", err)
	}
	s, err = t.ops.snapshot(target, false)
	if err != nil {
		return err
	}
	mounted, err = destinationState(s, d, destination)
	if err != nil {
		return err
	}
	if !mounted {
		return fmt.Errorf("mounted disk is not visible at destination")
	}
	if retained != nil {
		// The pre-mount target pins the underlying directory, not this root.
		post, err := t.ops.pinTarget(destination)
		if err != nil {
			return err
		}
		retained.lease.root = post.file
		snap, err := t.ops.snapshot(post, true)
		if err != nil {
			return err
		}
		if err := retained.lease.verifyJournaledMount(snap); err != nil {
			return err
		}
		retained.lease.mountID = snap.visible
	}
	if initialize {
		actual, err := t.ops.uuid(d)
		if err != nil {
			return err
		}
		if actual != uuid {
			return fmt.Errorf("mounted UUID differs from authorized UUID")
		}
	}
	if retained != nil {
		retained.lease.state = leaseOwned
		retained.lease.promoted = true // shared RW proof, not resume authority
	}
	return nil
}

// checkedDiskSync preserves failure ordering: never publish an identity after a
// failed filesystem/block flush, and never flush an unverified mount.
func checkedDiskSync(filesystem, block, verify func() error) error {
	if err := verify(); err != nil {
		return err
	}
	if err := filesystem(); err != nil {
		return err
	}
	if err := block(); err != nil {
		return err
	}
	return verify()
}

// Ext4Identity is an observation, never permission to initialize or host authority.
type Ext4Identity struct {
	UUID  string
	Bytes uint64
}

// Ext4ReadOnlyLease is the sole handle to one verified read-only, no-replay
// probe mount. It is an opaque pointer lease: the exported value wraps an
// unexported pointer, so copies of the value share one lease and its closed
// state, the zero value is inert, and nothing serializable grants access. For
// its whole lifetime the lease retains the pinned O_RDONLY device FD — keeping
// the exclusive flock against concurrent writers — and a POST-mount pinned
// mounted-root O_PATH FD whose observed mount ID was proved to be the exact
// verified one (a pre-mount pin still references the underlying directory's
// old mount and is never retained). Promote is the one-shot authorization
// boundary for replacing the RO mount with a normal journaled RW mount.
// PID1 exclusive device and mount
// namespace ownership is assumed; no pathname revalidation here can defend
// against racing privileged namespace mutation.
type Ext4ReadOnlyLease struct {
	lease *ext4ReadOnlyLease
}

// Lease states. Root is forbidden unless the lease is successfully verified
// (leaseOwned). Cleanup-only states retain the device pin — and thus the
// flock — until the owned mount is confirmed detached.
const (
	// leaseOwned: the mount and the retained root pin were verified; Root and
	// Close both reprove before acting.
	leaseOwned = iota
	// leaseProbeFailed: post-mount proof failed while a mount may remain;
	// pins are retained for cleanup only. Root is forbidden; Close repins and
	// reproves before attempting the detach.
	leaseProbeFailed
	// leaseClosePending: Close attempted the detach; the root pin was dropped
	// for umount(2) (an O_PATH mount reference makes it EBUSY) but the mount
	// remains — typically an open duplicated root. A retry Close safely
	// repins and reproves. Root is forbidden.
	leaseClosePending
)

type ext4ReadOnlyLease struct {
	mu                 sync.Mutex
	closed             bool
	state              int
	ops                ext4Ops
	device             *pinnedDevice
	root               *os.File // post-mount O_PATH pin; nil while closePending
	mountID            uint64   // exact observed ID of the verified mount; 0 = unproven
	devicePath         string
	dest               string
	identity           Ext4Identity
	promotionAttempted bool
	mayWrite           bool // journaled mount attempted; even an errno can follow writes
	promoted           bool
}

// Identity returns the superblock/kernel identity verified at probe time.
func (l Ext4ReadOnlyLease) Identity() Ext4Identity {
	if l.lease == nil {
		return Ext4Identity{}
	}
	return l.lease.identity
}

// Device returns the pinned device path recorded at probe time.
func (l Ext4ReadOnlyLease) Device() string {
	if l.lease == nil {
		return ""
	}
	return l.lease.devicePath
}

// Destination returns the verified mount destination path.
func (l Ext4ReadOnlyLease) Destination() string {
	if l.lease == nil {
		return ""
	}
	return l.lease.dest
}

// Root returns a new readable descriptor (O_RDONLY directory) for the
// verified mount root — the retained O_PATH pin is pinning-only and cannot
// serve directory reads. The mount and disk are revalidated against the held
// pins — same directory, same mount ID, same device, exact read-only
// no-replay policy (or writable journaled policy after Promote) — before the open;
// a replaced, hidden or policy-changed
// mount fails closed. Root is available only on a successfully verified
// (owned) lease. The caller MUST Close the returned descriptor before calling
// Promote or Close on the lease: an open descriptor into the mount makes the unmount
// EBUSY.
func (l Ext4ReadOnlyLease) Root() (*os.File, error) {
	if l.lease == nil {
		return nil, fmt.Errorf("invalid read-only lease")
	}
	return l.lease.dupRoot()
}

func (s *ext4ReadOnlyLease) dupRoot() (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state != leaseOwned || s.root == nil {
		return nil, fmt.Errorf("read-only lease root unavailable")
	}
	target := &pinnedTarget{file: s.root, path: s.dest}
	snap, err := s.ops.snapshot(target, true)
	if err != nil {
		return nil, err
	}
	mounted, err := s.rootDestinationState(snap)
	if err != nil {
		return nil, err
	}
	if !mounted || snap.visible != s.mountID {
		// The verified mount is gone or changed: fall back to cleanup-only.
		s.state = leaseProbeFailed
		return nil, fmt.Errorf("read-only lease root is no longer the verified mount")
	}
	return s.ops.dupDirectory(target)
}

// Close releases the lease: it revalidates that the visible mount is still the
// exact verified one, unmounts it — never a changed or foreign mount — then
// closes the root and device pins, releasing the flock. Close is idempotent;
// a failed unmount reports the retained mount, keeps the device lock held and
// leaves the lease in leaseClosePending so a retry — after the caller closes
// any descriptors duplicated from Root — safely repins, reproves and retries
// the detach. A zero lease Close is a no-op and never panics.
func (l Ext4ReadOnlyLease) Close() error {
	if l.lease == nil {
		return nil
	}
	return l.lease.close()
}

func (s *ext4ReadOnlyLease) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.mayWrite {
		s.state = leaseClosePending // cleanup attempt permanently revokes Root
	}
	if s.root == nil {
		// leaseClosePending/leaseProbeFailed: the root pin was dropped for the
		// umount attempt (an O_PATH mount reference makes umount(2) EBUSY) or
		// never established. Safely repin the destination before reproving;
		// a previously observed mount ID remains mandatory across retries.
		post, err := s.ops.pinTarget(s.dest)
		if err != nil {
			return err
		}
		s.root = post.file
	}
	target := &pinnedTarget{file: s.root, path: s.dest}
	snap, err := s.ops.snapshot(target, true)
	if err != nil {
		// The held pin may be stale (the mount moved on) or the snapshot
		// transiently unavailable: drop the root pin so a retry repins and
		// reproves from scratch, and retain the device lock.
		s.root.Close()
		s.root = nil
		s.state = leaseProbeFailed
		return err
	}
	// Absence at this pathname, a foreign overmount, and invalid mount policy
	// do NOT prove that our device is detached. It could remain hidden or moved.
	// Release the writer exclusion only after a complete snapshot finds no mount
	// of this device anywhere in the exclusively owned namespace.
	if err := notMounted(snap, s.device); err == nil {
		if err := s.syncUnmountedBlock(); err != nil {
			return err
		}
		s.releaseLocked()
		return nil
	}
	mounted, err := s.cleanupDestinationState(snap)
	if err != nil {
		s.state = leaseProbeFailed
		return fmt.Errorf("read-only lease close: %w (device pin retained)", err)
	}
	if !mounted {
		s.state = leaseProbeFailed
		return fmt.Errorf("probe device remains mounted outside the verified destination; device pin retained")
	}
	if s.mountID == 0 {
		s.state = leaseProbeFailed
		return fmt.Errorf("original probe mount identity was never proven; device pin retained until confirmed detached")
	}
	if snap.visible != s.mountID {
		s.state = leaseProbeFailed
		return fmt.Errorf("read-only lease mount ID changed from %d to %d; refusing to unmount a possibly foreign mount (device pin retained)", s.mountID, snap.visible)
	}
	// Refuse aliases before touching any mount, not just after detach.
	for _, r := range snap.records {
		if r.major == s.device.major && r.minor == s.device.minor && r.id != s.mountID {
			return fmt.Errorf("lease device has another mount; device pin retained")
		}
	}
	if s.mayWrite {
		// sync opens a readable FD relative to our root, calls syncfs, and
		// closes it before the plain unmount. Failure retains all ownership.
		if err := s.ops.sync(s.device, target); err != nil {
			return err
		}
	}
	// The visible mount is proved ours. An O_PATH reference to the mount makes
	// umount(2) EBUSY, so drop the root pin first; the snapshot above proved
	// the visible mount identity under the exclusive-namespace assumption.
	if err := s.root.Close(); err != nil {
		return err
	}
	s.root = nil
	if err := s.ops.unmountReadOnly(s.device, s.dest); err != nil {
		// The mount remains — typically EBUSY: a descriptor duplicated from
		// Root or another reference is still open. The device pin and flock
		// stay held and the lease stays closePending; retry Close after
		// closing the duplicated roots.
		s.state = leaseClosePending
		return fmt.Errorf("read-only lease unmount: %w (mount retained; close duplicated roots and retry Close)", err)
	}
	s.mountID = 0
	// A successful detach is not proof that no alias remains anywhere.
	post, err := s.ops.pinTarget(s.dest)
	if err != nil {
		return err
	}
	defer post.file.Close()
	after, err := s.ops.snapshot(post, true)
	if err != nil {
		return err
	}
	if err := notMounted(after, s.device); err != nil {
		return err
	}
	if err := s.syncUnmountedBlock(); err != nil {
		return err
	}
	s.releaseLocked()
	return nil
}

// releaseLocked drops the retained pins and marks the lease closed. Callers
// invoke it only once the owned mount is confirmed detached or definitively
// absent, so releasing the flock is safe.
func (s *ext4ReadOnlyLease) releaseLocked() {
	if s.root != nil {
		s.root.Close()
		s.root = nil
	}
	s.device.file.Close()
	s.closed = true
}

// ext4 superblock clean-state and feature bits (Linux fs/ext4/ext4.h).
const (
	ext4ValidFS = 0x0001 // Unmounted cleanly
	ext4ErrorFS = 0x0002 // Errors detected

	ext4FeatureCompatHasJournal   = 0x0004
	ext4FeatureCompatExtAttr      = 0x0008
	ext4FeatureCompatResizeInode  = 0x0010
	ext4FeatureCompatDirIndex     = 0x0020
	ext4FeatureCompatSparseSuper2 = 0x0200
	ext4FeatureCompatFastCommit   = 0x0400
	ext4FeatureCompatStableInodes = 0x0800
	ext4FeatureCompatOrphanFile   = 0x1000

	ext4FeatureIncompatFiletype   = 0x0002
	ext4FeatureIncompatRecover    = 0x0004 // Needs recovery: journal replay pending
	ext4FeatureIncompatMetaBG     = 0x0010
	ext4FeatureIncompatExtents    = 0x0040
	ext4FeatureIncompat64bit      = 0x0080
	ext4FeatureIncompatFlexBG     = 0x0200
	ext4FeatureIncompatEAInode    = 0x0400
	ext4FeatureIncompatCsumSeed   = 0x2000
	ext4FeatureIncompatLargeDir   = 0x4000
	ext4FeatureIncompatInlineData = 0x8000

	ext4FeatureROSparseSuper   = 0x0001
	ext4FeatureROLargeFile     = 0x0002
	ext4FeatureROHugeFile      = 0x0008
	ext4FeatureROGDTCsum       = 0x0010
	ext4FeatureRODirNlink      = 0x0020
	ext4FeatureROExtraIsize    = 0x0040
	ext4FeatureROQuota         = 0x0100
	ext4FeatureROMetadataCsum  = 0x0400
	ext4FeatureROReadonly      = 0x1000
	ext4FeatureROProject       = 0x2000
	ext4FeatureROOrphanPresent = 0x10000
)

// Allowlists for the read-only/no-replay probe. Anything outside them is an
// unknown unsupported feature and fails closed; recovery-needed, error-marked
// or not-cleanly-unmounted filesystems are rejected before mounting.
const (
	ext4SupportedCompat = ext4FeatureCompatHasJournal | ext4FeatureCompatExtAttr |
		ext4FeatureCompatResizeInode | ext4FeatureCompatDirIndex | ext4FeatureCompatSparseSuper2 |
		ext4FeatureCompatFastCommit | ext4FeatureCompatStableInodes | ext4FeatureCompatOrphanFile
	ext4SupportedIncompat = ext4FeatureIncompatFiletype | ext4FeatureIncompatMetaBG |
		ext4FeatureIncompatExtents | ext4FeatureIncompat64bit | ext4FeatureIncompatFlexBG |
		ext4FeatureIncompatEAInode | ext4FeatureIncompatCsumSeed | ext4FeatureIncompatLargeDir |
		ext4FeatureIncompatInlineData
	ext4SupportedROCompat = ext4FeatureROSparseSuper | ext4FeatureROLargeFile | ext4FeatureROHugeFile |
		ext4FeatureROGDTCsum | ext4FeatureRODirNlink | ext4FeatureROExtraIsize |
		ext4FeatureROQuota | ext4FeatureROMetadataCsum | ext4FeatureROReadonly |
		ext4FeatureROProject
)

func (t ext4Transition) inspect(device, destination string) (Ext4Identity, error) {
	return t.observe(device, destination, false)
}

func (t ext4Transition) observe(device, destination string, synchronize bool) (Ext4Identity, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !cleanAbsolute(device) || !cleanAbsolute(destination) {
		return Ext4Identity{}, fmt.Errorf("device and destination must be clean absolute non-root paths")
	}
	d, err := t.ops.pinDevice(device, false)
	if err != nil {
		return Ext4Identity{}, err
	}
	defer d.file.Close()
	target, err := t.ops.pinTarget(destination)
	if err != nil {
		return Ext4Identity{}, err
	}
	defer target.file.Close()
	verify := func() error {
		s, err := t.ops.snapshot(target, true)
		if err != nil {
			return err
		}
		mounted, err := destinationState(s, d, destination)
		if err != nil {
			return err
		}
		if !mounted {
			return fmt.Errorf("identity requires the visible exact ext4 mount")
		}
		return nil
	}
	if err := verify(); err != nil {
		return Ext4Identity{}, err
	}
	if synchronize {
		if err := t.ops.sync(d, target); err != nil {
			return Ext4Identity{}, err
		}
		if err := verify(); err != nil {
			return Ext4Identity{}, err
		}
	}
	uuid, err := t.ops.uuid(d)
	if err != nil {
		return Ext4Identity{}, err
	}
	size, err := t.ops.capacity(d)
	if err != nil {
		return Ext4Identity{}, err
	}
	if err := verify(); err != nil {
		return Ext4Identity{}, err
	}
	return Ext4Identity{UUID: uuid, Bytes: size}, nil
}

// ext4SuperSummary is the probe's strict preflight view of the on-disk
// superblock. It is an identity/clean-state observation only.
type ext4SuperSummary struct {
	State         uint16
	Compat        uint32
	Incompat      uint32
	ROCompat      uint32
	UUID          string
	LastOrphan    uint32
	JournalInode  uint32
	JournalDevice uint32
}

// parseExt4Superblock decodes the 1024-byte ext superblock at byte offset
// 1024. data must hold at least 2048 bytes.
func parseExt4Superblock(data []byte) (ext4SuperSummary, error) {
	if len(data) < 2048 {
		return ext4SuperSummary{}, fmt.Errorf("short ext superblock")
	}
	super := data[1024:]
	if binary.LittleEndian.Uint16(super[0x38:0x3a]) != 0xef53 {
		return ext4SuperSummary{}, fmt.Errorf("missing ext superblock identity")
	}
	raw := hex.EncodeToString(super[0x68:0x78])
	return ext4SuperSummary{
		State:         binary.LittleEndian.Uint16(super[0x3a:0x3c]),
		Compat:        binary.LittleEndian.Uint32(super[0x5c:0x60]),
		Incompat:      binary.LittleEndian.Uint32(super[0x60:0x64]),
		ROCompat:      binary.LittleEndian.Uint32(super[0x64:0x68]),
		UUID:          raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:],
		LastOrphan:    binary.LittleEndian.Uint32(super[0xe8:0xec]),
		JournalInode:  binary.LittleEndian.Uint32(super[0xe0:0xe4]),
		JournalDevice: binary.LittleEndian.Uint32(super[0xe4:0xe8]),
	}, nil
}

// requireCleanSuperblock rejects an unclean, error-marked, recovery-needed or
// unsupported-feature filesystem, and any identity mismatch, strictly before a
// mount is attempted. It never mutates, replays, repairs or authorizes.
func requireCleanSuperblock(s ext4SuperSummary, wantUUID string) error {
	if s.UUID != wantUUID {
		return fmt.Errorf("probe UUID differs from authorized UUID")
	}
	if s.State&ext4ErrorFS != 0 {
		return fmt.Errorf("ext4 superblock marked with errors (ERROR_FS)")
	}
	if s.State&ext4ValidFS == 0 {
		return fmt.Errorf("ext4 superblock missing VALID_FS: not cleanly unmounted")
	}
	if s.Incompat&ext4FeatureIncompatRecover != 0 {
		return fmt.Errorf("ext4 journal requires recovery; replay is forbidden")
	}
	// Orphan inode cleanup writes even to a read-only, noload mount: a
	// non-empty s_last_orphan or the orphan-present feature is rejected
	// outright, not merely absent from an allowlist.
	if s.LastOrphan != 0 {
		return fmt.Errorf("ext4 orphan inode list is non-empty; read-only orphan cleanup writes are forbidden")
	}
	if s.ROCompat&ext4FeatureROOrphanPresent != 0 {
		return fmt.Errorf("ext4 orphan-present feature set; read-only orphan cleanup writes are forbidden")
	}
	if v := s.Compat &^ ext4SupportedCompat; v != 0 {
		return fmt.Errorf("unsupported ext4 compatible feature set 0x%x", v)
	}
	if v := s.Incompat &^ ext4SupportedIncompat; v != 0 {
		return fmt.Errorf("unsupported ext4 incompatible feature set 0x%x", v)
	}
	if v := s.ROCompat &^ ext4SupportedROCompat; v != 0 {
		return fmt.Errorf("unsupported ext4 read-only-compatible feature set 0x%x", v)
	}
	return nil
}

// probeMountData is the exact mount data for the read-only probe: noload
// forbids journal replay; there is deliberately no errors=remount-ro (a
// read-only mount cannot be remounted read-only) and no data= mode override.
const probeMountData = "noload"

// probeReadOnly verifies an existing ext4 filesystem strictly read-only and
// mounts it without journal replay. The device is pinned O_RDONLY, the
// expected UUID/byte capacity must match the on-disk superblock exactly, the
// superblock must be cleanly unmounted with no pending recovery and only
// supported features, and the destination must be empty and trusted. The
// mount itself is MS_RDONLY|MS_NODEV|MS_NOSUID with noload and the visible
// mount identity is reverified afterwards. It never formats, fscks, syncs,
// replays or remounts read-write; every errno is an error, never evidence of
// freshness.
func (t ext4Transition) probeReadOnly(device, destination, uuid string, bytes uint64) (Ext4ReadOnlyLease, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	reject := func(err error) (Ext4ReadOnlyLease, error) {
		return Ext4ReadOnlyLease{}, err
	}
	if !cleanAbsolute(device) || !cleanAbsolute(destination) {
		return reject(fmt.Errorf("device and destination must be clean absolute non-root paths"))
	}
	if err := validateIdentity(uuid, bytes); err != nil {
		return reject(err)
	}
	d, err := t.ops.pinDevice(device, false)
	if err != nil {
		return reject(fmt.Errorf("pin block device: %w", err))
	}
	leased := false
	defer func() {
		if !leased {
			d.file.Close()
		}
	}()
	target, err := t.ops.pinTarget(destination)
	if err != nil {
		return reject(fmt.Errorf("pin destination: %w", err))
	}
	defer func() {
		if !leased {
			target.file.Close()
		}
	}()
	checkCapacity := func() error {
		current, err := t.ops.capacity(d)
		if err != nil {
			return fmt.Errorf("block capacity: %w", err)
		}
		if current != bytes {
			return fmt.Errorf("block capacity %d differs from authorized size %d", current, bytes)
		}
		return nil
	}
	checkClean := func() error {
		sb, err := t.ops.superblock(d)
		if err != nil {
			return fmt.Errorf("superblock preflight: %w", err)
		}
		return requireCleanSuperblock(sb, uuid)
	}
	// Preflight the superblock before any mount is possible, on the O_RDONLY pin.
	preMount := func() error {
		s, err := t.ops.snapshot(target, true)
		if err != nil {
			return err
		}
		mounted, err := probeDestinationState(s, d, destination)
		if err != nil {
			return err
		}
		if mounted {
			return fmt.Errorf("probe requires an unmounted destination")
		}
		if err := notMounted(s, d); err != nil {
			return err
		}
		if err := t.ops.trustedTarget(target); err != nil {
			return err
		}
		if err := checkCapacity(); err != nil {
			return err
		}
		return checkClean()
	}
	if err := preMount(); err != nil {
		return reject(err)
	}
	// Last pre-mount check: detect a replaced destination, a disk mounted
	// elsewhere, a capacity change and a swapped/rewritten superblock.
	if err := preMount(); err != nil {
		return reject(err)
	}
	// A failed mount syscall is not evidence of absence or cleanup ownership.
	// Only the first successful post-mount proof can establish this ID.
	var provedMountID uint64
	fail := func(cause error) (Ext4ReadOnlyLease, error) {
		lease, err := t.rollbackProbe(d, target, device, destination, provedMountID, cause)
		if lease.lease != nil {
			// Pins transferred to the retained cleanup lease: the deferred
			// release must not drop them while a mount may remain.
			leased = true
		}
		return lease, err
	}
	if err := t.ops.mountReadOnly(d, target); err != nil {
		return fail(fmt.Errorf("read-only ext4 mount: %w", err))
	}
	s, err := t.ops.snapshot(target, false)
	if err != nil {
		return fail(err)
	}
	mounted, err := probeDestinationState(s, d, destination)
	if err != nil {
		return fail(err)
	}
	if !mounted {
		return fail(fmt.Errorf("mounted read-only disk is not visible at destination"))
	}
	provedMountID = s.visible
	// The lease must pin the POST-mount root: the pre-mount O_PATH pin still
	// references the underlying directory's old mount (its observed mount ID
	// predates the mount), so Root/Close on it would act on the wrong mount.
	// Pin again and prove the fresh pin observes the exact verified mount ID
	// before transferring anything to the lease.
	post, err := t.ops.pinTarget(destination)
	if err != nil {
		return fail(fmt.Errorf("pin mounted root: %w", err))
	}
	postSnap, err := t.ops.snapshot(post, true)
	if err != nil {
		post.file.Close()
		return fail(err)
	}
	postMounted, err := probeDestinationState(postSnap, d, destination)
	if err != nil {
		post.file.Close()
		return fail(err)
	}
	if !postMounted || postSnap.visible != s.visible {
		post.file.Close()
		return fail(fmt.Errorf("mounted root pin does not observe the verified mount ID %d", s.visible))
	}
	// Both pins transfer to the lease: the flock-holding device FD and the
	// post-mount root FD with the exactly-observed mount ID, until Close. The
	// stale pre-mount pin is not retained.
	leased = true
	target.file.Close()
	return Ext4ReadOnlyLease{&ext4ReadOnlyLease{
		ops:        t.ops,
		device:     d,
		root:       post.file,
		mountID:    postSnap.visible,
		state:      leaseOwned,
		devicePath: device,
		dest:       destination,
		identity:   Ext4Identity{UUID: uuid, Bytes: bytes},
	}}, nil
}

// rollbackProbe detaches only the exact mount the probe just created after a
// post-mount verification failure. provedMountID comes only from the first
// successful mount proof, never the rollback snapshot. Zero cannot authorize a
// detach. A fresh snapshot must match that ID; foreign mounts are never adopted.
// The pins drop first because an O_PATH mount reference makes umount(2) EBUSY.
// A mount that may remain is never hidden behind a zero lease with dropped
// pins: rollback uncertainty or a failed detach returns a retained cleanup
// lease (probe-failed or closePending) that keeps the device pin and flock.
func (t ext4Transition) rollbackProbe(d *pinnedDevice, target *pinnedTarget, device, destination string, provedMountID uint64, cause error) (Ext4ReadOnlyLease, error) {
	retained := func(mountID uint64, state int, cleanup error) (Ext4ReadOnlyLease, error) {
		return Ext4ReadOnlyLease{&ext4ReadOnlyLease{
			ops:        t.ops,
			device:     d,
			mountID:    mountID,
			state:      state,
			devicePath: device,
			dest:       destination,
		}}, fmt.Errorf("%w (%v; a mount may remain)", cause, cleanup)
	}
	s, err := t.ops.snapshot(target, false)
	if err != nil {
		// Proof uncertain: retain a probe-failed cleanup lease instead of
		// closing every pin while our mount may remain. The stale pre-mount
		// pin is dropped; the retained lease repins before it reproves.
		target.file.Close()
		return retained(provedMountID, leaseProbeFailed, fmt.Errorf("rollback state unknown: %w", err))
	}
	if err := notMounted(s, d); err == nil {
		// Positive namespace-wide absence, not merely a different visible mount.
		target.file.Close()
		d.file.Close()
		return Ext4ReadOnlyLease{}, cause
	}
	owned, err := probeDestinationState(s, d, destination)
	if err != nil || !owned {
		target.file.Close()
		return retained(provedMountID, leaseProbeFailed, fmt.Errorf("rollback ownership/policy not proven: %v", err))
	}
	if provedMountID == 0 || s.visible != provedMountID {
		target.file.Close()
		return retained(provedMountID, leaseProbeFailed, fmt.Errorf("rollback mount ID %d does not prove original ownership %d", s.visible, provedMountID))
	}
	// The exact owned mount is proved: drop the O_PATH pin (an O_PATH mount
	// reference makes umount(2) EBUSY) and detach only it.
	target.file.Close()
	if err := t.ops.unmountReadOnly(d, destination); err != nil {
		// The mount remains: retain a closePending cleanup lease whose Close
		// safely repins and reproves before retrying the detach.
		return retained(provedMountID, leaseClosePending, fmt.Errorf("rollback unmount failed: %w", err))
	}
	// Successful detach clears ownership but does not prove device absence:
	// another mount may still exist elsewhere in the namespace.
	post, err := t.ops.pinTarget(destination)
	if err != nil {
		return retained(0, leaseProbeFailed, fmt.Errorf("rollback absence repin failed: %w", err))
	}
	defer post.file.Close()
	after, err := t.ops.snapshot(post, true)
	if err != nil {
		return retained(0, leaseProbeFailed, fmt.Errorf("rollback absence snapshot failed: %w", err))
	}
	if err := notMounted(after, d); err != nil {
		return retained(0, leaseProbeFailed, fmt.Errorf("rollback device remains mounted: %w", err))
	}
	d.file.Close()
	return Ext4ReadOnlyLease{}, cause
}

func mountUnescape(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", fmt.Errorf("invalid mountinfo escape")
		}
		code := value[i+1 : i+4]
		switch code {
		case "040":
			out.WriteByte(' ')
		case "011":
			out.WriteByte('\t')
		case "012":
			out.WriteByte('\n')
		case "134":
			out.WriteByte('\\')
		default:
			return "", fmt.Errorf("invalid mountinfo escape")
		}
		i += 3
	}
	return out.String(), nil
}
func parseMountinfo(data string) ([]mountRecord, error) {
	var records []mountRecord
	seen := map[uint64]bool{}
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mountinfo separator")
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) != 3 {
			return nil, fmt.Errorf("invalid mountinfo fields")
		}
		id, err := strconv.ParseUint(left[0], 10, 64)
		if err != nil || id == 0 || seen[id] {
			return nil, fmt.Errorf("invalid/duplicate mount ID")
		}
		seen[id] = true
		dev := strings.Split(left[2], ":")
		if len(dev) != 2 {
			return nil, fmt.Errorf("invalid mountinfo device")
		}
		major, err := strconv.ParseUint(dev[0], 10, 32)
		if err != nil {
			return nil, err
		}
		minor, err := strconv.ParseUint(dev[1], 10, 32)
		if err != nil {
			return nil, err
		}
		root, err := mountUnescape(left[3])
		if err != nil {
			return nil, err
		}
		point, err := mountUnescape(left[4])
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(root) || !filepath.IsAbs(point) {
			return nil, fmt.Errorf("nonabsolute mountinfo path")
		}
		parent, err := strconv.ParseUint(left[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid parent mount ID: %w", err)
		}
		records = append(records, mountRecord{id, uint32(major), uint32(minor), root, point, right[0], left[5], right[2], parent})
	}
	return records, nil
}
