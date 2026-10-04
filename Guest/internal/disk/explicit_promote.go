package disk

import (
	"fmt"
	"os"
	"syscall"
)

// ext4PromotionOps mounts only from the continuously held, locked device.
type ext4PromotionOps interface {
	mountJournaled(*pinnedDevice, *pinnedTarget) error
}

// Promote consumes this lease's single promotion attempt, including on failure.
// authorize must verify host-bound resume authority using the borrowed readable
// root while it is still proven read-only/noload. It must not close or retain
// that descriptor, mutate the namespace/device, or call methods on this lease.
// The descriptor is closed by Promote, including when authorize panics.
// No disk mutation is attempted until authorize succeeds and fresh proofs pass.
//
// Callers MUST close all external RO root descriptors before Promote. After
// authorization this plainly unmounts the RO mount, proves clean unmounted disk
// state, and creates a normal journaled RW mount from the SAME block FD/flock.
// Admission binds the held device, not the old mount ID. Obtain a new Root only
// after success. Every failure is terminal for promotion; Close alone may retry
// cleanup and keeps the device lock until positive namespace-wide absence.
func (l Ext4ReadOnlyLease) Promote(authorize func(*os.File) error) error {
	if l.lease == nil {
		return fmt.Errorf("invalid read-only lease")
	}
	s := l.lease
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state != leaseOwned || s.root == nil || s.promotionAttempted {
		return fmt.Errorf("lease promotion unavailable or already consumed")
	}
	s.promotionAttempted = true
	s.state = leaseProbeFailed // terminal even if the callback panics
	if authorize == nil {
		return fmt.Errorf("promotion requires an authorization callback")
	}
	ops, ok := s.ops.(ext4PromotionOps)
	if !ok {
		return fmt.Errorf("lease does not support pinned promotion")
	}
	target := &pinnedTarget{file: s.root, path: s.dest}
	if err := s.verifyPromotionReadOnly(target); err != nil {
		return err
	}
	root, err := s.ops.dupDirectory(target)
	if err != nil {
		return err
	}
	// Prove the callback descriptor too, not merely the retained O_PATH pin.
	err = func() error {
		defer root.Close()
		if err := s.verifyPromotionReadOnly(&pinnedTarget{file: root, path: s.dest}); err != nil {
			return err
		}
		return authorize(root)
	}()
	if err != nil {
		return fmt.Errorf("read-only promotion authorization: %w", err)
	}
	// No intervening caller code after these last clean UUID/capacity and
	// same-device/root/mount proofs. Exclusive namespace/device ownership is
	// required, as it is for the initial probe.
	if err := s.verifyPromotionReadOnly(target); err != nil {
		return err
	}
	// Capture disk-root inode/device and mode before dropping the old mount pin.
	oldInfo, err := s.root.Stat()
	if err != nil {
		return err
	}
	if err := s.root.Close(); err != nil {
		s.root = nil
		return err
	}
	s.root = nil
	if err := s.ops.unmountReadOnly(s.device, s.dest); err != nil {
		return fmt.Errorf("promotion RO unmount failed; close external roots; attempt consumed: %w", err)
	}
	// The old mount is gone. No future mount can inherit its ownership proof.
	s.mountID = 0
	destination, err := s.ops.pinTarget(s.dest)
	if err != nil {
		return err
	}
	defer destination.file.Close()
	snap, err := s.ops.snapshot(destination, true)
	if err != nil {
		return err
	}
	if _, mounted, err := resolveVisibleMount(snap, s.dest); err != nil || mounted {
		return fmt.Errorf("promotion destination is not unmounted: %v", err)
	}
	if err := notMounted(snap, s.device); err != nil {
		return err
	}
	if err := s.ops.trustedTarget(destination); err != nil {
		return err
	}
	if err := s.verifyPromotionDevice(); err != nil {
		return err
	}
	s.mayWrite = true // even a failing mount syscall may have written
	if err := ops.mountJournaled(s.device, destination); err != nil {
		// Do not infer ownership from whatever appears after a failed syscall.
		return fmt.Errorf("journaled ext4 mount failed; device lock retained: %w", err)
	}
	// Repin the ACTUAL new mount, not the underlying directory's stale FD.
	post, err := s.ops.pinTarget(s.dest)
	if err != nil {
		return err
	}
	s.root = post.file
	snap, err = s.ops.snapshot(post, true)
	if err != nil {
		return err
	}
	if err := s.verifyJournaledMount(snap); err != nil {
		return err
	}
	// Linux may reuse a numeric mount ID after unmount (proc_pid_mountinfo(5)).
	// Ownership comes from the successful owned unmount, namespace-wide absence,
	// held block FD/flock, successful mount and fresh root postproof, not from
	// comparing the new ID with the now-dead RO mount's ID.
	if snap.visible == 0 {
		return fmt.Errorf("promotion mount identity is zero")
	}
	newInfo, err := post.file.Stat()
	if err != nil {
		return err
	}
	if !samePromotionRoot(oldInfo, newInfo) {
		return fmt.Errorf("promotion disk root identity or mode changed")
	}
	// Only successful mount + complete postproof establish cleanup ownership.
	s.mountID = snap.visible
	s.promoted = true
	s.state = leaseOwned
	return nil
}

// samePromotionRoot compares stable root identity and ownership/mode across the
// replacement. Mounting never rewrites ACLs/xattrs; these are not attested here.
func samePromotionRoot(before, after os.FileInfo) bool {
	a, aOK := before.Sys().(*syscall.Stat_t)
	b, bOK := after.Sys().(*syscall.Stat_t)
	return aOK && bOK && os.SameFile(before, after) && before.Mode() == after.Mode() && a.Uid == b.Uid && a.Gid == b.Gid
}

// IsPromoted reports successful promotion of a still-owned, open lease. It is
// not a fresh mount proof; Root revalidates the writable journaled policy.
func (l Ext4ReadOnlyLease) IsPromoted() bool {
	if l.lease == nil {
		return false
	}
	s := l.lease
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.promoted && !s.closed && s.state == leaseOwned
}

func (s *ext4ReadOnlyLease) verifyPromotionReadOnly(target *pinnedTarget) error {
	snap, err := s.ops.snapshot(target, true)
	if err != nil {
		return err
	}
	mounted, err := probeDestinationState(snap, s.device, s.dest)
	if err != nil {
		return err
	}
	if !mounted || snap.visible != s.mountID {
		return fmt.Errorf("promotion requires the original read-only mount")
	}
	for _, r := range snap.records {
		if r.major == s.device.major && r.minor == s.device.minor && r.id != s.mountID {
			return fmt.Errorf("promotion device has another mount")
		}
	}
	return s.verifyPromotionDevice()
}

func (s *ext4ReadOnlyLease) verifyPromotionDevice() error {
	capacity, err := s.ops.capacity(s.device)
	if err != nil {
		return err
	}
	if capacity != s.identity.Bytes {
		return fmt.Errorf("promotion device capacity changed")
	}
	sb, err := s.ops.superblock(s.device)
	if err != nil {
		return err
	}
	if err := requireCleanSuperblock(sb, s.identity.UUID); err != nil {
		return err
	}
	if sb.Compat&ext4FeatureCompatHasJournal == 0 {
		return fmt.Errorf("promotion requires HAS_JOURNAL")
	}
	// An external journal would let the kernel open/write an unlocked second
	// device, outside the continuously held block descriptor authority.
	if sb.JournalDevice != 0 || sb.JournalInode == 0 {
		return fmt.Errorf("promotion requires an internal journal on the held device")
	}
	if sb.ROCompat&ext4FeatureROReadonly != 0 {
		return fmt.Errorf("ext4 readonly feature forbids promotion")
	}
	return nil
}

func (s *ext4ReadOnlyLease) verifyPromotedMount(snap mountSnapshot) error {
	if snap.visible != s.mountID || s.mountID == 0 {
		return fmt.Errorf("promoted mount identity changed")
	}
	return s.verifyJournaledMount(snap)
}

func (s *ext4ReadOnlyLease) verifyJournaledMount(snap mountSnapshot) error {
	mounted, err := destinationState(snap, s.device, s.dest)
	if err != nil {
		return err
	}
	if !mounted {
		return fmt.Errorf("promoted mount absent")
	}
	for _, r := range snap.records {
		if r.major == s.device.major && r.minor == s.device.minor && r.id != snap.visible {
			return fmt.Errorf("promoted device has another mount")
		}
	}
	visible, _, err := resolveVisibleMount(snap, s.dest)
	if err != nil {
		return err
	}
	// ext4_show_options omits data=ordered when it equals the on-disk default
	// (Linux fs/ext4/super.c). mountJournaled explicitly requested ordered mode;
	// under exclusive namespace ownership, omission is not a mode downgrade.
	// HAS_JOURNAL/internal-journal admission plus no noload is mandatory.
	if !hasOption(visible.options, "rw") || hasOption(visible.options, "ro") ||
		!hasOption(visible.superOptions, "rw") || hasOption(visible.superOptions, "ro") ||
		hasAnyOption(visible.superOptions, "noload", "norecovery", "data=writeback", "data=journal") {
		return fmt.Errorf("promoted mount lacks writable journaled policy")
	}
	return nil
}

func (s *ext4ReadOnlyLease) rootDestinationState(snap mountSnapshot) (bool, error) {
	if s.promoted {
		err := s.verifyPromotedMount(snap)
		return err == nil, err
	}
	return probeDestinationState(snap, s.device, s.dest)
}

func (s *ext4ReadOnlyLease) cleanupDestinationState(snap mountSnapshot) (bool, error) {
	if !s.mayWrite {
		return probeDestinationState(snap, s.device, s.dest)
	}
	// A failed replacement may leave RO, RW, or partly changed options. Cleanup
	// requires ownership, not writable policy: Close separately insists on the
	// proven nonzero mount ID, including across EBUSY retries. Never detach a
	// foreign mount merely because it names the same device and pathname.
	r, mounted, err := resolveVisibleMount(snap, s.dest)
	if err != nil || !mounted {
		return mounted, err
	}
	if r.fs != "ext4" || r.major != s.device.major || r.minor != s.device.minor || r.root != "/" {
		return false, fmt.Errorf("promotion cleanup mount ownership changed")
	}
	return true, nil
}
