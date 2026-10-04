package disk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
)

type promotionFake struct {
	*fakeExt4
	journaled        bool
	promotions       int
	promotionErr     error
	afterMount       func()
	afterUnmount     func()
	mountedDevice    *pinnedDevice
	journaledMountID uint64
	journaledRoot    string
}

func (f *promotionFake) pinTarget(path string) (*pinnedTarget, error) {
	target, err := f.fakeExt4.pinTarget(path)
	if err == nil && f.journaled {
		if f.journaledRoot != "" {
			target.file.Close()
			target.file, err = os.Open(f.journaledRoot)
			if err != nil {
				return nil, err
			}
		}
		f.fdMountIDs[int(target.file.Fd())] = f.journaledMountID
	}
	return target, err
}
func (f *promotionFake) dupDirectory(target *pinnedTarget) (*os.File, error) {
	root, err := f.fakeExt4.dupDirectory(target)
	if err == nil {
		f.fdMountIDs[int(root.Fd())] = f.fdMountIDs[int(target.file.Fd())]
	}
	return root, err
}
func (f *promotionFake) snapshot(target *pinnedTarget, same bool) (mountSnapshot, error) {
	if !f.journaled || f.snapshotHook != nil {
		return f.fakeExt4.snapshot(target, same)
	}
	if same && f.fdMountIDs[int(target.file.Fd())] != f.journaledMountID {
		return mountSnapshot{}, fmt.Errorf("stale root pin")
	}
	r := fakeMounted()
	r.id = f.journaledMountID
	r.superOptions += ",data=ordered"
	return mountSnapshot{f.journaledMountID, []mountRecord{fakeRoot(), r}}, nil
}
func (f *promotionFake) unmountReadOnly(d *pinnedDevice, path string) error {
	if err := f.fakeExt4.unmountReadOnly(d, path); err != nil {
		return err
	}
	f.journaled = false
	if f.afterUnmount != nil {
		f.afterUnmount()
	}
	return nil
}
func (f *promotionFake) mountJournaled(d *pinnedDevice, _ *pinnedTarget) error {
	f.promotions++
	f.mountedDevice = d
	// Even errno can leave an uncertain mount: never claim it for cleanup.
	f.journaled = true
	if f.afterMount != nil {
		f.afterMount()
	}
	return f.promotionErr
}
func newPromotionLease(t *testing.T) (Ext4ReadOnlyLease, *promotionFake) {
	t.Helper()
	f := &promotionFake{fakeExt4: &fakeExt4{}, journaledMountID: 3}
	l, err := (ext4Transition{new(sync.Mutex), f}).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, root := range f.dupRoots {
			root.Close()
			os.Remove(root.Name())
		}
		f.snapshotHook = nil
		f.unmountErr = nil
		f.afterUnmount = nil
		f.targetErr = nil
		f.failRepinAfter = 0
		// Simulate operator-proved absence for uncertain mount ownership.
		if l.lease.mountID == 0 {
			f.journaled = false
			f.probeMounted = false
		}
		if err := l.Close(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return l, f
}
func expectDeviceHeld(t *testing.T, l Ext4ReadOnlyLease, device *os.File) {
	t.Helper()
	if l.lease.device.file != device {
		t.Fatal("device replaced")
	}
	if _, err := device.Stat(); err != nil {
		t.Fatal("device/flock released", err)
	}
}
func expectTerminalPromotion(t *testing.T, l Ext4ReadOnlyLease) {
	t.Helper()
	if l.IsPromoted() {
		t.Fatal("failed attempt promoted")
	}
	if _, err := l.Root(); err == nil {
		t.Fatal("terminal root available")
	}
	if err := l.Promote(func(*os.File) error { t.Fatal("callback replayed"); return nil }); err == nil {
		t.Fatal("retry accepted")
	}
}
func TestPromotionSuccessReplacesMountNotDevice(t *testing.T) {
	l, f := newPromotionLease(t)
	oldRoot, device := l.lease.root, l.lease.device.file
	external, err := l.Root()
	if err != nil {
		t.Fatal(err)
	}
	external.Close()
	var borrowed *os.File
	copyLease := l
	if err := l.Promote(func(root *os.File) error {
		borrowed = root
		if _, err := root.Readdirnames(-1); err != nil {
			t.Fatal(err)
		}
		if f.promotions != 0 || f.unmounts != 0 || f.formats != 0 || f.mounts != 0 || f.syncs != 0 {
			t.Fatal("mutation before admission")
		}
		expectDeviceHeld(t, l, device)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := borrowed.Stat(); err == nil {
		t.Fatal("callback FD leaked")
	}
	if _, err := oldRoot.Stat(); err == nil {
		t.Fatal("old root retained")
	}
	if !l.IsPromoted() || !copyLease.IsPromoted() || l.lease.mountID != 3 {
		t.Fatal("new mount not published")
	}
	if f.pins != 1 || f.promotions != 1 || f.unmounts != 1 || f.mounts != 0 || f.mountedDevice != l.lease.device {
		t.Fatal("device reopened or wrong transition")
	}
	expectDeviceHeld(t, l, device)
	root, err := l.Root()
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.IsPromoted() {
		t.Fatal("closed lease promoted")
	}
}
func TestPromotionAcceptsReusedNumericMountID(t *testing.T) {
	l, f := newPromotionLease(t)
	oldRoot, device, oldID := l.lease.root, l.lease.device.file, l.lease.mountID
	f.journaledMountID = oldID
	pins := f.pinTargetCalls
	if err := l.Promote(func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !l.IsPromoted() || l.lease.mountID != oldID || oldID == 0 {
		t.Fatal("reused nonzero ID not published")
	}
	if _, err := oldRoot.Stat(); err == nil {
		t.Fatal("old root retained")
	}
	if f.unmounts != 1 || f.promotions != 1 || f.pinTargetCalls != pins+2 || f.pins != 1 || f.mountedDevice != l.lease.device {
		t.Fatal("missing owned replacement and fresh root pin")
	}
	expectDeviceHeld(t, l, device)
	root, err := l.Root()
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if err := l.Close(); err != nil || f.unmounts != 2 {
		t.Fatal("proven reused-ID mount not cleaned", err)
	}
	if _, err := device.Stat(); err == nil {
		t.Fatal("device retained after proven absence")
	}
}

func TestPromotionReusedIDDoesNotAllowLaterReplacement(t *testing.T) {
	l, f := newPromotionLease(t)
	f.journaledMountID = l.lease.mountID
	if err := l.Promote(func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	device := l.lease.device.file
	f.journaledMountID++ // a different live mount now occupies the path
	if root, err := l.Root(); err == nil {
		root.Close()
		t.Fatal("replaced mount root accepted")
	}
	for i := 0; i < 2; i++ { // stale pin, then fresh pin with the wrong ID
		if err := l.Close(); err == nil || f.unmounts != 1 {
			t.Fatal("replaced mount detached", err)
		}
		expectDeviceHeld(t, l, device)
	}
	f.journaled = false // only namespace-wide absence permits lock release
	_ = l.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPromotionAcceptsOmittedDefaultOrderedModeButRefusesOtherModes(t *testing.T) {
	for _, options := range []string{"rw,errors=remount-ro", "rw,errors=remount-ro,data=ordered", "rw,errors=remount-ro,data=writeback", "rw,errors=remount-ro,data=journal", "rw,errors=remount-ro,noload", "rw,errors=remount-ro,norecovery"} {
		t.Run(options, func(t *testing.T) {
			l, _ := newPromotionLease(t)
			r := fakeMounted()
			r.id, r.superOptions = 3, options
			err := l.lease.verifyJournaledMount(mountSnapshot{3, []mountRecord{fakeRoot(), r}})
			want := options == "rw,errors=remount-ro" || options == "rw,errors=remount-ro,data=ordered"
			if (err == nil) != want {
				t.Fatalf("journal policy: %v", err)
			}
		})
	}
}

func TestPromotionRequiresExternalRootsClosed(t *testing.T) {
	l, f := newPromotionLease(t)
	root, err := l.Root()
	if err != nil {
		t.Fatal(err)
	}
	device := l.lease.device.file
	if err := l.Promote(func(*os.File) error { return nil }); !errors.Is(err, syscall.EBUSY) {
		t.Fatal(err)
	}
	if f.promotions != 0 || l.lease.root != nil || l.lease.mountID != 2 {
		t.Fatal("busy RO mount replaced")
	}
	expectTerminalPromotion(t, l)
	expectDeviceHeld(t, l, device)
	root.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestPromotionInvalidAndRejectedCallbacks(t *testing.T) {
	var zero Ext4ReadOnlyLease
	if zero.Promote(nil) == nil || zero.IsPromoted() {
		t.Fatal("zero lease accepted")
	}
	for _, mode := range []string{"nil", "rejected", "panic", "closed"} {
		t.Run(mode, func(t *testing.T) {
			l, f := newPromotionLease(t)
			device := l.lease.device.file
			authorize := func(*os.File) error { return syscall.EACCES }
			switch mode {
			case "nil":
				authorize = nil
			case "closed":
				if err := l.Close(); err != nil {
					t.Fatal(err)
				}
			case "panic":
				authorize = func(*os.File) error { panic("denied") }
			}
			func() {
				if mode == "panic" {
					defer func() {
						if recover() == nil {
							t.Fatal("missing panic")
						}
					}()
				}
				if err := l.Promote(authorize); err == nil {
					t.Fatal("invalid authorization accepted")
				}
			}()
			if f.promotions != 0 {
				t.Fatal("invalid authorization wrote")
			}
			expectTerminalPromotion(t, l)
			if mode != "closed" {
				expectDeviceHeld(t, l, device)
			}
		})
	}
}
func TestPromotionRechecksAfterAuthorizationAndUnmount(t *testing.T) {
	for _, phase := range []string{"callback", "unmounted"} {
		for _, mutation := range []string{"dirty", "recovery", "orphan", "orphan-feature", "no-journal", "external-journal", "missing-journal-inode", "readonly", "uuid", "size", "mount", "snapshot", "untrusted"} {
			t.Run(phase+"/"+mutation, func(t *testing.T) {
				l, f := newPromotionLease(t)
				device := l.lease.device.file
				mutate := func() {
					sb := fakeCleanSuperblock()
					switch mutation {
					case "dirty":
						sb.State = 0
					case "recovery":
						sb.Incompat |= ext4FeatureIncompatRecover
					case "orphan":
						sb.LastOrphan = 42
					case "orphan-feature":
						sb.ROCompat |= ext4FeatureROOrphanPresent
					case "no-journal":
						sb.Compat &^= ext4FeatureCompatHasJournal
					case "external-journal":
						sb.JournalDevice = 0x801
					case "missing-journal-inode":
						sb.JournalInode = 0
					case "readonly":
						sb.ROCompat |= ext4FeatureROReadonly
					case "uuid":
						sb.UUID = "87654321-1234-5678-9abc-123456789abc"
					case "size":
						f.capacityValues = []uint64{testBytes * 2}
					case "untrusted":
						f.leafUID = 1000
					case "mount", "snapshot":
						f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) {
							if mutation == "snapshot" {
								return mountSnapshot{}, syscall.EIO
							}
							r := fakeProbeMounted()
							r.id = 7
							r.point = "/elsewhere"
							return mountSnapshot{1, []mountRecord{fakeRoot(), r}}, nil
						}
					}
					f.superblockValues = []ext4SuperSummary{sb}
				}
				if phase == "unmounted" {
					f.afterUnmount = mutate
				}
				err := l.Promote(func(*os.File) error {
					if phase == "callback" {
						mutate()
					}
					return nil
				})
				if err == nil || f.promotions != 0 {
					t.Fatal("changed proof promoted", err)
				}
				expectTerminalPromotion(t, l)
				expectDeviceHeld(t, l, device)
			})
		}
	}
}
func TestPromotionPreproofBlocksCallback(t *testing.T) {
	l, f := newPromotionLease(t)
	sb := fakeCleanSuperblock()
	sb.Incompat |= ext4FeatureIncompatRecover
	f.superblockValues = []ext4SuperSummary{sb}
	if err := l.Promote(func(*os.File) error { t.Fatal("callback before clean proof"); return nil }); err == nil {
		t.Fatal("dirty proof accepted")
	}
	if f.promotions != 0 {
		t.Fatal("write before proof")
	}
}
func TestPromotionUnknownNewMountNeverDetached(t *testing.T) {
	for _, mode := range []string{"errno", "snapshot", "foreign", "foreign-reused-id", "policy", "repin", "zero-id", "replaced-root"} {
		t.Run(mode, func(t *testing.T) {
			l, f := newPromotionLease(t)
			device := l.lease.device.file
			if mode == "errno" {
				f.promotionErr = syscall.EIO
			} else {
				f.afterMount = func() {
					if mode == "repin" {
						f.targetErr = syscall.EIO
						return
					}
					if mode == "replaced-root" {
						f.journaledMountID = 2 // reuse cannot excuse a different root inode
						f.journaledRoot = t.TempDir()
						return
					}
					f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) {
						if mode == "snapshot" {
							return mountSnapshot{}, syscall.EIO
						}
						r := fakeMounted()
						r.id = 3
						r.superOptions += ",data=ordered"
						switch mode {
						case "foreign":
							r.minor++
						case "policy":
							r.superOptions += ",noload"
						case "foreign-reused-id":
							r.id = 2
							r.minor++
						case "zero-id":
							r.id = 0
						}
						root := fakeRoot()
						root.parent = root.id // keep zero-ID case acyclic to exercise its explicit refusal
						return mountSnapshot{r.id, []mountRecord{root, r}}, nil
					}
				}
			}
			err := l.Promote(func(*os.File) error { return nil })
			if err == nil {
				t.Fatal("post-mount failure accepted")
			}
			if mode == "zero-id" && err.Error() != "promotion mount identity is zero" {
				t.Fatal("zero-ID guard not exercised", err)
			}
			if mode == "replaced-root" && err.Error() != "promotion disk root identity or mode changed" {
				t.Fatal("root identity guard not exercised", err)
			}
			expectTerminalPromotion(t, l)
			expectDeviceHeld(t, l, device)
			if l.lease.mountID != 0 || f.unmounts != 1 {
				t.Fatal("uncertain new mount claimed")
			}
			f.snapshotHook = nil
			f.targetErr = nil
			if err := l.Close(); err == nil || f.unmounts != 1 {
				t.Fatal("unknown mount detached")
			}
			expectDeviceHeld(t, l, device)
			f.journaled = false // only positive absence permits lock release
			// Close's pin may refer to the vanished mount, so its first retry drops it.
			_ = l.Close()
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPromotionHoldsSameFlockThroughReplacementAndFailure(t *testing.T) {
	l, f := newPromotionLease(t)
	path := t.TempDir() + "/lock"
	seed, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	seed.Close()
	locked, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(locked.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	l.lease.device.file.Close()
	l.lease.device.file = locked
	competitor, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer competitor.Close()
	assertLocked := func() {
		t.Helper()
		if err := syscall.Flock(int(competitor.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatalf("writer exclusion lost: %v", err)
		}
	}
	f.afterUnmount = assertLocked
	f.afterMount = assertLocked
	f.promotionErr = syscall.EIO
	if err := l.Promote(func(*os.File) error { assertLocked(); return nil }); !errors.Is(err, syscall.EIO) {
		t.Fatal(err)
	}
	assertLocked()
	expectDeviceHeld(t, l, locked)
	if err := l.Close(); err == nil {
		t.Fatal("uncertain mount cleaned")
	}
	assertLocked()
	f.journaled = false
	_ = l.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(competitor.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal("lock retained after absence", err)
	}
}
func TestPromotionJournalPolicy(t *testing.T) {
	l, _ := newPromotionLease(t)
	for _, policy := range []string{"rw,errors=remount-ro,data=journal", "rw,noload,errors=remount-ro,data=ordered", "rw,norecovery,errors=remount-ro,data=ordered", "rw,errors=remount-ro,data=writeback", "ro,errors=remount-ro,data=ordered"} {
		r := fakeMounted()
		r.superOptions = policy
		if err := l.lease.verifyJournaledMount(mountSnapshot{r.id, []mountRecord{fakeRoot(), r}}); err == nil {
			t.Fatal("bad journal policy accepted", policy)
		}
	}
}

func TestPromotionJournalFieldsParsed(t *testing.T) {
	data := make([]byte, 2048)
	binary.LittleEndian.PutUint16(data[1024+0x38:], 0xef53)
	binary.LittleEndian.PutUint32(data[1024+0xe0:], 8)
	binary.LittleEndian.PutUint32(data[1024+0xe4:], 0x801)
	sb, err := parseExt4Superblock(data)
	if err != nil || sb.JournalInode != 8 || sb.JournalDevice != 0x801 {
		t.Fatalf("journal fields lost: %+v %v", sb, err)
	}
}

func TestPromotionRootRevalidatesPolicyAndCloseBusyRetry(t *testing.T) {
	l, f := newPromotionLease(t)
	if err := l.Promote(func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, options := range []string{"rw,nodev", "rw,nosuid", "ro,nodev,nosuid"} {
		f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) {
			r := fakeMounted()
			r.id = 3
			r.options = options
			r.superOptions += ",data=ordered"
			return mountSnapshot{3, []mountRecord{fakeRoot(), r}}, nil
		}
		if root, err := l.Root(); err == nil {
			root.Close()
			t.Fatal("unsafe root available", options)
		}
	}
	f.snapshotHook = nil
	root, err := l.Root()
	if err != nil {
		t.Fatal(err)
	}
	device := l.lease.device.file
	if err := l.Close(); !errors.Is(err, syscall.EBUSY) {
		t.Fatal(err)
	}
	expectDeviceHeld(t, l, device)
	if l.lease.mountID != 3 {
		t.Fatal("busy cleanup lost mount identity")
	}
	root.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPromotionCloseRequiresPostDetachAbsence(t *testing.T) {
	l, f := newPromotionLease(t)
	if err := l.Promote(func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	device := l.lease.device.file
	f.afterUnmount = func() {
		f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) {
			r := fakeMounted()
			r.id = 9
			r.point = "/alias"
			return mountSnapshot{1, []mountRecord{fakeRoot(), r}}, nil
		}
	}
	if err := l.Close(); err == nil {
		t.Fatal("detach mistaken for device absence")
	}
	expectDeviceHeld(t, l, device)
	if l.lease.mountID != 0 {
		t.Fatal("detached mount ownership retained")
	}
	if err := l.Close(); err == nil || f.unmounts != 2 {
		t.Fatal("unknown alias detached")
	}
	f.afterUnmount = nil
	f.snapshotHook = nil
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
