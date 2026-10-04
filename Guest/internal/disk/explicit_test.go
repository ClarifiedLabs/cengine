package disk

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const testUUID = "12345678-1234-5678-9abc-123456789abc"
const testBytes = uint64(32 << 20)

type fakeExt4 struct {
	mounted                                                      bool
	probeMounted                                                 bool
	syncs                                                        int
	syncErr                                                      error
	leafUID, leafMode                                            uint32
	leafChecks                                                   int
	formats, mounts, pins, capacities, snapshots, uuids          int
	readOnlyMounts, superblocks, unmounts                        int
	pinErr, targetErr, capacityErr, formatErr, mountErr, uuidErr error
	mountReadOnlyErr, superblockErr, unmountErr                  error
	capacityValues                                               []uint64
	uuidValues                                                   []string
	superblockValues                                             []ext4SuperSummary
	snapshotHook                                                 func(*fakeExt4, bool) (mountSnapshot, error)
	formatDevice, mountDevice, mountReadOnlyDevice               *pinnedDevice
	// fdMountIDs models per-FD observed mount IDs: a pin taken before the
	// mount observes the parent mount (1); one taken after observes the new
	// mount (2). snapshot compares a held pin against a fresh reopen, like the
	// real ops. dupRoots are readable dups still open: unmount is EBUSY while
	// any of them lives, modeling the real mount reference counting.
	fdMountIDs     map[int]uint64
	dupRoots       []*os.File
	pinTargetCalls int
	failRepinAfter int // pinTarget fails once calls exceed this (0 = never)
}

// currentMountID is the mount ID a freshly reopened destination observes.
func (f *fakeExt4) currentMountID() uint64 {
	if f.probeMounted || f.mounted {
		return 2
	}
	return 1
}

func fakeCleanSuperblock() ext4SuperSummary {
	return ext4SuperSummary{
		State:    ext4ValidFS,
		Compat:   ext4FeatureCompatHasJournal | ext4FeatureCompatExtAttr | ext4FeatureCompatResizeInode | ext4FeatureCompatDirIndex,
		Incompat: ext4FeatureIncompatFiletype | ext4FeatureIncompatExtents | ext4FeatureIncompat64bit | ext4FeatureIncompatFlexBG | ext4FeatureIncompatCsumSeed,
		ROCompat: ext4FeatureROSparseSuper | ext4FeatureROLargeFile | ext4FeatureROHugeFile | ext4FeatureROGDTCsum |
			ext4FeatureRODirNlink | ext4FeatureROExtraIsize | ext4FeatureROMetadataCsum,
		UUID:         testUUID,
		JournalInode: 8,
	}
}
func fakeProbeMounted() mountRecord {
	return mountRecord{2, 8, 16, "/", "/disk", "ext4", "ro,nodev,nosuid", "ro,noload", 1}
}

func fakeRoot() mountRecord { return mountRecord{1, 0, 1, "/", "/", "rootfs", "rw", "rw", 0} }
func fakeMounted() mountRecord {
	return mountRecord{2, 8, 16, "/", "/disk", "ext4", "rw,nodev,nosuid", "rw,errors=remount-ro", 1}
}
func (f *fakeExt4) pinDevice(_ string, _ bool) (*pinnedDevice, error) {
	f.pins++
	if f.pinErr != nil {
		return nil, f.pinErr
	}
	file, err := os.Open(os.DevNull)
	return &pinnedDevice{file, 8, 16}, err
}
func (f *fakeExt4) pinTarget(path string) (*pinnedTarget, error) {
	f.pinTargetCalls++
	if f.targetErr != nil {
		return nil, f.targetErr
	}
	if f.failRepinAfter > 0 && f.pinTargetCalls > f.failRepinAfter {
		return nil, fmt.Errorf("repin failed")
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	if f.fdMountIDs == nil {
		f.fdMountIDs = map[int]uint64{}
	}
	f.fdMountIDs[int(file.Fd())] = f.currentMountID()
	return &pinnedTarget{file, path}, nil
}
func (f *fakeExt4) trustedTarget(_ *pinnedTarget) error {
	f.leafChecks++
	return directoryMetadataPolicy(f.leafUID, f.leafMode)
}
func (f *fakeExt4) snapshot(target *pinnedTarget, same bool) (mountSnapshot, error) {
	f.snapshots++
	if f.snapshotHook != nil {
		return f.snapshotHook(f, same)
	}
	fresh := f.currentMountID()
	if same {
		held, ok := f.fdMountIDs[int(target.file.Fd())]
		if !ok || held != fresh {
			return mountSnapshot{}, fmt.Errorf("destination replaced since pin")
		}
	}
	records := []mountRecord{fakeRoot()}
	switch {
	case f.probeMounted:
		records = append(records, fakeProbeMounted())
	case f.mounted:
		records = append(records, fakeMounted())
	}
	return mountSnapshot{fresh, records}, nil
}
func (f *fakeExt4) capacity(_ *pinnedDevice) (uint64, error) {
	f.capacities++
	if len(f.capacityValues) > 0 {
		value := f.capacityValues[0]
		f.capacityValues = f.capacityValues[1:]
		return value, f.capacityErr
	}
	return testBytes, f.capacityErr
}
func (f *fakeExt4) format(d *pinnedDevice, _, _ string) error {
	f.formats++
	f.formatDevice = d
	return f.formatErr
}
func (f *fakeExt4) uuid(_ *pinnedDevice) (string, error) {
	f.uuids++
	if len(f.uuidValues) > 0 {
		value := f.uuidValues[0]
		f.uuidValues = f.uuidValues[1:]
		return value, f.uuidErr
	}
	return testUUID, f.uuidErr
}
func (f *fakeExt4) mount(d *pinnedDevice, _ *pinnedTarget) error {
	f.mounts++
	f.mountDevice = d
	f.mounted = true
	return f.mountErr
}
func (f *fakeExt4) sync(_ *pinnedDevice, _ *pinnedTarget) error {
	f.syncs++
	return f.syncErr
}
func (f *fakeExt4) superblock(_ *pinnedDevice) (ext4SuperSummary, error) {
	f.superblocks++
	if len(f.superblockValues) > 0 {
		value := f.superblockValues[0]
		f.superblockValues = f.superblockValues[1:]
		return value, f.superblockErr
	}
	return fakeCleanSuperblock(), f.superblockErr
}
func (f *fakeExt4) mountReadOnly(d *pinnedDevice, _ *pinnedTarget) error {
	f.readOnlyMounts++
	f.mountReadOnlyDevice = d
	if f.mountReadOnlyErr != nil {
		return f.mountReadOnlyErr
	}
	f.probeMounted = true
	return nil
}
func (f *fakeExt4) dupDirectory(_ *pinnedTarget) (*os.File, error) {
	// A real readable directory: consumers can Readdirnames it, and while it
	// is open the fake mount stays busy like a real mount reference.
	dir, err := os.MkdirTemp("", "cengine-dup-root")
	if err != nil {
		return nil, err
	}
	file, err := os.Open(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	f.dupRoots = append(f.dupRoots, file)
	return file, nil
}
func (f *fakeExt4) unmountReadOnly(_ *pinnedDevice, _ string) error {
	f.unmounts++
	for _, dup := range f.dupRoots {
		if _, err := dup.Stat(); err == nil {
			return syscall.EBUSY // an open duplicated root holds the mount busy
		}
	}
	if f.unmountErr != nil {
		return f.unmountErr
	}
	f.probeMounted = false
	return nil
}
func transition(f *fakeExt4) ext4Transition { return ext4Transition{new(sync.Mutex), f} }
func initializeFake(f *fakeExt4) error {
	return transition(f).run("/dev/vdb", "/disk", "data", testUUID, testBytes, true)
}
func mountFake(f *fakeExt4) error { return transition(f).run("/dev/vdb", "/disk", "", "", 0, false) }

func TestMountExistingNeverFormats(t *testing.T) {
	for _, errno := range []error{syscall.EINVAL, syscall.ENODEV, syscall.EBUSY, syscall.EIO, syscall.EACCES, syscall.EROFS} {
		t.Run(errno.Error(), func(t *testing.T) {
			f := &fakeExt4{mountErr: errno}
			if err := mountFake(f); !errors.Is(err, errno) {
				t.Fatalf("error = %v", err)
			}
			if f.formats != 0 || f.uuids != 0 {
				t.Fatal("ordinary mount performed initialization work")
			}
		})
	}
	f := &fakeExt4{mounted: true}
	if err := mountFake(f); err != nil {
		t.Fatal(err)
	}
	if f.mounts != 0 || f.formats != 0 || f.uuids != 0 {
		t.Fatal("existing safe mount was modified")
	}
}
func TestMountedRootMetadataException(t *testing.T) {
	for _, uid := range []uint32{0, 1000} {
		for _, mode := range []uint32{0, 0700, 0777} {
			for _, mounted := range []bool{false, true} {
				f := &fakeExt4{mounted: mounted, leafUID: uid, leafMode: mode}
				err := mountFake(f)
				unsafe := uid != 0 || mode&0022 != 0
				if (err != nil) != (!mounted && unsafe) {
					t.Fatalf("uid=%d mode=%o mounted=%v: %v", uid, mode, mounted, err)
				}
				if f.formats != 0 || (mounted && (f.leafChecks != 0 || f.mounts != 0)) || (!mounted && unsafe && f.mounts != 0) {
					t.Fatalf("unexpected mutation: %+v", f)
				}
			}
		}
	}
}

func TestInspectRequiresVerifiedMountAndNeverMutates(t *testing.T) {
	for _, mounted := range []bool{false, true} {
		f := &fakeExt4{mounted: mounted, leafUID: 1000, leafMode: 0777}
		id, err := transition(f).inspect("/dev/vdb", "/disk")
		if (err == nil) != mounted {
			t.Fatalf("mounted=%v: %v", mounted, err)
		}
		if mounted && (id.UUID != testUUID || id.Bytes != testBytes || f.snapshots != 2) {
			t.Fatalf("identity=%+v ops=%+v", id, f)
		}
		if f.formats != 0 || f.mounts != 0 || f.leafChecks != 0 {
			t.Fatal("inspection mutated disk")
		}
		if !mounted && (f.uuids != 0 || f.capacities != 0) {
			t.Fatal("unverified identity read")
		}
	}
	for _, phase := range []string{"before", "after"} {
		f := &fakeExt4{}
		f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
			r := fakeMounted()
			if phase == "before" || f.snapshots == 2 {
				r.minor++
			}
			return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
		}
		if id, err := transition(f).inspect("/dev/vdb", "/disk"); err == nil || id != (Ext4Identity{}) {
			t.Fatal("accepted replaced/foreign mount")
		}
	}
}

func TestDestinationPolicy(t *testing.T) {
	cases := []struct {
		name   string
		change func(*mountRecord)
	}{
		{"foreign filesystem", func(r *mountRecord) { r.fs = "xfs" }},
		{"wrong major", func(r *mountRecord) { r.major++ }},
		{"wrong minor", func(r *mountRecord) { r.minor++ }},
		{"bind subtree", func(r *mountRecord) { r.root = "/sub" }},
		{"missing nodev", func(r *mountRecord) { r.options = "rw,nosuid" }},
		{"missing nosuid", func(r *mountRecord) { r.options = "rw,nodev" }},
		{"wrong errors policy", func(r *mountRecord) { r.superOptions = "rw,errors=continue" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fakeMounted()
			tc.change(&r)
			for _, init := range []bool{false, true} {
				f := &fakeExt4{leafUID: 1000, leafMode: 0777, snapshotHook: func(_ *fakeExt4, _ bool) (mountSnapshot, error) {
					return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
				}}
				err := transition(f).run("/dev/vdb", "/disk", "data", testUUID, testBytes, init)
				if err == nil || f.formats != 0 || f.mounts != 0 {
					t.Fatalf("unsafe operation: err=%v fake=%+v", err, f)
				}
			}
		})
	}
}
func TestVisibleMountAndStacks(t *testing.T) {
	lower, upper := fakeMounted(), fakeMounted()
	upper.id = 3
	upper.minor++
	hidden := fakeMounted()
	hidden.point = "/elsewhere"
	child := fakeMounted()
	child.point = "/disk/child"
	for _, s := range []mountSnapshot{
		{3, []mountRecord{fakeRoot(), lower, upper}},
		{2, []mountRecord{fakeRoot(), upper, lower}},
		{99, []mountRecord{fakeRoot(), lower}},
		{1, []mountRecord{fakeRoot(), lower}},
		{1, []mountRecord{fakeRoot(), child}},
		{1, []mountRecord{fakeRoot(), hidden}}, // mounted elsewhere is fatal for initialization
	} {
		f := &fakeExt4{snapshotHook: func(_ *fakeExt4, _ bool) (mountSnapshot, error) { return s, nil }}
		if err := initializeFake(f); err == nil || f.formats != 0 {
			t.Fatalf("accepted unsafe snapshot %+v", s)
		}
	}
}
func TestHiddenAncestorAtDifferentMountpoint(t *testing.T) {
	d := &pinnedDevice{major: 8, minor: 16}
	cover := mountRecord{id: 3, parent: 1, major: 0, minor: 3, root: "/", point: "/a", fs: "tmpfs"}
	hidden := mountRecord{id: 4, parent: 1, major: 0, minor: 4, root: "/", point: "/a/b", fs: "tmpfs"}
	for _, mounted := range []bool{false, true} {
		s := mountSnapshot{3, []mountRecord{fakeRoot(), cover, hidden}}
		if mounted {
			r := fakeMounted()
			r.id = 5
			r.parent = 3
			r.point = "/a/b/disk"
			s.visible = 5
			s.records = append(s.records, r)
		}
		if _, err := destinationState(s, d, "/a/b/disk"); err == nil {
			t.Fatal("accepted differently pathed hidden ancestor")
		}
		// Removing the hidden record leaves a valid ordinary ancestor chain.
		s.records = append(s.records[:2], s.records[3:]...)
		if got, err := destinationState(s, d, "/a/b/disk"); err != nil || got != mounted {
			t.Fatalf("valid ancestry: mounted=%v err=%v", got, err)
		}
	}
}

func TestRootParentVariants(t *testing.T) {
	for _, parent := range []uint64{0, 1, 999} {
		for _, mounted := range []bool{false, true} {
			root := fakeRoot()
			root.parent = parent
			s := mountSnapshot{1, []mountRecord{root}}
			if mounted {
				s.visible = 2
				s.records = append(s.records, fakeMounted())
			}
			got, err := destinationState(s, &pinnedDevice{major: 8, minor: 16}, "/disk")
			if err != nil || got != mounted {
				t.Fatalf("root parent=%d mounted=%v: got=%v err=%v", parent, mounted, got, err)
			}
		}
	}
}

func TestInitializationValidation(t *testing.T) {
	for _, tc := range []struct {
		label, uuid string
		size        uint64
	}{
		{"data", testUUID, 0}, {"data", testUUID, 4096}, {"data", testUUID, testBytes + 1}, {"data", testUUID, 1 << 63},
		{"", testUUID, testBytes}, {strings.Repeat("x", 17), testUUID, testBytes}, {"é", testUUID, testBytes}, {"x\n", testUUID, testBytes},
		{"data", "random", testBytes}, {"data", strings.ToUpper(testUUID), testBytes}, {"data", "00000000-0000-0000-0000-000000000000", testBytes},
		{"data", "12345678-1234-5678-9abc-123456789abg", testBytes},
	} {
		f := &fakeExt4{}
		if err := transition(f).run("/dev/vdb", "/disk", tc.label, tc.uuid, tc.size, true); err == nil || f.pins != 0 {
			t.Fatalf("accepted %+v", tc)
		}
	}
	if err := validateInitialization("data", testUUID, 1<<40); err != nil {
		t.Fatal("64-bit size rejected", err)
	}
}
func TestInitializationFailClosed(t *testing.T) {
	cases := []struct {
		name                    string
		f                       *fakeExt4
		wantFormats, wantMounts int
	}{
		{"pin", &fakeExt4{pinErr: syscall.ELOOP}, 0, 0},
		{"unsafe path", &fakeExt4{targetErr: syscall.EACCES}, 0, 0},
		{"mounted", &fakeExt4{mounted: true}, 0, 0},
		{"ioctl", &fakeExt4{capacityErr: syscall.ENOTTY}, 0, 0},
		{"wrong capacity", &fakeExt4{capacityValues: []uint64{testBytes + 4096}}, 0, 0},
		{"capacity changed", &fakeExt4{capacityValues: []uint64{testBytes, testBytes + 4096}}, 0, 0},
		{"format failure", &fakeExt4{formatErr: syscall.EIO}, 1, 0},
		{"uuid read", &fakeExt4{uuidErr: syscall.EIO}, 1, 0},
		{"wrong formatted UUID", &fakeExt4{uuidValues: []string{"other"}}, 1, 0},
		{"wrong mounted UUID", &fakeExt4{uuidValues: []string{testUUID, "other"}}, 1, 1},
		{"mount failure", &fakeExt4{mountErr: syscall.EBUSY}, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := initializeFake(tc.f); err == nil {
				t.Fatal("expected error")
			}
			if tc.f.formats != tc.wantFormats || tc.f.mounts != tc.wantMounts {
				t.Fatalf("unexpected attempts: %+v", tc.f)
			}
		})
	}
}
func TestPreDestructionRecheckAndPostMountIdentity(t *testing.T) {
	for _, phase := range []string{"destination replaced", "device mounted elsewhere", "wrong mounted disk", "mounted subtree"} {
		t.Run(phase, func(t *testing.T) {
			f := &fakeExt4{}
			f.snapshotHook = func(f *fakeExt4, same bool) (mountSnapshot, error) {
				if f.snapshots == 2 && phase == "destination replaced" {
					return mountSnapshot{}, fmt.Errorf("replacement")
				}
				if f.snapshots == 2 && phase == "device mounted elsewhere" {
					r := fakeMounted()
					r.point = "/other"
					return mountSnapshot{1, []mountRecord{fakeRoot(), r}}, nil
				}
				if !same {
					r := fakeMounted()
					if phase == "wrong mounted disk" {
						r.minor++
					}
					if phase == "mounted subtree" {
						r.root = "/sub"
					}
					return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
				}
				return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
			}
			if err := initializeFake(f); err == nil {
				t.Fatal("expected rejection")
			}
			if (phase == "destination replaced" || phase == "device mounted elsewhere") && f.formats != 0 {
				t.Fatal("destructive recheck failed")
			}
		})
	}
}
func TestInitializationSuccessUsesSamePin(t *testing.T) {
	f := &fakeExt4{}
	if err := initializeFake(f); err != nil {
		t.Fatal(err)
	}
	if f.formats != 1 || f.mounts != 1 || f.pins != 1 || f.capacities != 2 || f.uuids != 2 || f.formatDevice != f.mountDevice {
		t.Fatalf("unexpected operations %+v", f)
	}
}
func TestTransitionsSerialize(t *testing.T) {
	f := &fakeExt4{}
	tr := transition(f)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = tr.run("/dev/vdb", "/disk", "data", testUUID, testBytes, true) }()
	}
	wg.Wait()
	if f.formats != 1 {
		t.Fatalf("format attempts=%d", f.formats)
	}
}
func TestRejectUncleanPathsBeforePin(t *testing.T) {
	for _, path := range []string{"relative", "/", "/disk/../other", "/disk/", "/disk\x00"} {
		f := &fakeExt4{}
		if err := transition(f).run("/dev/vdb", path, "", "", 0, false); err == nil || f.pins != 0 {
			t.Fatalf("accepted %q", path)
		}
	}
}
func TestProbeRejectsDirtyRecoveryMismatchAndUnknownFeaturesBeforeMount(t *testing.T) {
	bad := func(mutate func(*ext4SuperSummary)) ext4SuperSummary {
		s := fakeCleanSuperblock()
		mutate(&s)
		return s
	}
	cases := []struct {
		name string
		f    *fakeExt4
	}{
		{"missing VALID_FS", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.State = 0 })}}},
		{"ERROR_FS", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.State = ext4ErrorFS })}}},
		{"journal recovery pending", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.Incompat |= ext4FeatureIncompatRecover })}}},
		{"orphan inode list present", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.LastOrphan = 7 })}}},
		{"orphan-present feature", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.ROCompat |= ext4FeatureROOrphanPresent })}}},
		{"UUID mismatch", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.UUID = "abcdefab-1234-5678-9abc-123456789abc" })}}},
		{"unsupported compat feature", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.Compat |= 0x0001 })}}},
		{"unsupported incompat feature", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.Incompat |= 0x0001 })}}},
		{"unsupported ro_compat feature", &fakeExt4{superblockValues: []ext4SuperSummary{bad(func(s *ext4SuperSummary) { s.ROCompat |= 0x0200 })}}},
		{"capacity mismatch", &fakeExt4{capacityValues: []uint64{testBytes + 4096}}},
		{"already mounted", &fakeExt4{probeMounted: true}},
		{"superblock read failure", &fakeExt4{superblockErr: syscall.EIO}},
		{"mount failure consumed", &fakeExt4{mountReadOnlyErr: syscall.EBUSY}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tprobe, err := transition(tc.f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
			if err == nil || tprobe != (Ext4ReadOnlyLease{}) {
				t.Fatalf("accepted %+v: %v", tc.f, err)
			}
			if tc.f.formats != 0 || tc.f.mounts != 0 || tc.f.syncs != 0 || tc.f.unmounts != 0 {
				t.Fatalf("probe mutated disk: %+v", tc.f)
			}
			wantMounts := 0
			if tc.name == "mount failure consumed" {
				wantMounts = 1 // mount was attempted only after clean preflight passed
			}
			if tc.f.readOnlyMounts != wantMounts {
				t.Fatalf("unexpected mount attempts: %+v", tc.f)
			}
		})
	}
}
func TestProbeSuccessUsesSameReadOnlyPin(t *testing.T) {
	f := &fakeExt4{}
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err != nil {
		t.Fatal(err)
	}
	if probe.lease == nil {
		t.Fatal("probe returned no lease")
	}
	if probe.Identity() != (Ext4Identity{UUID: testUUID, Bytes: testBytes}) || probe.Device() != "/dev/vdb" || probe.Destination() != "/disk" {
		t.Fatalf("identity mismatch: %+v", probe)
	}
	if probe.lease.mountID != 2 || probe.lease.device == nil || probe.lease.root == nil {
		t.Fatalf("lease retained no pins/mount ID: %+v", probe.lease)
	}
	// The lease retains the pinned device and root descriptors (and the flock).
	if _, err := probe.lease.device.file.Stat(); err != nil {
		t.Fatalf("device pin not retained: %v", err)
	}
	if _, err := probe.lease.root.Stat(); err != nil {
		t.Fatalf("root pin not retained: %v", err)
	}
	// Two pre-mount passes (each: capacity + superblock), one read-only mount,
	// never a format, rw mount or sync.
	if f.readOnlyMounts != 1 || f.capacities != 2 || f.superblocks != 2 || f.formats != 0 || f.mounts != 0 || f.syncs != 0 || f.uuids != 0 {
		t.Fatalf("unexpected operations: %+v", f)
	}
	if f.mountReadOnlyDevice == nil || f.pins != 1 || f.mountReadOnlyDevice.file == nil {
		t.Fatalf("probe did not use the pinned device: %+v", f)
	}
}

func TestProbeLeaseRootDupAndCloseShareState(t *testing.T) {
	f := &fakeExt4{}
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := probe.Root()
	if err != nil {
		t.Fatal(err)
	}
	if root.Fd() == probe.lease.root.Fd() {
		t.Fatal("Root returned the retained pin, not a dup")
	}
	if _, err := root.Stat(); err != nil {
		t.Fatalf("root dup invalid: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	// Copies of the value share the lease: closing one closes all.
	copyLease := probe
	if err := copyLease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := probe.lease.device.file.Stat(); err == nil {
		t.Fatal("device pin not closed by Close")
	}
	if _, err := probe.Root(); err == nil {
		t.Fatal("Root on closed lease accepted")
	}
	if err := probe.Close(); err != nil {
		t.Fatal("Close not idempotent")
	}
	if f.formats != 0 || f.mounts != 0 || f.syncs != 0 || f.unmounts != 1 {
		t.Fatalf("unexpected operations: %+v", f)
	}
	// The zero lease is inert and hides nothing.
	var zero Ext4ReadOnlyLease
	if zero.Identity() != (Ext4Identity{}) || zero.Device() != "" || zero.Destination() != "" {
		t.Fatal("zero lease exposed state")
	}
	if _, err := zero.Root(); err == nil {
		t.Fatal("zero lease Root accepted")
	}
	if err := zero.Close(); err != nil {
		t.Fatal("zero lease Close errored")
	}
}

func TestProbePostMountRejectionRollsBackExactOwnedMount(t *testing.T) {
	// A post-mount verification failure must unmount only the exact mount the
	// probe created, proved from a fresh snapshot, and never a foreign one.
	f := &fakeExt4{}
	f.snapshotHook = func(f *fakeExt4, same bool) (mountSnapshot, error) {
		if !same {
			r := fakeProbeMounted()
			r.minor++              // our device is positively absent from the entire snapshot
			f.probeMounted = false // model actual detach, not a hidden owned mount
			return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
		}
		return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
	}
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err == nil || probe != (Ext4ReadOnlyLease{}) {
		t.Fatalf("accepted replaced post-mount identity: %v", err)
	}
	if f.unmounts != 0 {
		t.Fatalf("foreign mount unmounted: %+v", f)
	}
	// Failed first proof cannot acquire ownership from a later good snapshot.
	f = &fakeExt4{}
	f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
		if !f.probeMounted {
			return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
		}
		r := fakeProbeMounted()
		if f.snapshots == 3 {
			r.options = "rw,nodev,nosuid"
		}
		return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
	}
	unknown, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err == nil || unknown.lease == nil || unknown.lease.mountID != 0 || f.unmounts != 0 {
		t.Fatalf("failed first proof adopted ownership: lease=%+v err=%v", unknown.lease, err)
	}
	if err := unknown.Close(); err == nil || f.unmounts != 0 {
		t.Fatal("cleanup adopted unknown mount")
	}
	f.probeMounted = false
	if err := unknown.Close(); err != nil {
		t.Fatal(err)
	}

	// Once mount ID 2 was proved, a later post-pin failure can attempt cleanup
	// only of that same ID. EBUSY must retain that original ownership and lock.
	f = &fakeExt4{unmountErr: syscall.EBUSY}
	f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
		if f.snapshots == 4 {
			return mountSnapshot{}, syscall.EIO
		}
		if f.probeMounted {
			return mountSnapshot{2, []mountRecord{fakeRoot(), fakeProbeMounted()}}, nil
		}
		return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
	}
	lease, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err == nil || !strings.Contains(err.Error(), "may remain") || f.unmounts != 1 {
		t.Fatalf("rollback failure hidden: %v", err)
	}
	if lease.lease == nil || lease.lease.state != leaseClosePending || lease.lease.root != nil || lease.lease.mountID != 2 {
		t.Fatalf("no retained closePending cleanup lease: %+v", lease.lease)
	}
	if _, err := lease.lease.device.file.Stat(); err != nil {
		t.Fatalf("device pin/flock released: %v", err)
	}
	if _, err := lease.Root(); err == nil {
		t.Fatal("Root allowed on cleanup lease")
	}
	f.unmountErr = nil
	f.snapshotHook = nil
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

// The fake must model pre-FD vs post-FD mount IDs, otherwise the stale
// pre-mount root pin bug is invisible: a pin taken before the mount still
// observes the parent mount ID and must be rejected by a requireSame snapshot.
func TestFakeModelsPreAndPostMountRootPins(t *testing.T) {
	f := &fakeExt4{}
	pre, err := f.pinTarget("/disk")
	if err != nil {
		t.Fatal(err)
	}
	defer pre.file.Close()
	f.probeMounted = true // the mount now exists, but the pin predates it
	if _, err := f.snapshot(pre, true); err == nil {
		t.Fatal("stale pre-mount pin accepted as the mounted root")
	}
	post, err := f.pinTarget("/disk")
	if err != nil {
		t.Fatal(err)
	}
	defer post.file.Close()
	if _, err := f.snapshot(post, true); err != nil {
		t.Fatalf("post-mount pin rejected: %v", err)
	}
}

// A successful probe retains the POST-mount root pin: it observes the exact
// verified mount ID, and Root returns a readable directory descriptor (the
// O_PATH pin alone cannot serve Readdirnames).
func TestProbeLeaseRootIsPostMountReadableDirectory(t *testing.T) {
	f := &fakeExt4{}
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.fdMountIDs[int(probe.lease.root.Fd())]; got != 2 {
		t.Fatalf("lease retained a pre-mount root pin (mount ID %d)", got)
	}
	if probe.lease.state != leaseOwned || probe.lease.mountID != 2 {
		t.Fatalf("lease not owned with exact mount ID: %+v", probe.lease)
	}
	root, err := probe.Root()
	if err != nil {
		t.Fatal(err)
	}
	if root.Fd() == probe.lease.root.Fd() {
		t.Fatal("Root returned the retained pin, not a new descriptor")
	}
	if _, err := root.Readdirnames(-1); err != nil {
		t.Fatalf("Root descriptor is not a readable directory: %v", err)
	}
	// The consumer must close the dup before the lease: an open dup makes the
	// unmount EBUSY.
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
}

// The post-mount pin must observe the exact mount ID the probe verified. A pin
// observing a different mount fails the probe and the rollback unmounts only a
// mount proved owned.
func TestProbePostMountPinMustObserveVerifiedMountID(t *testing.T) {
	f := &fakeExt4{}
	f.snapshotHook = func(f *fakeExt4, same bool) (mountSnapshot, error) {
		if same && f.snapshots == 4 { // the post-mount root pin observes mount 3
			r := fakeProbeMounted()
			r.id = 3
			return mountSnapshot{3, []mountRecord{fakeRoot(), r}}, nil
		}
		if f.probeMounted {
			return mountSnapshot{2, []mountRecord{fakeRoot(), fakeProbeMounted()}}, nil
		}
		return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
	}
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err == nil || probe != (Ext4ReadOnlyLease{}) {
		t.Fatalf("accepted a root pin on a different mount ID: %v", err)
	}
	if f.unmounts != 1 || f.probeMounted {
		t.Fatalf("owned mount not rolled back exactly once: %+v", f)
	}
}

// Rollback uncertainty (the re-proof snapshot itself fails) must retain a
// probe-failed cleanup lease with the device pin and flock held — never a zero
// lease with every pin closed while a mount may remain. Without an original
// mount ID, Close retains the pin until namespace-wide device absence is proven.
func TestProbeRollbackRetainsCleanupLeaseWhenProofUncertain(t *testing.T) {
	f := &fakeExt4{}
	f.snapshotHook = func(f *fakeExt4, same bool) (mountSnapshot, error) {
		if f.snapshots == 4 { // rollback re-proof: mountinfo unavailable
			return mountSnapshot{}, fmt.Errorf("mountinfo unavailable")
		}
		if !same && f.snapshots == 3 { // post-mount verify: policy mismatch
			r := fakeProbeMounted()
			r.options = "rw,nodev,nosuid"
			return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
		}
		if f.probeMounted {
			return mountSnapshot{2, []mountRecord{fakeRoot(), fakeProbeMounted()}}, nil
		}
		return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
	}
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err == nil || !strings.Contains(err.Error(), "may remain") {
		t.Fatalf("rollback uncertainty hidden: %v", err)
	}
	if probe.lease == nil || probe.lease.state != leaseProbeFailed || probe.lease.root != nil {
		t.Fatalf("no retained probe-failed cleanup lease: %+v", probe.lease)
	}
	if _, err := probe.lease.device.file.Stat(); err != nil {
		t.Fatalf("device pin/flock released on uncertain rollback: %v", err)
	}
	if _, err := probe.Root(); err == nil {
		t.Fatal("Root allowed on probe-failed cleanup lease")
	}
	if err := probe.Close(); err == nil || f.unmounts != 0 {
		t.Fatal("cleanup adopted an unproven original mount ID")
	}
	f.probeMounted = false
	f.snapshotHook = func(_ *fakeExt4, _ bool) (mountSnapshot, error) {
		return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("cleanup Close did not accept proven device absence: %v", err)
	}
	if _, err := probe.lease.device.file.Stat(); err == nil {
		t.Fatal("device pin retained after confirmed detach")
	}
	if err := probe.Close(); err != nil {
		t.Fatal("Close not idempotent")
	}
}

// Consumers must close descriptors duplicated from Root before Close: an open
// dup holds the mount busy, so the first Close fails with EBUSY, retains the
// device lock in closePending state, and a retry after closing the dup
// safely repins, reproves and detaches.
func TestProbeLeaseCloseEBUSYRetainsAndRetryAfterDupClose(t *testing.T) {
	f := &fakeExt4{}
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := probe.Root()
	if err != nil {
		t.Fatal(err)
	}
	err = probe.Close()
	if !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("Close with an open dup: %v", err)
	}
	if probe.lease.state != leaseClosePending || probe.lease.root != nil {
		t.Fatalf("lease not closePending after EBUSY: %+v", probe.lease)
	}
	if _, err := probe.lease.device.file.Stat(); err != nil {
		t.Fatalf("device pin/flock released on EBUSY: %v", err)
	}
	if !f.probeMounted {
		t.Fatal("mount detached despite EBUSY")
	}
	if _, err := probe.Root(); err == nil {
		t.Fatal("Root allowed while closePending")
	}
	if err := dup.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("retry Close after dup close: %v", err)
	}
	if f.unmounts != 2 || f.probeMounted {
		t.Fatalf("detach not retried exactly once: %+v", f)
	}
	if _, err := probe.lease.device.file.Stat(); err == nil {
		t.Fatal("device pin retained after confirmed detach")
	}
	if err := probe.Close(); err != nil {
		t.Fatal("Close not idempotent")
	}
}

// A closePending retry whose repin fails retains the lease and the device
// lock, and a later retry still succeeds.
func TestProbeLeaseCloseRetryRepinFailureRetains(t *testing.T) {
	f := &fakeExt4{failRepinAfter: 2} // probe pins twice (pre + post); retry repin is the third
	probe, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err != nil {
		t.Fatal(err)
	}
	f.probeMounted = false // the mount moved on: the held post pin (ID 2) is stale
	if err := probe.Close(); err == nil {
		t.Fatal("Close accepted a stale root pin")
	}
	if probe.lease.root != nil || probe.lease.state != leaseProbeFailed {
		t.Fatalf("stale root pin retained: %+v", probe.lease)
	}
	// Whatever the failure, the device lock is retained for cleanup retry.
	if _, err := probe.lease.device.file.Stat(); err != nil {
		t.Fatalf("device pin/flock released: %v", err)
	}
	// The retry repin itself fails: the lease and the device lock stay held.
	if err := probe.Close(); err == nil {
		t.Fatal("repin failure swallowed")
	}
	if _, err := probe.lease.device.file.Stat(); err != nil {
		t.Fatalf("device pin/flock released after repin failure: %v", err)
	}
	// With the repin allowed and the mount already gone, cleanup completes.
	f.failRepinAfter = 0
	if err := probe.Close(); err != nil {
		t.Fatalf("retry Close after repin failure: %v", err)
	}
	if _, err := probe.lease.device.file.Stat(); err == nil {
		t.Fatal("device pin retained after confirmed detach")
	}
}
func TestProbeDestinationStateRequiresReadOnlyNoReplayPolicy(t *testing.T) {
	cases := []struct {
		name   string
		change func(*mountRecord)
	}{
		{"read-write options", func(r *mountRecord) { r.options = "rw,nodev,nosuid" }},
		{"missing ro", func(r *mountRecord) { r.options = "nodev,nosuid" }},
		{"missing nodev", func(r *mountRecord) { r.options = "ro,nosuid" }},
		{"missing nosuid", func(r *mountRecord) { r.options = "ro,nodev" }},
		{"rw super options", func(r *mountRecord) { r.superOptions = "rw,noload" }},
		{"missing noload", func(r *mountRecord) { r.superOptions = "ro,errors=remount-ro" }},
		{"foreign filesystem", func(r *mountRecord) { r.fs = "xfs" }},
		{"wrong device", func(r *mountRecord) { r.minor++ }},
		{"bind subtree", func(r *mountRecord) { r.root = "/sub" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fakeProbeMounted()
			tc.change(&r)
			mounted, err := probeDestinationState(mountSnapshot{2, []mountRecord{fakeRoot(), r}}, &pinnedDevice{major: 8, minor: 16}, "/disk")
			if err == nil || mounted {
				t.Fatalf("accepted %+v: mounted=%v err=%v", r, mounted, err)
			}
		})
	}
	mounted, err := probeDestinationState(mountSnapshot{2, []mountRecord{fakeRoot(), fakeProbeMounted()}}, &pinnedDevice{major: 8, minor: 16}, "/disk")
	if err != nil || !mounted {
		t.Fatalf("clean probe mount rejected: mounted=%v err=%v", mounted, err)
	}
	// The kernel accepts norecovery as the noload alias; the visible mount may
	// record either, but ro/nodev/nosuid remain mandatory.
	alias := fakeProbeMounted()
	alias.superOptions = "ro,norecovery"
	mounted, err = probeDestinationState(mountSnapshot{2, []mountRecord{fakeRoot(), alias}}, &pinnedDevice{major: 8, minor: 16}, "/disk")
	if err != nil || !mounted {
		t.Fatalf("norecovery alias rejected: mounted=%v err=%v", mounted, err)
	}
}
func TestParseExt4Superblock(t *testing.T) {
	data := make([]byte, 2048)
	if _, err := parseExt4Superblock(data); err == nil {
		t.Fatal("zero header accepted")
	}
	super := data[1024:]
	binary.LittleEndian.PutUint16(super[0x38:0x3a], 0xef53)
	binary.LittleEndian.PutUint16(super[0x3a:0x3c], ext4ValidFS)
	binary.LittleEndian.PutUint32(super[0x5c:0x60], ext4FeatureCompatHasJournal)
	binary.LittleEndian.PutUint32(super[0x60:0x64], ext4FeatureIncompatExtents)
	binary.LittleEndian.PutUint32(super[0x64:0x68], ext4FeatureROMetadataCsum)
	raw, _ := hex.DecodeString(strings.ReplaceAll(testUUID, "-", ""))
	copy(super[0x68:0x78], raw)
	binary.LittleEndian.PutUint32(super[0xe8:0xec], 4)
	s, err := parseExt4Superblock(data)
	if err != nil {
		t.Fatal(err)
	}
	if s.UUID != testUUID || s.State != ext4ValidFS || s.Compat != ext4FeatureCompatHasJournal ||
		s.Incompat != ext4FeatureIncompatExtents || s.ROCompat != ext4FeatureROMetadataCsum || s.LastOrphan != 4 {
		t.Fatalf("parsed %+v", s)
	}
	if err := requireCleanSuperblock(s, testUUID); err == nil {
		t.Fatal("non-empty orphan list accepted")
	}
	s.LastOrphan = 0
	if err := requireCleanSuperblock(s, testUUID); err != nil {
		t.Fatal(err)
	}
	if err := requireCleanSuperblock(s, "abcdefab-1234-5678-9abc-123456789abc"); err == nil {
		t.Fatal("UUID mismatch accepted")
	}
}

func TestMountinfoParser(t *testing.T) {
	records, err := parseMountinfo("42 1 8:16 / /disk\\040space rw,nodev,nosuid shared:2 - ext4 /dev/vdb rw,errors=remount-ro\n")
	if err != nil || len(records) != 1 || records[0].point != "/disk space" {
		t.Fatalf("%+v %v", records, err)
	}
	for _, bad := range []string{"", "1 0 8:x / / rw - ext4 disk rw", "1 0 8:1 / /bad\\999 rw - ext4 disk rw", "1 0 8:1 / / rw - ext4 disk rw\n1 0 8:1 / / rw - ext4 disk rw"} {
		if _, err := parseMountinfo(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
