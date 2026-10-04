package disk

import (
	"errors"
	"sync"
	"syscall"
	"testing"
)

// Simulate an uncertain mount syscall: errno does not establish whether a
// mount was attached, and cannot grant ownership of anything now visible.
type uncertainProbeMountOps struct{ *fakeExt4 }

func (f uncertainProbeMountOps) mountReadOnly(d *pinnedDevice, target *pinnedTarget) error {
	err := f.fakeExt4.mountReadOnly(d, target)
	f.probeMounted = true
	return err
}

func TestProbeMountErrnoRequiresPositiveAbsence(t *testing.T) {
	for _, outcome := range []string{"present", "snapshot-error", "absent"} {
		t.Run(outcome, func(t *testing.T) {
			f := &fakeExt4{mountReadOnlyErr: syscall.EIO}
			f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
				if f.readOnlyMounts == 0 || outcome == "absent" {
					return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
				}
				if outcome == "snapshot-error" {
					return mountSnapshot{}, syscall.EIO
				}
				return mountSnapshot{2, []mountRecord{fakeRoot(), fakeProbeMounted()}}, nil
			}
			lease, err := (ext4Transition{new(sync.Mutex), uncertainProbeMountOps{f}}).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
			if !errors.Is(err, syscall.EIO) || f.unmounts != 0 {
				t.Fatalf("errno lost or unknown mount detached: %v", err)
			}
			device := f.mountReadOnlyDevice.file
			if outcome == "absent" {
				if lease.lease != nil {
					t.Fatal("absence retained a lease")
				}
				if _, err := device.Stat(); err == nil {
					t.Fatal("absence retained device pin")
				}
				return
			}
			if lease.lease == nil || lease.lease.mountID != 0 {
				t.Fatal("uncertain mount acquired ownership or lost lease")
			}
			if _, err := device.Stat(); err != nil {
				t.Fatal("uncertainty released device/flock", err)
			}
			if _, err := lease.Root(); err == nil {
				t.Fatal("uncertain mount exposed Root")
			}
			if err := lease.Close(); err == nil || f.unmounts != 0 {
				t.Fatal("Close detached unknown mount")
			}
			if _, err := device.Stat(); err != nil {
				t.Fatal("failed cleanup released device/flock", err)
			}
			f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) { return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil }
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := device.Stat(); err == nil {
				t.Fatal("positive absence did not release pin")
			}
		})
	}
}

func TestProbeRollbackNeverAdoptsChangedOriginalMountID(t *testing.T) {
	f := &fakeExt4{}
	f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
		if !f.probeMounted {
			return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
		}
		r := fakeProbeMounted()
		if f.snapshots >= 4 {
			r.id = 3
		} // first proof was ID 2; replacement persists into rollback
		return mountSnapshot{r.id, []mountRecord{fakeRoot(), r}}, nil
	}
	lease, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err == nil || lease.lease == nil || lease.lease.mountID != 2 || f.unmounts != 0 {
		t.Fatalf("rollback adopted replacement: lease=%+v err=%v", lease.lease, err)
	}
	if err := lease.Close(); err == nil || f.unmounts != 0 {
		t.Fatal("Close adopted replacement")
	}
	if _, err := lease.lease.device.file.Stat(); err != nil {
		t.Fatal("replacement released device/flock", err)
	}
	f.probeMounted = false
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProbeRollbackDetachRequiresCompleteAbsence(t *testing.T) {
	for _, outcome := range []string{"elsewhere", "snapshot-error"} {
		t.Run(outcome, func(t *testing.T) {
			f := &fakeExt4{}
			f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
				if f.snapshots == 4 {
					return mountSnapshot{}, syscall.EIO
				} // failure after original ID 2 proved
				if f.unmounts > 0 {
					if outcome == "snapshot-error" {
						return mountSnapshot{}, syscall.EIO
					}
					r := fakeProbeMounted()
					r.id = 9
					r.point = "/elsewhere"
					return mountSnapshot{1, []mountRecord{fakeRoot(), r}}, nil
				}
				if f.probeMounted {
					return mountSnapshot{2, []mountRecord{fakeRoot(), fakeProbeMounted()}}, nil
				}
				return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
			}
			lease, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
			if err == nil || lease.lease == nil || f.unmounts != 1 || lease.lease.mountID != 0 {
				t.Fatalf("post-detach uncertainty lost lease: %+v %v", lease.lease, err)
			}
			if _, err := lease.lease.device.file.Stat(); err != nil {
				t.Fatal("detach released device/flock without absence", err)
			}
			if err := lease.Close(); err == nil || f.unmounts != 1 {
				t.Fatal("cleanup detached an unowned alias")
			}
			f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) { return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil }
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProbePersistentPolicyMismatchRetainsWriterExclusion(t *testing.T) {
	f := &fakeExt4{}
	f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
		if !f.probeMounted {
			return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
		}
		r := fakeProbeMounted()
		r.options = "ro,nosuid" // same owned disk/mount, but policy proof fails
		return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
	}
	lease, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err == nil || lease.lease == nil {
		t.Fatalf("policy failure lost ownership: lease=%+v error=%v", lease, err)
	}
	if _, err := lease.Root(); err == nil {
		t.Fatal("cleanup-only lease exposed a root")
	}
	if err := lease.Close(); err == nil {
		t.Fatal("unproven policy allowed detach")
	}
	if _, err := lease.lease.device.file.Stat(); err != nil || !f.probeMounted || f.unmounts != 0 {
		t.Fatalf("writer exclusion dropped while disk remains mounted: %v", err)
	}
	// No original mount ID was proven: even a valid same-device replacement
	// cannot become detach authority merely by observing its current policy.
	f.snapshotHook = func(_ *fakeExt4, _ bool) (mountSnapshot, error) {
		r := fakeProbeMounted()
		r.id = 3
		return mountSnapshot{3, []mountRecord{fakeRoot(), r}}, nil
	}
	if err := lease.Close(); err == nil || f.unmounts != 0 {
		t.Fatal("unknown original mount accepted a replacement for cleanup")
	}
	// Only positive namespace-wide absence can now release this cleanup lease.
	f.probeMounted = false
	f.snapshotHook = func(_ *fakeExt4, _ bool) (mountSnapshot, error) {
		return mountSnapshot{1, []mountRecord{fakeRoot()}}, nil
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProbeForeignOrMovedMountDoesNotProveDeviceAbsence(t *testing.T) {
	for _, mode := range []string{"hidden", "moved", "policy"} {
		t.Run(mode, func(t *testing.T) {
			f := &fakeExt4{}
			lease, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
			if err != nil {
				t.Fatal(err)
			}
			f.snapshotHook = func(_ *fakeExt4, _ bool) (mountSnapshot, error) {
				owned := fakeProbeMounted()
				switch mode {
				case "hidden":
					foreign := owned
					foreign.id, foreign.minor = 3, owned.minor+1
					return mountSnapshot{3, []mountRecord{fakeRoot(), owned, foreign}}, nil
				case "moved":
					owned.point = "/elsewhere"
					return mountSnapshot{1, []mountRecord{fakeRoot(), owned}}, nil
				default:
					owned.superOptions = "ro" // no no-replay observation
					return mountSnapshot{2, []mountRecord{fakeRoot(), owned}}, nil
				}
			}
			if err := lease.Close(); err == nil {
				t.Fatal("Close mistook failed verification for device absence")
			}
			if _, err := lease.lease.device.file.Stat(); err != nil || f.unmounts != 0 {
				t.Fatalf("lost ownership or detached unproven mount: %v", err)
			}
			f.snapshotHook = nil
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProbeCloseRetryPreservesOriginalMountID(t *testing.T) {
	f := &fakeExt4{unmountErr: syscall.EBUSY}
	lease, err := transition(f).probeReadOnly("/dev/vdb", "/disk", testUUID, testBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("expected retained busy mount: %v", err)
	}
	f.unmountErr = nil
	f.snapshotHook = func(_ *fakeExt4, _ bool) (mountSnapshot, error) {
		r := fakeProbeMounted()
		r.id = 3 // same device/policy but not the originally held mount ID
		return mountSnapshot{3, []mountRecord{fakeRoot(), r}}, nil
	}
	if err := lease.Close(); err == nil {
		t.Fatal("retry forgot the original mount identity")
	}
	if lease.lease.mountID != 2 || f.unmounts != 1 {
		t.Fatal("retry detached or adopted a different mount")
	}
	if _, err := lease.lease.device.file.Stat(); err != nil {
		t.Fatal("failed retry lost the device pin")
	}
	f.snapshotHook = nil
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}
