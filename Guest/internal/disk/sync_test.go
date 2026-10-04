package disk

import (
	"errors"
	"reflect"
	"syscall"
	"testing"
)

func TestSyncIdentityRequiresVisibleMountAndReverifies(t *testing.T) {
	for _, phase := range []string{"unmounted", "sync", "replaced", "uuid", "capacity", "success"} {
		t.Run(phase, func(t *testing.T) {
			f := &fakeExt4{mounted: phase != "unmounted", leafUID: 1000, leafMode: 0777}
			if phase == "sync" {
				f.syncErr = syscall.EIO
			}
			if phase == "uuid" {
				f.uuidErr = syscall.EIO
			}
			if phase == "capacity" {
				f.capacityErr = syscall.EIO
			}
			if phase == "replaced" {
				f.snapshotHook = func(f *fakeExt4, _ bool) (mountSnapshot, error) {
					if f.snapshots == 2 {
						return mountSnapshot{}, errors.New("replaced")
					}
					return mountSnapshot{2, []mountRecord{fakeRoot(), fakeMounted()}}, nil
				}
			}
			id, err := transition(f).observe("/dev/vdb", "/disk", true)
			if phase == "success" {
				if err != nil || id.UUID != testUUID || id.Bytes != testBytes || f.syncs != 1 || f.snapshots != 3 {
					t.Fatalf("id=%+v err=%v ops=%+v", id, err, f)
				}
			} else if err == nil || id != (Ext4Identity{}) {
				t.Fatalf("failed phase returned identity: %+v %v", id, err)
			}
			if phase == "unmounted" && f.syncs != 0 {
				t.Fatal("synced unverified mount")
			}
			if f.formats != 0 || f.mounts != 0 || f.leafChecks != 0 {
				t.Fatal("sync changed filesystem or root metadata")
			}
		})
	}
}

func TestCheckedDiskSyncOrderingAndFailures(t *testing.T) {
	for _, failed := range []string{"verify-before", "syncfs", "block-fsync", "verify-after", ""} {
		var calls []string
		call := func(name string) error {
			calls = append(calls, name)
			if name == failed {
				return syscall.EIO
			}
			return nil
		}
		verify := func() error {
			if len(calls) == 0 {
				return call("verify-before")
			}
			return call("verify-after")
		}
		err := checkedDiskSync(func() error { return call("syncfs") }, func() error { return call("block-fsync") }, verify)
		if (err == nil) != (failed == "") {
			t.Fatalf("phase %s: %v", failed, err)
		}
		want := []string{"verify-before", "syncfs", "block-fsync", "verify-after"}
		for i, name := range want {
			if name == failed {
				want = want[:i+1]
				break
			}
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("phase %s: calls=%v want=%v", failed, calls, want)
		}
	}
}
