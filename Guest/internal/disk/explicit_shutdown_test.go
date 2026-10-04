package disk

import (
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
)

// Promotion and fresh cleanup use the same block durability operation.
func (f *promotionFake) syncBlock(*pinnedDevice) error { return nil }

type shutdownFake struct {
	*fakeExt4
	blocks   int
	blockErr error
}

func (f *shutdownFake) syncBlock(*pinnedDevice) error { f.blocks++; return f.blockErr }
func (f *shutdownFake) unmountReadOnly(d *pinnedDevice, path string) error {
	if err := f.fakeExt4.unmountReadOnly(d, path); err != nil {
		return err
	}
	f.mounted = false
	return nil
}
func freshShutdown(t *testing.T, f *shutdownFake) Ext4ShutdownLease {
	t.Helper()
	var l Ext4ShutdownLease
	err := (ext4Transition{new(sync.Mutex), f}).runRetained("/dev/vdb", "/disk", "data", testUUID, testBytes, true, &l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, root := range f.dupRoots {
			root.Close()
			os.Remove(root.Name())
		}
		f.syncErr, f.blockErr, f.unmountErr, f.snapshotHook = nil, nil, nil, nil
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	return l
}
func TestFreshShutdownRetainsOriginalDeviceAndRoot(t *testing.T) {
	f := &shutdownFake{fakeExt4: &fakeExt4{}}
	l := freshShutdown(t, f)
	if l.lease.device != f.formatDevice || l.lease.device != f.mountDevice || f.pins != 1 {
		t.Fatal("original pin lost")
	}
	if id, err := l.SyncIdentity(); err != nil || id.UUID != testUUID || f.pins != 1 {
		t.Fatal(id, err)
	}
	root, err := l.Root()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); !errors.Is(err, syscall.EBUSY) {
		t.Fatal("open root did not block detach", err)
	}
	if _, err := l.lease.device.file.Stat(); err != nil {
		t.Fatal("released busy block", err)
	}
	root.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if f.syncs != 3 || f.blocks != 1 || !l.lease.closed {
		t.Fatal("missing durability/close", f.syncs, f.blocks)
	}
	copy := l
	if err := copy.Close(); err != nil {
		t.Fatal("copy close not idempotent", err)
	}
	if root, err := copy.Root(); err == nil {
		root.Close()
		t.Fatal("copy granted closed root")
	}
}
func TestFreshShutdownUncertaintyRetainsLease(t *testing.T) {
	for _, stage := range []string{"sync", "unmount", "block"} {
		t.Run(stage, func(t *testing.T) {
			f := &shutdownFake{fakeExt4: &fakeExt4{}}
			l := freshShutdown(t, f)
			switch stage {
			case "sync":
				f.syncErr = syscall.EIO
			case "unmount":
				f.unmountErr = syscall.EBUSY
			case "block":
				f.blockErr = syscall.EIO
			}
			if err := l.Close(); err == nil {
				t.Fatal("uncertain close succeeded")
			}
			if l.lease.closed {
				t.Fatal("released lease")
			}
			if root, err := l.Root(); err == nil {
				root.Close()
				t.Fatal("cleanup failure granted a new root")
			}
			if _, err := l.SyncIdentity(); err == nil {
				t.Fatal("cleanup failure granted new synchronization evidence")
			}
			if _, err := l.lease.device.file.Stat(); err != nil {
				t.Fatal(err)
			}
			if stage == "sync" && f.unmounts != 0 {
				t.Fatal("unmounted after failed sync")
			}
		})
	}
}
func TestFreshShutdownFailedMountIsCleanupOnly(t *testing.T) {
	f := &shutdownFake{fakeExt4: &fakeExt4{mountErr: syscall.EIO}}
	var l Ext4ShutdownLease
	err := (ext4Transition{new(sync.Mutex), f}).runRetained("/dev/vdb", "/disk", "data", testUUID, testBytes, true, &l)
	if err == nil || l.lease == nil {
		t.Fatal("failure lost pin")
	}
	if root, err := l.Root(); err == nil {
		root.Close()
		t.Fatal("failure granted root")
	}
	if err := l.Close(); err == nil || f.unmounts != 0 {
		t.Fatal("unproven mount detached")
	}
	f.mounted = false // external positive absence permits releasing this test pin
	_ = l.Close()     // stale root is dropped; the next attempt repins and proves absence
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestFreshShutdownRejectsAliasBeforeUnmount(t *testing.T) {
	f := &shutdownFake{fakeExt4: &fakeExt4{}}
	l := freshShutdown(t, f)
	f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) {
		alias := fakeMounted()
		alias.id, alias.point = 9, "/alias"
		return mountSnapshot{2, []mountRecord{fakeRoot(), fakeMounted(), alias}}, nil
	}
	if err := l.Close(); err == nil || f.unmounts != 0 || f.syncs != 0 {
		t.Fatal("touched aliased device", err)
	}
}
