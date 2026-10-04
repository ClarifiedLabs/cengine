package disk

import (
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
)

type fakeInheritedMount struct {
	*fakeExt4
	metadataPins, targetChecks int
	metadataErr, verifyErr     error
}

func (f *fakeInheritedMount) pinDeviceMetadata(string) (*pinnedDevice, error) {
	f.metadataPins++
	if f.metadataErr != nil {
		return nil, f.metadataErr
	}
	file, err := os.Open(os.DevNull)
	return &pinnedDevice{file, 8, 16}, err
}
func (f *fakeInheritedMount) verifyTargetDevice(*pinnedTarget, *pinnedDevice) error {
	f.targetChecks++
	return f.verifyErr
}
func verifyInheritedFake(f *fakeInheritedMount) error {
	return verifyInheritedMountedExt4(new(sync.Mutex), f, "/dev/vdb", "/disk")
}
func noInheritedMutations(t *testing.T, f *fakeInheritedMount) {
	t.Helper()
	if f.pins != 0 || f.formats != 0 || f.mounts != 0 || f.capacities != 0 || f.uuids != 0 || f.syncs != 0 || f.leafChecks != 0 {
		t.Fatalf("inherited verification opened raw data or mutated state: %+v", f.fakeExt4)
	}
}

func TestInheritedMountWorksWithRawDeviceAccessDenied(t *testing.T) {
	for _, mode := range []uint32{0, 0700, 0777} {
		f := &fakeInheritedMount{fakeExt4: &fakeExt4{mounted: true, pinErr: syscall.EPERM, leafUID: 1000, leafMode: mode}}
		// This is the regression: ordinary data-access pinning is forbidden once
		// Supervisor.Start places stage 2 in the unprivileged device cgroup.
		if err := mountFake(f.fakeExt4); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("expected denied raw block open: %v", err)
		}
		f.pins = 0
		if err := verifyInheritedFake(f); err != nil {
			t.Fatalf("metadata-only inherited verification mode=%o: %v", mode, err)
		}
		if f.metadataPins != 1 || f.targetChecks != 2 || f.snapshots != 2 {
			t.Fatalf("missing pinned identity verification: %+v", f)
		}
		noInheritedMutations(t, f)
	}
}

func TestInheritedMountRejectsEveryUnsafeVisibleMount(t *testing.T) {
	for _, change := range []func(*mountRecord){
		func(r *mountRecord) { r.fs = "xfs" },
		func(r *mountRecord) { r.major++ },
		func(r *mountRecord) { r.minor++ },
		func(r *mountRecord) { r.root = "/subtree" },
		func(r *mountRecord) { r.options = "rw,nodev" },
		func(r *mountRecord) { r.options = "rw,nosuid" },
		func(r *mountRecord) { r.superOptions = "rw,errors=continue" },
	} {
		for _, changedAt := range []int{1, 2} {
			f := &fakeInheritedMount{fakeExt4: &fakeExt4{}}
			f.snapshotHook = func(state *fakeExt4, same bool) (mountSnapshot, error) {
				if !same {
					t.Fatal("did not require held target identity")
				}
				r := fakeMounted()
				if state.snapshots == changedAt {
					change(&r)
				}
				return mountSnapshot{2, []mountRecord{fakeRoot(), r}}, nil
			}
			if err := verifyInheritedFake(f); err == nil {
				t.Fatal("accepted unsafe or replaced mount")
			}
			noInheritedMutations(t, f)
		}
	}
	for _, snapshot := range []mountSnapshot{
		{1, []mountRecord{fakeRoot()}},
		{99, []mountRecord{fakeRoot(), fakeMounted()}},
		{2, []mountRecord{fakeRoot(), fakeMounted(), fakeMounted()}},
		{2, []mountRecord{fakeRoot(), fakeMounted(), {id: 3, parent: 2, point: "/disk/child"}}},
		{2, []mountRecord{fakeRoot(), fakeMounted(), {id: 3, parent: 1, point: "/", root: "/", fs: "tmpfs"}}},
	} {
		f := &fakeInheritedMount{fakeExt4: &fakeExt4{snapshotHook: func(*fakeExt4, bool) (mountSnapshot, error) { return snapshot, nil }}}
		if err := verifyInheritedFake(f); err == nil {
			t.Fatalf("accepted hidden, absent, stacked or nested mount: %+v", snapshot)
		}
		noInheritedMutations(t, f)
	}
}

func TestInheritedMountMetadataFailuresStayClosed(t *testing.T) {
	for _, fail := range []func(*fakeInheritedMount){
		func(f *fakeInheritedMount) { f.metadataErr = syscall.EACCES },
		func(f *fakeInheritedMount) { f.targetErr = syscall.EACCES },
		func(f *fakeInheritedMount) { f.verifyErr = syscall.EIO },
		func(f *fakeInheritedMount) {
			f.snapshotHook = func(*fakeExt4, bool) (mountSnapshot, error) { return mountSnapshot{}, syscall.EIO }
		},
	} {
		f := &fakeInheritedMount{fakeExt4: &fakeExt4{mounted: true}}
		fail(f)
		if err := verifyInheritedFake(f); err == nil {
			t.Fatal("accepted failed metadata verification")
		}
		noInheritedMutations(t, f)
	}
	for _, path := range []string{"relative", "/", "/dev/../dev/vda", "/dev/vda\x00"} {
		f := &fakeInheritedMount{fakeExt4: &fakeExt4{mounted: true}}
		if err := verifyInheritedMountedExt4(new(sync.Mutex), f, path, "/disk"); err == nil || f.metadataPins != 0 {
			t.Fatalf("accepted noncanonical device %q", path)
		}
		if err := verifyInheritedMountedExt4(new(sync.Mutex), f, "/dev/vda", path); err == nil || f.metadataPins != 0 {
			t.Fatalf("accepted noncanonical destination %q", path)
		}
	}
}
