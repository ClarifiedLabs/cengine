//go:build linux

package supervisor

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestCapabilityMaskAppliesDockerDefaultsAddsAndDrops(t *testing.T) {
	mask, err := capabilityMask([]string{"CAP_NET_ADMIN"}, []string{"CHOWN", "NET_RAW"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if mask&(uint64(1)<<unix.CAP_NET_ADMIN) == 0 {
		t.Fatal("CAP_NET_ADMIN was not added")
	}
	for _, capability := range []int{unix.CAP_CHOWN, unix.CAP_NET_RAW} {
		if mask&(uint64(1)<<capability) != 0 {
			t.Fatalf("capability %d was not dropped", capability)
		}
	}
	if mask&(uint64(1)<<unix.CAP_SYS_ADMIN) != 0 {
		t.Fatal("CAP_SYS_ADMIN unexpectedly present in Docker defaults")
	}
}

func TestCapabilityMaskDropsCapabilitiesFromAll(t *testing.T) {
	mask, err := capabilityMask([]string{"ALL"}, []string{"MKNOD"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if mask&(uint64(1)<<unix.CAP_MKNOD) != 0 {
		t.Fatal("CAP_MKNOD was not dropped from ALL")
	}
	if mask&(uint64(1)<<unix.CAP_SYS_ADMIN) == 0 {
		t.Fatal("CAP_SYS_ADMIN was not added by ALL")
	}
}

func TestCapabilityMaskSupportsAllAndRejectsUnknownValues(t *testing.T) {
	mask, err := capabilityMask([]string{"ALL"}, []string{"ALL"}, false)
	if err != nil {
		t.Fatal(err)
	}
	all := uint64(1)<<(unix.CAP_LAST_CAP+1) - 1
	if mask != all {
		t.Fatalf("ALL mask = %#x, want %#x", mask, all)
	}
	if _, err := capabilityMask([]string{"CAP_SIDEWAYS"}, nil, false); err == nil {
		t.Fatal("unknown capability unexpectedly accepted")
	}
}

func TestApplyProcessCapabilitiesSplitsTheLinuxV3Mask(t *testing.T) {
	mask := uint64(1)<<unix.CAP_CHOWN | uint64(1)<<unix.CAP_CHECKPOINT_RESTORE
	var captured [2]unix.CapUserData
	err := applyProcessCapabilities(mask, 0, func(header *unix.CapUserHeader, data *unix.CapUserData) error {
		if header.Version != unix.LINUX_CAPABILITY_VERSION_3 {
			t.Fatalf("capability version = %#x", header.Version)
		}
		copy(captured[:], unsafe.Slice(data, 2))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured[0].Effective != 1 || captured[0].Permitted != 1 {
		t.Fatalf("lower capability word = %#v", captured[0])
	}
	wantUpper := uint32(1 << (unix.CAP_CHECKPOINT_RESTORE - 32))
	if captured[1].Effective != wantUpper || captured[1].Permitted != wantUpper {
		t.Fatalf("upper capability word = %#v", captured[1])
	}
}
