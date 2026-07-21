//go:build linux

package supervisor

import (
	"testing"
	"unsafe"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestDockerDefaultDevicePolicyAllowsStandardDevicesAndDeniesVMDisks(t *testing.T) {
	all := uint32(unix.BPF_DEVCG_ACC_MKNOD | unix.BPF_DEVCG_ACC_READ | unix.BPF_DEVCG_ACC_WRITE)
	for _, device := range []struct {
		major uint32
		minor uint32
	}{
		{major: 1, minor: 3},
		{major: 1, minor: 5},
		{major: 1, minor: 7},
		{major: 1, minor: 8},
		{major: 1, minor: 9},
		{major: 5, minor: 0},
		{major: 5, minor: 1},
		{major: 5, minor: 2},
		{major: 10, minor: 200},
		{major: 136, minor: 42},
	} {
		if !deviceAccessAllowed(
			dockerDefaultDeviceRules, unix.BPF_DEVCG_DEV_CHAR,
			device.major, device.minor, all,
		) {
			t.Fatalf("standard character device %d:%d was denied", device.major, device.minor)
		}
	}

	if !deviceAccessAllowed(
		dockerDefaultDeviceRules, unix.BPF_DEVCG_DEV_BLOCK, 254, 0,
		unix.BPF_DEVCG_ACC_MKNOD,
	) {
		t.Fatal("block-device node creation was denied")
	}
	if deviceAccessAllowed(
		dockerDefaultDeviceRules, unix.BPF_DEVCG_DEV_BLOCK, 254, 0,
		unix.BPF_DEVCG_ACC_READ,
	) {
		t.Fatal("VM root disk read was allowed")
	}
	if deviceAccessAllowed(
		dockerDefaultDeviceRules, unix.BPF_DEVCG_DEV_BLOCK, 254, 1,
		unix.BPF_DEVCG_ACC_WRITE,
	) {
		t.Fatal("VM volume disk write was allowed")
	}
	if deviceAccessAllowed(
		dockerDefaultDeviceRules, unix.BPF_DEVCG_DEV_CHAR, 10, 229,
		unix.BPF_DEVCG_ACC_READ,
	) {
		t.Fatal("unlisted character device read was allowed")
	}
}

func TestConfiguredDeviceRulesAddMappedAndWildcardAccess(t *testing.T) {
	major := uint32(10)
	resources := protocol.Resources{
		Devices: []protocol.DeviceMapping{{
			PathOnHost: "/dev/data", PathInContainer: "/dev/container-data",
			CgroupPermissions: "rw",
		}},
		DeviceCgroupRules: []protocol.DeviceCgroupRule{{
			DeviceType: "c", Major: &major, Access: "r",
		}},
	}
	rules, err := configuredDeviceRules(resources, func(path string, status *unix.Stat_t) error {
		if path != "/dev/data" {
			t.Fatalf("lstat path = %q", path)
		}
		status.Mode = unix.S_IFBLK | 0660
		status.Rdev = uint64(unix.Mkdev(254, 7))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	readWrite := uint32(unix.BPF_DEVCG_ACC_READ | unix.BPF_DEVCG_ACC_WRITE)
	if !deviceAccessAllowed(rules, unix.BPF_DEVCG_DEV_BLOCK, 254, 7, readWrite) {
		t.Fatal("mapped block-device read/write access was denied")
	}
	if deviceAccessAllowed(rules, unix.BPF_DEVCG_DEV_BLOCK, 254, 7, unix.BPF_DEVCG_ACC_MKNOD|readWrite) {
		t.Fatal("mapped block-device mknod access exceeded its configured permissions")
	}
	if !deviceAccessAllowed(rules, unix.BPF_DEVCG_DEV_CHAR, 10, 229, unix.BPF_DEVCG_ACC_READ) {
		t.Fatal("wildcard-minor character-device rule was denied")
	}
	if deviceAccessAllowed(rules, unix.BPF_DEVCG_DEV_CHAR, 11, 229, unix.BPF_DEVCG_ACC_READ) {
		t.Fatal("wildcard-minor character-device rule matched the wrong major")
	}
}

func TestConfiguredDeviceRulesRejectNonDevicesAndInvalidPermissions(t *testing.T) {
	for name, resources := range map[string]protocol.Resources{
		"regular source": {Devices: []protocol.DeviceMapping{{
			PathOnHost: "/dev/data", PathInContainer: "/dev/container-data",
			CgroupPermissions: "rw",
		}}},
		"duplicate permission": {DeviceCgroupRules: []protocol.DeviceCgroupRule{{
			DeviceType: "c", Access: "rr",
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configuredDeviceRules(resources, func(_ string, status *unix.Stat_t) error {
				status.Mode = unix.S_IFREG
				return nil
			})
			if err == nil {
				t.Fatal("invalid device configuration was accepted")
			}
		})
	}
}

func TestDeviceBPFProgramHasValidForwardRuleJumps(t *testing.T) {
	instructions := bpfDeviceProgram(dockerDefaultDeviceRules)
	if unsafe.Sizeof(bpfInstruction{}) != 8 {
		t.Fatalf("BPF instruction size = %d, want 8", unsafe.Sizeof(bpfInstruction{}))
	}
	if len(instructions) < 2 || instructions[len(instructions)-1].code != unix.BPF_JMP|unix.BPF_EXIT {
		t.Fatal("device BPF program does not end with exit")
	}
	for index, instruction := range instructions {
		if instruction.code != unix.BPF_JMP|unix.BPF_JNE|unix.BPF_K {
			continue
		}
		target := index + 1 + int(instruction.offset)
		if instruction.offset < 0 || target >= len(instructions) {
			t.Fatalf("instruction %d jumps outside the program to %d", index, target)
		}
	}
	if unsafe.Sizeof(bpfProgramLoadAttribute{}) != 72 {
		t.Fatalf("BPF program-load attribute size = %d, want 72", unsafe.Sizeof(bpfProgramLoadAttribute{}))
	}
	if unsafe.Sizeof(bpfProgramAttachAttribute{}) != 28 {
		t.Fatalf("BPF program-attach attribute size = %d, want 28", unsafe.Sizeof(bpfProgramAttachAttribute{}))
	}
}

func TestDevicePolicyReplacementKeepsMultiAttachMode(t *testing.T) {
	if flags := devicePolicyAttachFlags(-1); flags != unix.BPF_F_ALLOW_MULTI {
		t.Fatalf("initial device-policy attach flags = %#x", flags)
	}
	want := uint32(unix.BPF_F_ALLOW_MULTI | unix.BPF_F_REPLACE)
	if flags := devicePolicyAttachFlags(42); flags != want {
		t.Fatalf("replacement device-policy attach flags = %#x, want %#x", flags, want)
	}
}

func TestBPFProgramLoadRetriesTransientVerifierInterruption(t *testing.T) {
	attempts := 0
	programFD, loadErr := retryBPFProgramLoad(func() (uintptr, unix.Errno) {
		attempts++
		if attempts < 3 {
			return 0, unix.EAGAIN
		}
		return 42, 0
	})
	if loadErr != 0 {
		t.Fatalf("BPF program load returned %v", loadErr)
	}
	if programFD != 42 {
		t.Fatalf("BPF program fd = %d, want 42", programFD)
	}
	if attempts != 3 {
		t.Fatalf("BPF program load attempts = %d, want 3", attempts)
	}
}

func TestBPFProgramLoadBoundsPersistentVerifierInterruption(t *testing.T) {
	attempts := 0
	_, loadErr := retryBPFProgramLoad(func() (uintptr, unix.Errno) {
		attempts++
		return 0, unix.EAGAIN
	})
	if loadErr != unix.EAGAIN {
		t.Fatalf("BPF program load error = %v, want EAGAIN", loadErr)
	}
	if attempts != bpfProgramLoadAttempts {
		t.Fatalf("BPF program load attempts = %d, want %d", attempts, bpfProgramLoadAttempts)
	}
}
