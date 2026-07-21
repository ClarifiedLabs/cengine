//go:build linux

package supervisor

import (
	"testing"
	"unsafe"

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
