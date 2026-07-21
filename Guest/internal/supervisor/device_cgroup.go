//go:build linux

package supervisor

import (
	"bytes"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux cgroup v2 delegates device access control to BPF_CGROUP_DEVICE
// programs. Docker's default policy permits device-node creation while
// limiting reads and writes to the standard devices exposed in /dev.
type deviceAccessRule struct {
	deviceType uint32
	major      *uint32
	minor      *uint32
	access     uint32
}

func deviceNumber(value uint32) *uint32 { return &value }

var dockerDefaultDeviceRules = []deviceAccessRule{
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, access: unix.BPF_DEVCG_ACC_MKNOD},
	{deviceType: unix.BPF_DEVCG_DEV_BLOCK, access: unix.BPF_DEVCG_ACC_MKNOD},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(1), minor: deviceNumber(3), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(1), minor: deviceNumber(5), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(1), minor: deviceNumber(7), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(1), minor: deviceNumber(8), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(1), minor: deviceNumber(9), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(5), minor: deviceNumber(0), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(5), minor: deviceNumber(1), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(5), minor: deviceNumber(2), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(10), minor: deviceNumber(200), access: 7},
	{deviceType: unix.BPF_DEVCG_DEV_CHAR, major: deviceNumber(136), access: 7},
}

func deviceAccessAllowed(rules []deviceAccessRule, deviceType, major, minor, access uint32) bool {
	for _, rule := range rules {
		if rule.deviceType != deviceType || rule.major != nil && *rule.major != major ||
			rule.minor != nil && *rule.minor != minor {
			continue
		}
		if access & ^rule.access == 0 {
			return true
		}
	}
	return false
}

type bpfInstruction struct {
	code   uint8
	regs   uint8
	offset int16
	value  int32
}

func bpfRegisters(destination, source uint8) uint8 { return destination | source<<4 }

func bpfDeviceProgram(rules []deviceAccessRule) []bpfInstruction {
	instructions := []bpfInstruction{
		// struct bpf_cgroup_dev_ctx.access_type: low 16 bits are the device
		// type and high 16 bits are the requested access mask.
		{code: unix.BPF_LDX | unix.BPF_MEM | unix.BPF_W, regs: bpfRegisters(2, 1), offset: 0},
		{code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_X, regs: bpfRegisters(3, 2)},
		{code: unix.BPF_ALU64 | unix.BPF_RSH | unix.BPF_K, regs: bpfRegisters(3, 0), value: 16},
		{code: unix.BPF_ALU64 | unix.BPF_AND | unix.BPF_K, regs: bpfRegisters(2, 0), value: 0xffff},
		{code: unix.BPF_LDX | unix.BPF_MEM | unix.BPF_W, regs: bpfRegisters(4, 1), offset: 4},
		{code: unix.BPF_LDX | unix.BPF_MEM | unix.BPF_W, regs: bpfRegisters(5, 1), offset: 8},
	}
	for _, rule := range rules {
		start := len(instructions)
		instructions = append(instructions, bpfInstruction{
			code: unix.BPF_JMP | unix.BPF_JNE | unix.BPF_K,
			regs: bpfRegisters(2, 0), value: int32(rule.deviceType),
		})
		if rule.major != nil {
			instructions = append(instructions, bpfInstruction{
				code: unix.BPF_JMP | unix.BPF_JNE | unix.BPF_K,
				regs: bpfRegisters(4, 0), value: int32(*rule.major),
			})
		}
		if rule.minor != nil {
			instructions = append(instructions, bpfInstruction{
				code: unix.BPF_JMP | unix.BPF_JNE | unix.BPF_K,
				regs: bpfRegisters(5, 0), value: int32(*rule.minor),
			})
		}
		instructions = append(instructions,
			bpfInstruction{
				code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_X,
				regs: bpfRegisters(0, 3),
			},
			bpfInstruction{
				code: unix.BPF_ALU64 | unix.BPF_AND | unix.BPF_K,
				regs: bpfRegisters(0, 0), value: int32(^rule.access),
			},
			bpfInstruction{
				code: unix.BPF_JMP | unix.BPF_JNE | unix.BPF_K,
				regs: bpfRegisters(0, 0), value: 0,
			},
			bpfInstruction{
				code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K,
				regs: bpfRegisters(0, 0), value: 1,
			},
			bpfInstruction{code: unix.BPF_JMP | unix.BPF_EXIT},
		)
		end := len(instructions)
		for index := start; index < end; index++ {
			if instructions[index].code == unix.BPF_JMP|unix.BPF_JNE|unix.BPF_K {
				instructions[index].offset = int16(end - index - 1)
			}
		}
	}
	return append(instructions,
		bpfInstruction{
			code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K,
			regs: bpfRegisters(0, 0), value: 0,
		},
		bpfInstruction{code: unix.BPF_JMP | unix.BPF_EXIT},
	)
}

type bpfProgramLoadAttribute struct {
	programType        uint32
	instructionCount   uint32
	instructions       uint64
	license            uint64
	logLevel           uint32
	logSize            uint32
	logBuffer          uint64
	kernelVersion      uint32
	programFlags       uint32
	programName        [16]byte
	programIfIndex     uint32
	expectedAttachType uint32
}

type bpfProgramAttachAttribute struct {
	targetFD         uint32
	programFD        uint32
	attachType       uint32
	attachFlags      uint32
	replaceProgramFD uint32
	relativeFD       uint32
	expectedRevision uint32
}

const bpfProgramLoadAttempts = 8

func retryBPFProgramLoad(load func() (uintptr, unix.Errno)) (uintptr, unix.Errno) {
	var programFD uintptr
	var loadErr unix.Errno
	for attempt := 0; attempt < bpfProgramLoadAttempts; attempt++ {
		programFD, loadErr = load()
		if loadErr != unix.EAGAIN {
			return programFD, loadErr
		}
	}
	return programFD, loadErr
}

func attachDefaultDevicePolicy(cgroupPath string) error {
	instructions := bpfDeviceProgram(dockerDefaultDeviceRules)
	license := []byte("GPL\x00")
	logBuffer := make([]byte, 64*1024)
	load := bpfProgramLoadAttribute{
		programType:        unix.BPF_PROG_TYPE_CGROUP_DEVICE,
		instructionCount:   uint32(len(instructions)),
		instructions:       uint64(uintptr(unsafe.Pointer(&instructions[0]))),
		license:            uint64(uintptr(unsafe.Pointer(&license[0]))),
		logLevel:           1,
		logSize:            uint32(len(logBuffer)),
		logBuffer:          uint64(uintptr(unsafe.Pointer(&logBuffer[0]))),
		expectedAttachType: unix.BPF_CGROUP_DEVICE,
	}
	programFD, loadErr := retryBPFProgramLoad(func() (uintptr, unix.Errno) {
		clear(logBuffer)
		fd, _, errno := unix.Syscall(
			unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&load)), unsafe.Sizeof(load),
		)
		return fd, errno
	})
	runtime.KeepAlive(instructions)
	runtime.KeepAlive(license)
	runtime.KeepAlive(logBuffer)
	if loadErr != 0 {
		log := string(bytes.TrimRight(logBuffer, "\x00"))
		if log != "" {
			return fmt.Errorf("load cgroup device policy: %w: %s", loadErr, log)
		}
		return fmt.Errorf("load cgroup device policy: %w", loadErr)
	}
	defer unix.Close(int(programFD))

	cgroupFD, err := unix.Open(cgroupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open workload cgroup for device policy: %w", err)
	}
	defer unix.Close(cgroupFD)
	attach := bpfProgramAttachAttribute{
		targetFD: uint32(cgroupFD), programFD: uint32(programFD),
		attachType: unix.BPF_CGROUP_DEVICE,
	}
	_, _, attachErr := unix.Syscall(
		unix.SYS_BPF, unix.BPF_PROG_ATTACH, uintptr(unsafe.Pointer(&attach)), unsafe.Sizeof(attach),
	)
	if attachErr != 0 {
		return fmt.Errorf("attach cgroup device policy: %w", attachErr)
	}
	return nil
}
