//go:build linux

package supervisor

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"dev.cengine/guest/internal/protocol"
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

func deviceAccessMask(value string) (uint32, error) {
	var result uint32
	seen := map[rune]bool{}
	for _, permission := range value {
		if seen[permission] {
			return 0, fmt.Errorf("duplicate device permission %q", permission)
		}
		seen[permission] = true
		switch permission {
		case 'r':
			result |= unix.BPF_DEVCG_ACC_READ
		case 'w':
			result |= unix.BPF_DEVCG_ACC_WRITE
		case 'm':
			result |= unix.BPF_DEVCG_ACC_MKNOD
		default:
			return 0, fmt.Errorf("invalid device permission %q", permission)
		}
	}
	if result == 0 {
		return 0, fmt.Errorf("device permissions must not be empty")
	}
	return result, nil
}

func deviceType(mode uint32) (uint32, error) {
	switch mode & unix.S_IFMT {
	case unix.S_IFCHR:
		return unix.BPF_DEVCG_DEV_CHAR, nil
	case unix.S_IFBLK:
		return unix.BPF_DEVCG_DEV_BLOCK, nil
	default:
		return 0, fmt.Errorf("path is not a character or block device")
	}
}

func configuredDeviceRules(
	resources protocol.Resources,
	lstat func(string, *unix.Stat_t) error,
) ([]deviceAccessRule, error) {
	rules := append([]deviceAccessRule(nil), dockerDefaultDeviceRules...)
	for _, device := range resources.Devices {
		if !strings.HasPrefix(device.PathOnHost, "/dev/") ||
			!strings.HasPrefix(device.PathInContainer, "/dev/") {
			return nil, fmt.Errorf("configured devices require normalized /dev paths")
		}
		var status unix.Stat_t
		if err := lstat(device.PathOnHost, &status); err != nil {
			return nil, fmt.Errorf("inspect configured device %s: %w", device.PathOnHost, err)
		}
		kind, err := deviceType(status.Mode)
		if err != nil {
			return nil, fmt.Errorf("configured device %s %w", device.PathOnHost, err)
		}
		access, err := deviceAccessMask(device.CgroupPermissions)
		if err != nil {
			return nil, fmt.Errorf("configured device %s: %w", device.PathOnHost, err)
		}
		rules = append(rules, deviceAccessRule{
			deviceType: kind,
			major:      deviceNumber(uint32(unix.Major(uint64(status.Rdev)))),
			minor:      deviceNumber(uint32(unix.Minor(uint64(status.Rdev)))),
			access:     access,
		})
	}
	for _, configured := range resources.DeviceCgroupRules {
		access, err := deviceAccessMask(configured.Access)
		if err != nil {
			return nil, fmt.Errorf("custom device rule: %w", err)
		}
		var kinds []uint32
		switch configured.DeviceType {
		case "a":
			kinds = []uint32{unix.BPF_DEVCG_DEV_CHAR, unix.BPF_DEVCG_DEV_BLOCK}
		case "c":
			kinds = []uint32{unix.BPF_DEVCG_DEV_CHAR}
		case "b":
			kinds = []uint32{unix.BPF_DEVCG_DEV_BLOCK}
		default:
			return nil, fmt.Errorf("invalid custom device rule type %q", configured.DeviceType)
		}
		for _, kind := range kinds {
			rules = append(rules, deviceAccessRule{
				deviceType: kind, major: configured.Major, minor: configured.Minor, access: access,
			})
		}
	}
	return rules, nil
}

func configuredDeviceRulesForHost(resources protocol.Resources) ([]deviceAccessRule, error) {
	return configuredDeviceRules(resources, unix.Lstat)
}

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

func loadDevicePolicy(rules []deviceAccessRule) (int, error) {
	instructions := bpfDeviceProgram(rules)
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
			return -1, fmt.Errorf("load cgroup device policy: %w: %s", loadErr, log)
		}
		return -1, fmt.Errorf("load cgroup device policy: %w", loadErr)
	}
	return int(programFD), nil
}

func attachDevicePolicy(cgroupPath string, rules []deviceAccessRule, replacedFD int) (int, error) {
	programFD, err := loadDevicePolicy(rules)
	if err != nil {
		return -1, err
	}
	attached := false
	defer func() {
		if !attached {
			_ = unix.Close(programFD)
		}
	}()

	cgroupFD, err := unix.Open(cgroupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open workload cgroup for device policy: %w", err)
	}
	defer unix.Close(cgroupFD)
	attach := bpfProgramAttachAttribute{
		targetFD: uint32(cgroupFD), programFD: uint32(programFD),
		attachType:  unix.BPF_CGROUP_DEVICE,
		attachFlags: devicePolicyAttachFlags(replacedFD),
	}
	if replacedFD >= 0 {
		attach.replaceProgramFD = uint32(replacedFD)
	}
	_, _, attachErr := unix.Syscall(
		unix.SYS_BPF, unix.BPF_PROG_ATTACH, uintptr(unsafe.Pointer(&attach)), unsafe.Sizeof(attach),
	)
	if attachErr != 0 {
		return -1, fmt.Errorf("attach cgroup device policy: %w", attachErr)
	}
	attached = true
	return programFD, nil
}

func devicePolicyAttachFlags(replacedFD int) uint32 {
	flags := uint32(unix.BPF_F_ALLOW_MULTI)
	if replacedFD >= 0 {
		flags |= unix.BPF_F_REPLACE
	}
	return flags
}
