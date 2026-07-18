//go:build linux

package supervisor

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

var linuxCapabilityNumbers = map[string]int{
	"AUDIT_CONTROL":      unix.CAP_AUDIT_CONTROL,
	"AUDIT_READ":         unix.CAP_AUDIT_READ,
	"AUDIT_WRITE":        unix.CAP_AUDIT_WRITE,
	"BLOCK_SUSPEND":      unix.CAP_BLOCK_SUSPEND,
	"BPF":                unix.CAP_BPF,
	"CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
	"CHOWN":              unix.CAP_CHOWN,
	"DAC_OVERRIDE":       unix.CAP_DAC_OVERRIDE,
	"DAC_READ_SEARCH":    unix.CAP_DAC_READ_SEARCH,
	"FOWNER":             unix.CAP_FOWNER,
	"FSETID":             unix.CAP_FSETID,
	"IPC_LOCK":           unix.CAP_IPC_LOCK,
	"IPC_OWNER":          unix.CAP_IPC_OWNER,
	"KILL":               unix.CAP_KILL,
	"LEASE":              unix.CAP_LEASE,
	"LINUX_IMMUTABLE":    unix.CAP_LINUX_IMMUTABLE,
	"MAC_ADMIN":          unix.CAP_MAC_ADMIN,
	"MAC_OVERRIDE":       unix.CAP_MAC_OVERRIDE,
	"MKNOD":              unix.CAP_MKNOD,
	"NET_ADMIN":          unix.CAP_NET_ADMIN,
	"NET_BIND_SERVICE":   unix.CAP_NET_BIND_SERVICE,
	"NET_BROADCAST":      unix.CAP_NET_BROADCAST,
	"NET_RAW":            unix.CAP_NET_RAW,
	"PERFMON":            unix.CAP_PERFMON,
	"SETFCAP":            unix.CAP_SETFCAP,
	"SETGID":             unix.CAP_SETGID,
	"SETPCAP":            unix.CAP_SETPCAP,
	"SETUID":             unix.CAP_SETUID,
	"SYS_ADMIN":          unix.CAP_SYS_ADMIN,
	"SYS_BOOT":           unix.CAP_SYS_BOOT,
	"SYS_CHROOT":         unix.CAP_SYS_CHROOT,
	"SYS_MODULE":         unix.CAP_SYS_MODULE,
	"SYS_NICE":           unix.CAP_SYS_NICE,
	"SYS_PACCT":          unix.CAP_SYS_PACCT,
	"SYS_PTRACE":         unix.CAP_SYS_PTRACE,
	"SYS_RAWIO":          unix.CAP_SYS_RAWIO,
	"SYS_RESOURCE":       unix.CAP_SYS_RESOURCE,
	"SYS_TIME":           unix.CAP_SYS_TIME,
	"SYS_TTY_CONFIG":     unix.CAP_SYS_TTY_CONFIG,
	"SYSLOG":             unix.CAP_SYSLOG,
	"WAKE_ALARM":         unix.CAP_WAKE_ALARM,
}

var dockerDefaultCapabilities = []string{
	"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
	"NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
}

func capabilityMask(add, drop []string, privileged bool) (uint64, error) {
	all := uint64(1)<<(unix.CAP_LAST_CAP+1) - 1
	if privileged {
		return all, nil
	}
	mask := uint64(0)
	if !containsCapability(drop, "ALL") {
		for _, name := range dockerDefaultCapabilities {
			mask |= uint64(1) << linuxCapabilityNumbers[name]
		}
	}
	for _, raw := range add {
		name := normalizeCapabilityName(raw)
		if name == "ALL" {
			mask = all
			continue
		}
		number, ok := linuxCapabilityNumbers[name]
		if !ok {
			return 0, fmt.Errorf("unknown Linux capability %q", raw)
		}
		mask |= uint64(1) << number
	}
	for _, raw := range drop {
		name := normalizeCapabilityName(raw)
		if name == "ALL" {
			continue
		}
		number, ok := linuxCapabilityNumbers[name]
		if !ok {
			return 0, fmt.Errorf("unknown Linux capability %q", raw)
		}
		mask &^= uint64(1) << number
	}
	return mask, nil
}

func containsCapability(values []string, expected string) bool {
	for _, value := range values {
		if normalizeCapabilityName(value) == expected {
			return true
		}
	}
	return false
}

func normalizeCapabilityName(value string) string {
	return strings.TrimPrefix(strings.ToUpper(value), "CAP_")
}

func applyCapabilityBoundingSet(
	mask uint64,
	prctl func(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) error,
) error {
	for capability := 0; capability <= unix.CAP_LAST_CAP; capability++ {
		if mask&(uint64(1)<<capability) != 0 {
			continue
		}
		if err := prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil {
			return fmt.Errorf("drop capability %d from bounding set: %w", capability, err)
		}
	}
	return nil
}

func applyProcessCapabilities(mask uint64, uid int, capset func(*unix.CapUserHeader, *unix.CapUserData) error) error {
	if uid != 0 {
		return nil
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(mask), Permitted: uint32(mask)},
		{Effective: uint32(mask >> 32), Permitted: uint32(mask >> 32)},
	}
	if err := capset(&header, &data[0]); err != nil {
		return fmt.Errorf("apply process capabilities: %w", err)
	}
	return nil
}
