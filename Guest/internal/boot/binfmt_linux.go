//go:build linux

package boot

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const binfmtMiscDirectory = "/proc/sys/fs/binfmt_misc"

// MountBinfmtMisc mounts the kernel binfmt_misc filesystem so the boot
// sequence can register binary format handlers. An already-mounted or
// unavailable filesystem is tolerated because registration simply has no
// effect without it.
func MountBinfmtMisc() error {
	if err := unix.Mount("binfmt_misc", binfmtMiscDirectory, "binfmt_misc", 0, ""); err != nil &&
		!errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("mount binfmt_misc: %w", err)
	}
	return nil
}

// RosettaRegistrationEntry is the binfmt_misc handler definition for x86-64
// ELF binaries interpreted by Rosetta for Linux. The magic matches EM_X86_64
// executables and shared objects (ET_EXEC/ET_DYN through the e_type mask);
// i386 is intentionally not registered. The magic and mask must be written as
// \xHH escape sequences, never raw bytes: the binfmt_misc register parser
// treats the entry as a C string and unescapes \xHH itself, so raw NUL bytes
// silently truncate the magic and mask at the first zero byte, producing a
// handler that matches every 64-bit little-endian ELF binary. The OCF flags
// are required: F pins the interpreter descriptor at registration because
// container root filesystems are chrooted and cannot see the virtiofs mount,
// O passes the executable descriptor instead of a path, and C takes
// credentials from the executed program.
func RosettaRegistrationEntry(interpreter string) string {
	return ":rosetta:M::" +
		`\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00` +
		`:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:` +
		interpreter + ":OCF"
}

// RegisterRosetta installs the x86-64 binfmt_misc handler. The interpreter
// must live on a mount visible to PID 1, such as the rosetta virtiofs share.
func RegisterRosetta(interpreter string) error {
	return registerBinfmtHandler(
		binfmtMiscDirectory+"/register", RosettaRegistrationEntry(interpreter),
	)
}

func registerBinfmtHandler(path, entry string) error {
	if err := os.WriteFile(path, []byte(entry), 0); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
