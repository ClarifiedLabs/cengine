package storagefuse

import w "dev.cengine/guest/internal/storagewire"

// Linux UAPI values: deliberately independent of the machine running unit tests.
// On 64-bit Linux O_LARGEFILE is zero in libc but nonzero in the kernel ABI.
func openFlags(in uint32, arch string) (uint32, bool) {
	// Linux do_open_execat adds __FMODE_EXEC to file.f_flags; FUSE forwards
	// it on OPEN and READ. It is kernel execution intent, not an O_* flag
	// for the backing open. Strip only this known bit, not unknown flags or
	// the separate fuse_open_in.open_flags word.
	in &^= 0x20
	direct, large, directory, nofollow := uint32(0x4000), uint32(0x8000), uint32(0x10000), uint32(0x20000)
	switch arch {
	case "amd64":
	case "arm64":
		direct, large, directory, nofollow = 0x10000, 0x20000, 0x4000, 0x8000
	default:
		return 0, false
	}
	const common uint32 = 3 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x2000 | 0x40000 | 0x80000 | 0x100000
	if in & ^(common|direct|large|directory|nofollow) != 0 || in&3 == 3 {
		return 0, false
	}
	out := in & common
	for _, p := range [][2]uint32{{direct, w.OpenDirect}, {large, w.OpenLargeFile}, {directory, w.OpenDirectory}, {nofollow, w.OpenNoFollow}} {
		if in&p[0] != 0 {
			out |= p[1]
		}
	}
	return out, true
}
