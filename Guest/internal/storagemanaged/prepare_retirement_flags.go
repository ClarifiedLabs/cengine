package storagemanaged

// F_GETFL reports kernel ABI flags. On both supported 64-bit architectures,
// libc (and x/sys/unix) defines O_LARGEFILE as zero, but Linux adds a nonzero
// architecture-specific bit to real descriptors. Accept only that harmless bit,
// never arbitrary flags or a write access mode. O_PATH pins use a separate mask.
func prepareRetirementFlags(flags int, path bool, arch string) bool {
	var large, directory, nofollow int
	switch arch {
	case "arm64":
		large, directory, nofollow = 0x20000, 0x4000, 0x8000
	case "amd64":
		large, directory, nofollow = 0x8000, 0x10000, 0x20000
	default:
		return false
	}
	const accessMask, nonblock, cloexec, pathFlag = 3, 0x800, 0x80000, 0x200000
	allowed := directory | nofollow | cloexec | large | nonblock
	if path {
		allowed = pathFlag | cloexec
		if flags&pathFlag == 0 {
			return false
		}
	}
	return flags&accessMask == 0 && flags & ^allowed == 0
}
