//go:build darwin

package workloadstorage

import (
	"golang.org/x/sys/unix"
	"os"
)

// Host-test seam only. This is NOT the Linux mount-ID/FUSE attestation.
func retainedFDOpen(root int) (int, error) {
	return unix.Openat(root, retainedFDName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}
func retainedStat(file *os.File, directory, writable bool) (retainedFDIdentity, error) {
	st, err := retainedStatBasic(file, directory, writable)
	if err != nil {
		return retainedFDIdentity{}, err
	}
	return retainedFDIdentity{device: uint64(st.Dev), inode: st.Ino}, nil
}
