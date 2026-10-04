//go:build darwin

package workloadstorage

import "golang.org/x/sys/unix"

// Host fixture only; not Linux mount/atime attestation.
func retainedReadOpen(root int) (int, error) {
	return unix.Openat(root, retainedReadName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}
