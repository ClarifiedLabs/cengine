//go:build darwin

package storageauthority

import (
	"os"

	"golang.org/x/sys/unix"
)

// Native prototype tests only; production Linux additionally enforces NO_XDEV.
func volumeDirectory(dir *os.File, name string) (*os.File, error) {
	return child(dir, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
}
