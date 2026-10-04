package storageboot

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

const authorityName = ".cengine-storage-authority"

func childDirectory(root *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "storage-directory"), nil
}

// Initialization is never migration. Only empty pristine-layout directories are
// permitted, and no content is removed or rewritten.
func freshRoot(root *os.File) error {
	scan, err := childDirectory(root, ".")
	if err != nil {
		return err
	}
	defer scan.Close()
	// A pristine layout has at most these two directories. Bound inspection
	// even for a hostile legacy root containing millions of directory entries.
	entries, err := scan.ReadDir(3)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > 2 {
		return errors.New("configuration")
	}
	for _, entry := range entries {
		if entry.Name() != "lost+found" && entry.Name() != "volumes" {
			return errors.New("configuration")
		}
		dir, err := childDirectory(root, entry.Name())
		if err != nil {
			return err
		}
		_, err = dir.Readdirnames(1)
		dir.Close()
		if err != io.EOF {
			return errors.New("configuration")
		}
	}
	return nil
}
