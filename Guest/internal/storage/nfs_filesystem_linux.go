//go:build linux

package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-billy/v5"
	"golang.org/x/sys/unix"
)

// All data and namespace operations use os.Root's descriptor-relative traversal.
// Never reintroduce host-path check-then-use operations here.
func (f *volumeNFSFilesystem) confinedName(name string) string {
	name = strings.TrimPrefix(name, f.root+string(filepath.Separator))
	name = strings.TrimPrefix(name, string(filepath.Separator))
	if name == "" {
		return "."
	}
	return name
}

type nfsOSFile struct {
	*os.File
	name string
}

func (f *nfsOSFile) Name() string  { return f.name }
func (f *nfsOSFile) Lock() error   { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }
func (f *nfsOSFile) Unlock() error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func (f *volumeNFSFilesystem) OpenFile(name string, flags int, mode os.FileMode) (billy.File, error) {
	if f.rootErr != nil {
		return nil, f.rootErr
	}
	if flags&os.O_CREATE != 0 {
		// Exclusive creation can only produce a new regular file. If it races
		// another creator, inspect the existing inode without opening a device.
		file, err := f.confined.OpenFile(f.confinedName(name), flags|os.O_EXCL|unix.O_NONBLOCK, mode)
		if err == nil {
			return &nfsOSFile{file, name}, nil
		}
		if !errors.Is(err, os.ErrExist) || flags&os.O_EXCL != 0 {
			return nil, err
		}
	}
	fd, err := f.pin(name)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, unix.EPERM
	}
	// Reopen only this verified inode; re-resolving name would allow a device
	// substitution between the type check and open (even with O_NONBLOCK).
	file, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), flags & ^(os.O_CREATE|os.O_EXCL) | unix.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	return &nfsOSFile{file, name}, nil
}
func (f *volumeNFSFilesystem) Open(name string) (billy.File, error) {
	return f.OpenFile(name, os.O_RDONLY, 0)
}
func (f *volumeNFSFilesystem) Create(name string) (billy.File, error) {
	return f.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}
func (f *volumeNFSFilesystem) Stat(name string) (os.FileInfo, error) {
	if f.rootErr != nil {
		return nil, f.rootErr
	}
	return f.confined.Stat(f.confinedName(name))
}
func (f *volumeNFSFilesystem) Lstat(name string) (os.FileInfo, error) {
	if f.rootErr != nil {
		return nil, f.rootErr
	}
	return f.confined.Lstat(f.confinedName(name))
}
func (f *volumeNFSFilesystem) Readlink(name string) (string, error) {
	if f.rootErr != nil {
		return "", f.rootErr
	}
	return f.confined.Readlink(f.confinedName(name))
}
func (f *volumeNFSFilesystem) Symlink(target, name string) error {
	if f.rootErr != nil {
		return f.rootErr
	}
	return f.confined.Symlink(target, f.confinedName(name))
}
func (f *volumeNFSFilesystem) Remove(name string) error {
	if f.rootErr != nil {
		return f.rootErr
	}
	return f.confined.Remove(f.confinedName(name))
}
func (f *volumeNFSFilesystem) MkdirAll(name string, mode os.FileMode) error {
	// NFS MKDIR creates exactly one directory, never missing ancestors.
	if f.rootErr != nil {
		return f.rootErr
	}
	return f.confined.Mkdir(f.confinedName(name), mode)
}
func (f *volumeNFSFilesystem) ReadDir(name string) ([]os.FileInfo, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.(*nfsOSFile).Readdir(-1)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, err
}
func (f *volumeNFSFilesystem) Chroot(string) (billy.Filesystem, error) {
	return nil, billy.ErrNotSupported
}
func (f *volumeNFSFilesystem) TempFile(string, string) (billy.File, error) {
	return nil, billy.ErrNotSupported
}

// pin uses O_PATH, which does not require read permission on the object. The
// kernel still checks search permission on every ancestor under this identity.
func (f *volumeNFSFilesystem) pin(name string) (int, error) {
	return f.pinFlags(name, 0)
}

func (f *volumeNFSFilesystem) pinFlags(name string, flags uint64) (int, error) {
	if f.rootErr != nil {
		return -1, f.rootErr
	}
	return unix.Openat2(int(f.rootFile.Fd()), f.confinedName(name), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | flags,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	})
}
func (f *volumeNFSFilesystem) Access(name string, requested uint32) (uint32, error) {
	// NFS handles name the leaf inode, not a symlink's target. In particular,
	// sticky-directory DELETE checks must use the link owner's UID.
	fd, err := f.pinFlags(name, unix.O_NOFOLLOW)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, err
	}
	allowed := func(mode uint32) bool { return unix.Faccessat(fd, "", mode, unix.AT_EMPTY_PATH|unix.AT_EACCESS) == nil }
	var mask uint32
	if allowed(unix.R_OK) {
		mask |= 1
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		if allowed(unix.X_OK) {
			mask |= 2
		}
		if allowed(unix.W_OK | unix.X_OK) {
			mask |= 4 | 8
		}
	} else {
		if allowed(unix.W_OK) {
			mask |= 4 | 8
		}
		if allowed(unix.X_OK) {
			mask |= 32
		}
	}
	// DELETE is checked against the parent directory (including sticky rules).
	parent, err := f.pin(filepath.Dir(f.confinedName(name)))
	if err == nil {
		defer unix.Close(parent)
		var dir unix.Stat_t
		if unix.Fstat(parent, &dir) == nil && unix.Faccessat(parent, "", unix.W_OK|unix.X_OK, unix.AT_EMPTY_PATH|unix.AT_EACCESS) == nil {
			uid := uint32(unix.Geteuid())
			if dir.Mode&unix.S_ISVTX == 0 || uid == 0 || uid == dir.Uid || uid == stat.Uid {
				mask |= 16
			}
		}
	}
	return requested & mask, nil
}

func (f *volumeNFSFilesystem) withParent(name string, call func(int, string) error) error {
	name = f.confinedName(name)
	fd, err := f.pin(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return call(fd, filepath.Base(name))
}
