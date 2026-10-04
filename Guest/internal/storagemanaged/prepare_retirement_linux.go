//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"os"
	"runtime"

	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// prepareRetirementCensus runs only with registry.gate held, after the historical
// qualification check. It neither opens paths nor reads directories/data: stat,
// statx and fcntl inspection cannot dirty atime. New's RW initialization owns one
// canonical real root, two O_PATH pins, and one lookup/object reference. Only
// successful root OPENDIR may have added ownership since then.
func (s *Session) prepareRetirementCensus(root *os.File) (bool, error) {
	if len(s.nodes) != 1 || len(s.byInode) != 1 || len(s.registry.objects) != 1 {
		return false, nil // includes foreign-volume and zero-ref orphan objects
	}
	n := s.nodes[1]
	if n == nil || n.id != 1 || n.object == nil || s.nextNode != 1 || n.lookups != 1 || n.opens != uint64(len(s.handles)) || uint64(s.nextHandle) != uint64(len(s.handles)) {
		return false, unix.EIO
	}
	obj := n.object
	if obj.key.volume != s.binding.Volume || s.byInode[obj.key] != n || s.registry.objects[obj.key] != obj || obj.refs != 1 || obj.id == (w.ObjectID{}) {
		return false, unix.EIO
	}
	if s.root == nil || s.metadataFD == nil || s.worker == nil || s.registry.worker != s.worker || s.registry.store != s.binding.Store {
		return false, unix.EIO
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(root.Fd()), &fs); err != nil {
		return false, err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return false, unix.ENODEV
	}
	mount, err := uniqueMountID(int(root.Fd()))
	if err != nil {
		return false, err
	}
	// The authority root is borrowed, not one of the independently owned FDs.
	owned := map[int]bool{int(root.Fd()): true}
	check := func(fd int, path bool) error {
		if owned[fd] {
			return unix.EIO
		}
		owned[fd] = true
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			return err
		}
		if flags&unix.FD_CLOEXEC == 0 {
			return unix.EIO
		}
		return prepareRetirementRootPin(fd, obj.key, mount, path)
	}
	if err := prepareRetirementRootPin(int(root.Fd()), obj.key, mount, false); err != nil {
		return false, err
	}
	if err := check(int(s.root.Fd()), false); err != nil {
		return false, err
	}
	if err := check(n.fd, true); err != nil {
		return false, err
	}
	if err := check(obj.fd, true); err != nil {
		return false, err
	}
	// New minted this anonymous kernel capability before initialization. It is
	// not a backing-file write descriptor; no metadata ioctl is allowlisted.
	metadata := int(s.metadataFD.Fd())
	if owned[metadata] {
		return false, unix.EIO
	}
	owned[metadata] = true
	metadataFlags, err := unix.FcntlInt(uintptr(metadata), unix.F_GETFD, 0)
	if err != nil {
		return false, err
	}
	if metadataFlags&unix.FD_CLOEXEC == 0 {
		return false, unix.EIO
	}
	for id, h := range s.handles {
		if id == 0 || id > s.nextHandle || h == nil || h.node != n || !h.directory || !replayRootBootstrap(w.Request{Body: w.OpenDirRequest{Node: 1, Flags: h.flags}}) {
			return false, unix.EIO
		}
		if err := check(h.fd, false); err != nil {
			return false, err
		}
	}
	return true, nil
}

func prepareRetirementRootPin(fd int, key inodeKey, mount uint64, path bool) error {
	st, err := stat(fd)
	if err != nil {
		return err
	}
	if st.Dev != key.dev || st.Ino != key.ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 {
		return unix.ESTALE
	}
	got, err := uniqueMountID(fd)
	if err != nil {
		return err
	}
	if got != mount {
		return unix.EXDEV
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if !prepareRetirementFlags(flags, path, runtime.GOARCH) {
		return unix.EIO
	}
	return nil
}
