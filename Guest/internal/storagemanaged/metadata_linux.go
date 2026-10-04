//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	w "dev.cengine/guest/internal/storagewire"
	"errors"
	"golang.org/x/sys/unix"
)

func (o *operation) setattr(v w.SetAttrRequest) (w.ReplyBody, error) {
	s := o.s
	n, err := s.getNode(v.Node)
	if err != nil {
		return nil, err
	}
	fd := n.fd
	var h *handle
	if v.Handle != nil {
		h = s.handles[*v.Handle]
		if h == nil || h.node != n {
			return nil, unix.EBADF
		}
	}
	if v.Semantics&w.MetadataFile != 0 {
		if h == nil {
			return nil, unix.EBADF
		}
		fd = h.fd
		if v.Valid&w.SetSize != 0 {
			if h.directory {
				return nil, unix.EBADF
			}
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil {
				return nil, err
			}
			if h.flags&w.OpenAccessMask == w.OpenReadOnly || flags&unix.O_ACCMODE == unix.O_RDONLY || flags&unix.O_PATH != 0 {
				return nil, unix.EINVAL
			}
		}
	}
	// This runs inside Worker.Do, with both session and namespace locks held.
	// No data reopen or opener identity: FILE uses its exact grant, all other
	// intents use this session's view pin (including retained-unlinked symlinks).
	// notify_change may fail after an implicit kill: invalidate and sync even on
	// error, never retry an ambiguous completion or split it into user syscalls.
	o.changed(n, false)
	if v.Valid&w.SetSize != 0 {
		o.changed(n, true)
	}
	attr := metadataAttr(v, fd)
	if err = platformApplyMetadata(int(s.metadataFD.Fd()), &attr); err != nil {
		return nil, err
	}
	st, err := stat(fd)
	return w.SetAttrReply{Attr: attributes(st)}, err
}

// Prefer exact f*xattr on real regular/directory descriptors opened under the
// caller. Metadata permission is not data-open permission. For inaccessible
// data opens we use the retained pin's trusted procfs magiclink with an actual
// metadata syscall under the same caller. xattrat(AT_EMPTY_PATH) rejects O_PATH
// descriptors, including on Linux 6.18; it is not a valid fallback.
func xattrFD(n *node) (int, error) {
	st, err := stat(n.fd)
	if err != nil {
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG && st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, unix.EOPNOTSUPP
	}
	fd, err := unix.Open(procFD(n.fd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil && st.Mode&unix.S_IFMT == unix.S_IFREG && errors.Is(err, unix.EACCES) {
		fd, err = unix.Open(procFD(n.fd), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return -1, err
	}
	if err = same(fd, n.object.key); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
func (o *operation) xattrCall(id w.NodeID, name string, data []byte, flags int, kind int) (int, error) {
	n, err := o.s.getNode(id)
	if err != nil {
		return 0, err
	}
	st, err := stat(n.fd)
	if err != nil {
		return 0, err
	}
	if kind >= 2 {
		o.changed(n, false)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return pinnedXattr(n.fd, name, data, flags, kind)
	}
	fd, err := xattrFD(n)
	if err == nil {
		defer unix.Close(fd)
		switch kind {
		case 0:
			return unix.Fgetxattr(fd, name, data)
		case 1:
			return unix.Flistxattr(fd, data)
		case 2:
			return 0, unix.Fsetxattr(fd, name, data, flags)
		case 3:
			return 0, unix.Fremovexattr(fd, name)
		}
	}
	// An O_WRONLY metadata-open fallback can fail EROFS on a read-only view,
	// even though the actual Get/ListXattr needs no data-open permission.
	if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EROFS) {
		return 0, err
	}
	return pinnedXattr(n.fd, name, data, flags, kind)
}
func (o *operation) getXattr(id w.NodeID, name string, size uint32, list bool) ([]byte, uint32, error) {
	kind := 0
	if list {
		kind = 1
	}
	data := make([]byte, size)
	n, err := o.xattrCall(id, name, data, 0, kind)
	if err != nil {
		return nil, 0, err
	}
	if n < 0 || n > w.MaxXAttr {
		return nil, 0, unix.EOVERFLOW
	}
	if size == 0 {
		return []byte{}, uint32(n), nil
	}
	if n > len(data) {
		return nil, 0, unix.EIO
	}
	return data[:n], uint32(n), nil
}
func (o *operation) setXattr(id w.NodeID, name string, data []byte, flags int, remove bool) error {
	kind := 2
	if remove {
		kind = 3
	}
	_, err := o.xattrCall(id, name, data, flags, kind)
	return err
}

// pinnedXattr follows only the trusted exact procfd magiclink. Linux 6.18
// proc_pid_get_link/nd_jump_link returns a pure jump, not symlink text: even a
// symlink pin selects that inode, not its target. l*xattr here would incorrectly
// select the procfs link itself. No client pathname or service data-open grant.
func pinnedXattr(fd int, name string, data []byte, flags, kind int) (int, error) {
	path := procFD(fd)
	switch kind {
	case 0:
		return unix.Getxattr(path, name, data)
	case 1:
		return unix.Listxattr(path, data)
	case 2:
		return 0, unix.Setxattr(path, name, data, flags)
	case 3:
		return 0, unix.Removexattr(path, name)
	}
	return 0, unix.EINVAL
}
