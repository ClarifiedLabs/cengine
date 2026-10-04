//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func procFD(fd int) string { return fmt.Sprintf("/proc/self/fd/%d", fd) }
func stat(fd int) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	return st, err
}
func attributes(st unix.Stat_t) w.Attr {
	return w.Attr{Ino: st.Ino, Size: uint64(st.Size), Blocks: uint64(st.Blocks), Mode: st.Mode, Nlink: uint32(st.Nlink), UID: st.Uid, GID: st.Gid, Rdev: st.Rdev, BlockSize: uint32(st.Blksize), ATime: w.Timestamp{Seconds: st.Atim.Sec, Nanoseconds: uint32(st.Atim.Nsec)}, MTime: w.Timestamp{Seconds: st.Mtim.Sec, Nanoseconds: uint32(st.Mtim.Nsec)}, CTime: w.Timestamp{Seconds: st.Ctim.Sec, Nanoseconds: uint32(st.Ctim.Nsec)}}
}
func dup(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0) }
func pinAt(fd int, name string) (int, error) {
	return unix.Openat2(fd, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
}
func same(fd int, key inodeKey) error {
	st, err := stat(fd)
	if err != nil {
		return err
	}
	if st.Dev != key.dev || st.Ino != key.ino {
		return unix.ESTALE
	}
	return nil
}
func (s *Session) initialize() (w.Entry, error) {
	b, err := stat(int(s.root.Fd()))
	if err != nil {
		return w.Entry{}, err
	}
	if b.Mode&unix.S_IFMT != unix.S_IFDIR {
		return w.Entry{}, unix.EXDEV
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(s.root.Fd()), &fs); err != nil {
		return w.Entry{}, err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return w.Entry{}, unix.ENODEV
	}
	// syncfs requires a real descriptor. Reject O_PATH setup duplicates.
	flags, err := unix.FcntlInt(s.root.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return w.Entry{}, err
	}
	if flags&unix.O_PATH != 0 {
		return w.Entry{}, unix.EBADF
	}
	// Canonical provenance alone is not a no-idmap guarantee. RW requires an
	// authoritative check here; RO checks immediately before cloning in operationRoot.
	if s.binding.Mode != storageauthority.ReadOnly {
		if _, err = requireUnmappedMount(int(s.root.Fd())); err != nil {
			return w.Entry{}, err
		}
	}
	fd, err := s.operationRoot()
	if err != nil {
		return w.Entry{}, err
	}
	return s.intern(fd)
}

// intern consumes fd on every path. A kernel lookup owns one lookup reference;
// open references and the serialized in-flight operation keep forgotten nodes live.
func (s *Session) intern(fd int) (w.Entry, error) {
	st, err := stat(fd)
	if err != nil {
		unix.Close(fd)
		return w.Entry{}, err
	}
	key := inodeKey{s.binding.Volume, st.Dev, st.Ino}
	n := s.byInode[key]
	if n == nil {
		if len(s.nodes) >= MaxNodes || s.nextNode == ^w.NodeID(0) {
			unix.Close(fd)
			return w.Entry{}, unix.ENFILE
		}
		identityFD, err := dup(fd)
		if err != nil {
			unix.Close(fd)
			return w.Entry{}, err
		}
		obj, err := s.registry.retainObject(identityFD, key)
		if err != nil {
			unix.Close(fd)
			return w.Entry{}, err
		}
		s.nextNode++
		n = &node{id: s.nextNode, object: obj, fd: fd}
		obj.refs++
		s.nodes[n.id] = n
		s.byInode[key] = n
	} else {
		unix.Close(fd)
	}
	if n.lookups == ^uint64(0) {
		return w.Entry{}, unix.EOVERFLOW
	}
	n.lookups++
	return w.Entry{Node: n.id, Generation: uint64(n.id), Object: n.object.id, Attr: attributes(st)}, nil
}

// retainObject consumes fd and gives the same opaque identity to every session
// and event for this inode. Pins prevent inode-number reuse during that lifetime.
// The fd is lifetime identity ownership only, never an operational descriptor.
func (r *Registry) retainObject(fd int, key inodeKey) (*object, error) {
	if obj := r.objects[key]; obj != nil {
		return obj, unix.Close(fd)
	}
	if len(r.objects) >= MaxObjects {
		unix.Close(fd)
		return nil, unix.ENFILE
	}
	obj := &object{key: key, fd: fd}
	if _, err := rand.Read(obj.id[:]); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if obj.id == (w.ObjectID{}) {
		unix.Close(fd)
		return nil, unix.EIO
	}
	r.objects[key] = obj
	return obj, nil
}
func (s *Session) getNode(id w.NodeID) (*node, error) {
	n := s.nodes[id]
	if n == nil {
		return nil, unix.ESTALE
	}
	return n, nil
}
func (s *Session) parent(id w.NodeID) (*node, error) {
	n, err := s.getNode(id)
	if err != nil {
		return nil, err
	}
	st, err := stat(n.fd)
	if err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, unix.ENOTDIR
	}
	return n, nil
}
func (s *Session) lookup(parent w.NodeID, name []byte) (w.Entry, error) {
	p, err := s.parent(parent)
	if err != nil {
		return w.Entry{}, err
	}
	fd, err := pinAt(p.fd, string(name))
	if err != nil {
		return w.Entry{}, err
	}
	return s.intern(fd)
}
func (s *Session) collect(n *node) error {
	if n.lookups != 0 || n.opens != 0 {
		return nil
	}
	delete(s.nodes, n.id)
	delete(s.byInode, n.object.key)
	n.object.refs--
	// The bounded volume registry keeps the inode pinned until the last session
	// drains: events and later lookups must not reuse an inode's identity.
	// Operational pins never survive their session/node or migrate between views.
	if err := unix.Close(n.fd); err != nil {
		return s.registry.latch(s.binding.Volume, err)
	}
	return nil
}
func (s *Session) getHandle(nodeID w.NodeID, id w.HandleID, dir bool, access int) (*handle, error) {
	h := s.handles[id]
	if h == nil || h.node.id != nodeID || h.directory != dir {
		return nil, unix.EBADF
	}
	mode := h.flags & w.OpenAccessMask
	if access == 1 && mode == w.OpenWriteOnly || access == 2 && mode == w.OpenReadOnly {
		return nil, unix.EBADF
	}
	return h, nil
}
func (s *Session) grant(n *node, fd int, flags uint32, dir bool) (w.Opened, error) {
	if len(s.handles) >= MaxHandles || s.nextHandle == ^w.HandleID(0) {
		unix.Close(fd)
		return w.Opened{}, unix.EMFILE
	}
	s.nextHandle++
	s.handles[s.nextHandle] = &handle{fd: fd, node: n, flags: flags, directory: dir}
	n.opens++
	return w.Opened{Handle: s.nextHandle}, nil
}
func (s *Session) release(nodeID w.NodeID, id w.HandleID, dir bool) error {
	h, err := s.getHandle(nodeID, id, dir, 0)
	if err != nil {
		return err
	}
	// Close errors are terminal: never retry close on a potentially reused fd.
	err = s.syncFile(h.fd, false)
	err = errors.Join(err, unix.Close(h.fd))
	delete(s.handles, id)
	h.node.opens--
	err = errors.Join(err, s.collect(h.node))
	if err != nil {
		s.failed = true
		s.registry.latch(s.binding.Volume, err)
	}
	return err
}
func (s *Session) forget(entries []w.ForgetEntry) error {
	// Validate the entire batch before changing any count.
	for _, e := range entries {
		n := s.nodes[e.Node]
		if n == nil || n.lookups < e.Count {
			s.failed = true
			return unix.EINVAL
		}
	}
	var err error
	for _, e := range entries {
		n := s.nodes[e.Node]
		n.lookups -= e.Count
		err = errors.Join(err, s.collect(n))
	}
	if err != nil {
		s.failed = true
	}
	return err
}
func (r *Registry) barrier(binding storageauthority.Binding, root *os.File) error {
	var fs unix.Statfs_t
	validation := unix.Fstatfs(int(root.Fd()), &fs)
	if validation == nil && fs.Type != unix.EXT4_SUPER_MAGIC {
		validation = unix.ENODEV
	}
	s := r.sessions[binding]
	if s != nil && validation == nil {
		st, err := stat(int(s.root.Fd()))
		if err != nil {
			validation = err
		} else {
			validation = same(int(root.Fd()), inodeKey{binding.Volume, st.Dev, st.Ino})
		}
	}
	err := validation
	if s != nil {
		s.closed = true
		for id, h := range s.handles {
			err = errors.Join(err, unix.Close(h.fd))
			h.node.opens--
			delete(s.handles, id)
		}
		for _, n := range s.nodes {
			n.lookups = 0
			err = errors.Join(err, s.collect(n))
		}
		err = errors.Join(err, s.metadataFD.Close(), s.root.Close())
		delete(r.sessions, binding)
	}
	last := true
	for _, other := range r.sessions {
		if other.binding.Volume == binding.Volume {
			last = false
			break
		}
	}
	if last {
		for key, obj := range r.objects {
			if key.volume != binding.Volume {
				continue
			}
			if obj.refs != 0 {
				err = errors.Join(err, unix.EIO)
			}
			err = errors.Join(err, unix.Close(obj.fd))
			delete(r.objects, key)
		}
	}
	// Close ALL final orphan/inode owners before the final filesystem sync.
	// root is the authority's borrowed descriptor and survives the cleanup above.
	// Still attempt sync after a previous failure; never erase the sticky evidence.
	if validation == nil {
		err = errors.Join(err, r.syncFilesystem(binding.Volume, int(root.Fd())))
	}
	return r.latch(binding.Volume, err)
}
