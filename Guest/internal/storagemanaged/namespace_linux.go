//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	w "dev.cengine/guest/internal/storagewire"
	"errors"
	"golang.org/x/sys/unix"
)

func (o *operation) open(n *node, flags, fuseFlags uint32, dir bool) (w.Opened, error) {
	s := o.s
	if len(s.handles) >= MaxHandles || s.nextHandle == ^w.HandleID(0) {
		return w.Opened{}, unix.EMFILE
	}
	st, err := stat(n.fd)
	if err != nil {
		return w.Opened{}, err
	}
	kind := st.Mode & unix.S_IFMT
	if dir && kind != unix.S_IFDIR {
		return w.Opened{}, unix.ENOTDIR
	}
	if !dir && kind != unix.S_IFREG {
		if kind == unix.S_IFLNK {
			return w.Opened{}, unix.ELOOP
		}
		if kind == unix.S_IFDIR {
			return w.Opened{}, unix.EISDIR
		}
		return w.Opened{}, unix.EPERM
	}
	if fuseFlags != 0 || flags&w.OpenTruncate != 0 {
		return w.Opened{}, unix.EINVAL
	}
	// The only followed magiclink is our retained exact descriptor, after checking
	// its type. No client path can reach procfs, devices, sockets, or a FIFO open.
	fd, err := unix.Open(procFD(n.fd), openFlags(flags)&^(unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL), 0)
	if err != nil {
		return w.Opened{}, err
	}
	if err = same(fd, n.object.key); err != nil {
		unix.Close(fd)
		return w.Opened{}, err
	}
	return s.grant(n, fd, flags, dir)
}
func (o *operation) create(v w.CreateRequest) (w.ReplyBody, error) {
	s := o.s
	if len(s.nodes) >= MaxNodes || len(s.handles) >= MaxHandles || len(s.registry.objects) >= MaxObjects {
		return nil, unix.ENFILE
	}
	p, err := s.parent(v.Parent)
	if err != nil {
		return nil, err
	}
	// CREATE success means newly created to Linux fuse_atomic_open (FMODE_CREATED).
	// Always return EEXIST on collision: the managed source kernel must look up and
	// perform a normal non-created OPEN plus semantic truncate. Returning an existing
	// handle here suppresses VFS truncation and its permission/killpriv checks.
	// O_EXCL also prevents opening special inodes with side-effecting callbacks.
	fd, err := unix.Openat(p.fd, string(v.Name), (openFlags(v.Flags)|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW)&^unix.O_TRUNC, v.Mode&07777)
	if err != nil {
		return nil, err
	}
	if err = o.namespaceApplied(p); err != nil {
		unix.Close(fd)
		return nil, err
	}
	pin, err := unix.Open(procFD(fd), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	e, err := s.intern(pin)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	n := s.nodes[e.Node]
	opened, err := s.grant(n, fd, v.Flags, false)
	if err != nil {
		n.lookups--
		s.collect(n)
		return nil, err
	}
	o.entry(p, v.Name, e.Object)
	o.changed(n, false)
	o.namespacePending = false
	return w.CreateReply{Entry: e, Opened: opened}, nil
}
func (o *operation) makeNode(parent w.NodeID, name []byte, call func(int, string) error) (w.Entry, error) {
	s := o.s
	if len(s.nodes) >= MaxNodes || len(s.registry.objects) >= MaxObjects {
		return w.Entry{}, unix.ENFILE
	}
	p, err := s.parent(parent)
	if err != nil {
		return w.Entry{}, err
	}
	if err = call(p.fd, string(name)); err != nil {
		return w.Entry{}, err
	}
	if err = o.namespaceApplied(p); err != nil {
		return w.Entry{}, err
	}
	e, err := s.lookup(parent, name)
	if err != nil {
		return w.Entry{}, err
	}
	o.entry(p, name, e.Object)
	o.namespacePending = false
	return e, nil
}
func (o *operation) link(v w.LinkRequest) (w.ReplyBody, error) {
	s := o.s
	n, err := s.getNode(v.Source)
	if err != nil {
		return nil, err
	}
	p, err := s.parent(v.Parent)
	if err != nil {
		return nil, err
	}
	if n.lookups == ^uint64(0) {
		return nil, unix.ENFILE
	}
	// Follow only the trusted procfd magiclink, whose pure jump retains even a
	// symlink inode. No source alias scan or privileged AT_EMPTY_PATH. linkat still
	// checks current-caller protected_hardlinks and rejects zero-nlink resurrection.
	if err = unix.Linkat(unix.AT_FDCWD, procFD(n.fd), p.fd, string(v.Name), unix.AT_SYMLINK_FOLLOW); err != nil {
		return nil, err
	}
	if err = o.namespaceApplied(p); err != nil {
		return nil, err
	}
	e, err := s.lookup(v.Parent, v.Name)
	if err != nil {
		return nil, err
	}
	if e.Object != n.object.id {
		return nil, unix.ESTALE
	}
	o.entry(p, v.Name, e.Object)
	o.changed(n, false)
	o.namespacePending = false
	return w.LinkReply{Entry: e}, nil
}

// Name operations can affect an inode not yet looked up in this session. Global
// registry retains an identity even when no session currently has a NodeID.
func (o *operation) namedObject(p *node, name []byte) (w.ObjectID, *object, error) {
	fd, err := pinAt(p.fd, string(name))
	if err != nil {
		return w.ObjectID{}, nil, err
	}
	st, err := stat(fd)
	if err != nil {
		unix.Close(fd)
		return w.ObjectID{}, nil, err
	}
	obj, err := o.s.registry.retainObject(fd, inodeKey{o.s.binding.Volume, st.Dev, st.Ino})
	if err != nil {
		return w.ObjectID{}, nil, err
	}
	return obj.id, obj, nil
}
func (o *operation) unlink(parent w.NodeID, name []byte, flags int) error {
	s := o.s
	p, err := s.parent(parent)
	if err != nil {
		return err
	}
	id, obj, err := o.namedObject(p, name)
	if err != nil {
		return err
	}
	if err = unix.Unlinkat(p.fd, string(name), flags); err != nil {
		return err
	}
	if err = o.namespaceApplied(p); err != nil {
		return err
	}
	o.entry(p, name, id)
	if obj != nil {
		o.changed(&node{object: obj}, false)
	}
	o.namespacePending = false
	return nil
}
func (o *operation) rename(v w.RenameRequest) error {
	s := o.s
	old, err := s.parent(v.OldParent)
	if err != nil {
		return err
	}
	next, err := s.parent(v.NewParent)
	if err != nil {
		return err
	}
	id, src, err := o.namedObject(old, v.OldName)
	if err != nil {
		return err
	}
	destID, dst, err := o.namedObject(next, v.NewName)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err = unix.Renameat2(old.fd, string(v.OldName), next.fd, string(v.NewName), uint(v.Flags)); err != nil {
		return err
	}
	if err = o.namespaceApplied(old); err != nil {
		return err
	}
	o.entry(old, v.OldName, id)
	o.entry(next, v.NewName, id)
	if dst != nil {
		o.changed(&node{object: dst}, false)
	}
	if src != nil {
		o.changed(&node{object: src}, false)
	}
	if v.Flags&w.RenameExchange != 0 && dst != nil {
		o.entry(old, v.OldName, destID)
	}
	o.namespacePending = false
	return nil
}
