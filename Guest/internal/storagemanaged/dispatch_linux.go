//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	w "dev.cengine/guest/internal/storagewire"
	"errors"
	"golang.org/x/sys/unix"
)

type operation struct {
	s                *Session
	request          w.Request
	events           []w.Event
	namespacePending bool
}

// A successful namespace syscall is not complete until its pin/ref and
// event bookkeeping succeeds. On failure we fence the entire volume, rather than
// invent an ObjectID or allow another peer to observe stale cache state.
func (o *operation) namespaceApplied(parent *node) error {
	o.namespacePending = true
	o.changed(parent, false)
	if hook := o.s.registry.postNamespace; hook != nil {
		return hook()
	}
	return nil
}
func (o *operation) changed(n *node, data bool) {
	kind := w.InvalidateAttr
	if data {
		kind = w.InvalidateData
	}
	o.events = append(o.events, w.Event{Volume: o.s.binding.Volume, Object: n.object.id, Kind: kind, Name: []byte{}})
}
func (o *operation) entry(parent *node, name []byte, id w.ObjectID) {
	o.events = append(o.events, w.Event{Volume: o.s.binding.Volume, Object: id, Parent: parent.object.id, Kind: w.InvalidateEntry, Name: append([]byte{}, name...)})
	o.changed(parent, false)
}
func (s *Session) execute(r w.Request) (Result, error) {
	o := &operation{s: s, request: r, events: []w.Event{}}
	result := Result{Reply: w.Reply{Sequence: r.Sequence, Op: r.Body.Operation()}, Events: []w.Event{}}
	entered, returned := false, false
	call := func() error {
		entered = true
		var e error
		result.Reply.Body, e = o.run()
		returned = true
		return e
	}
	var err error
	if r.Auth.Kind == w.CallerAuth {
		umask := uint32(0)
		switch v := r.Body.(type) {
		case w.CreateRequest:
			umask = v.Umask
		case w.MkdirRequest:
			umask = v.Umask
		case w.MknodRequest:
			umask = v.Umask
		}
		err = s.worker.Do(*r.Auth.Caller, umask, call)
	} else if r.Auth.Kind == w.OpenGrantAuth {
		err = grantIO(call)
	} else {
		err = call()
	}
	// An I/O/space failure from the mutation itself is uncertain even if a later
	// sync succeeds. Preserve its write-ahead obligation across service crashes.
	// Worker.Do catches panic/Goexit as non-errno errors. A normal-return witness
	// distinguishes those from ordinary policy errors after successful sync.
	if needsDurability(r) && ((entered && !returned) || errors.Is(err, unix.EIO) || errors.Is(err, unix.ENOSPC)) {
		s.registry.latch(s.binding.Volume, err)
	}
	// syncfs includes file data, inode/xattr metadata AND all directory mutations.
	// Also synchronize partial failures (SETATTR, create-then-open, etc.).
	if o.namespacePending {
		if err == nil {
			err = unix.EIO
		}
		s.registry.latch(s.binding.Volume, err)
	}
	if r.Mutates() {
		err = errors.Join(err, s.registry.syncFilesystem(s.binding.Volume, int(s.root.Fd())))
	}
	if err != nil {
		result.Reply.Errno = errno(err)
		result.Reply.Body = nil
	}
	for _, e := range o.events {
		if s.registry.eventSequence == ^uint64(0) {
			s.failed = true
			return result, s.registry.latch(s.binding.Volume, unix.EOVERFLOW)
		}
		s.registry.eventSequence++
		e.EventSequence = s.registry.eventSequence
		if e.Validate() != nil {
			s.failed = true
			return result, s.registry.latch(s.binding.Volume, unix.EIO)
		}
		result.Events = append(result.Events, e)
	}
	return result, s.registry.faults[s.binding.Volume]
}
func (o *operation) run() (w.ReplyBody, error) {
	s := o.s
	switch v := o.request.Body.(type) {
	case w.LookupRequest:
		e, err := s.lookup(v.Parent, v.Name)
		return w.LookupReply{Entry: e}, err
	case w.GetAttrRequest:
		n, err := s.getNode(v.Node)
		if err != nil {
			return nil, err
		}
		fd := n.fd
		if v.Handle != nil {
			h := s.handles[*v.Handle]
			if h == nil || h.node != n {
				return nil, unix.EBADF
			}
			fd = h.fd
		} else if o.request.Auth.Kind == w.NodeMetadataAuth && n.lookups == 0 {
			return nil, unix.ESTALE
		}
		st, err := stat(fd)
		return w.GetAttrReply{Attr: attributes(st)}, err
	case w.SetAttrRequest:
		return o.setattr(v)
	case w.CreateRequest:
		return o.create(v)
	case w.OpenRequest:
		n, err := s.getNode(v.Node)
		if err != nil {
			return nil, err
		}
		opened, err := o.open(n, v.Flags, v.FuseOpenFlags, false)
		return w.OpenReply{Opened: opened}, err
	case w.OpenDirRequest:
		n, err := s.parent(v.Node)
		if err != nil {
			return nil, err
		}
		opened, err := o.open(n, v.Flags, 0, true)
		return w.OpenDirReply{Opened: opened}, err
	case w.ReadRequest:
		h, err := s.getHandle(v.Node, v.Handle, false, 1)
		if err != nil {
			return nil, err
		}
		if err = o.prepareIO(h, v.IOFlags); err != nil {
			return nil, err
		}
		data := ioBuffer(int(v.Size), v.IOFlags)
		n, err := unix.Pread(h.fd, data, int64(v.Offset))
		if n < 0 {
			n = 0
		}
		return w.ReadReply{Data: data[:n]}, err
	case w.WriteRequest:
		h, err := s.getHandle(v.Node, v.Handle, false, 2)
		if err != nil {
			return nil, err
		}
		if err = o.prepareIO(h, v.IOFlags); err != nil {
			return nil, err
		}

		o.changed(h.node, true)
		o.changed(h.node, false)
		data := v.Data
		if v.IOFlags&w.OpenDirect != 0 {
			data = ioBuffer(len(v.Data), v.IOFlags)
			copy(data, v.Data)
		}
		n, err := unix.Pwrite(h.fd, data, int64(v.Offset))
		if n < 0 {
			n = 0
		}
		return w.WriteReply{Written: uint32(n)}, err
	case w.FlushRequest:
		h, err := s.getHandle(v.Node, v.Handle, false, 0)
		if err != nil {
			return nil, err
		}
		return w.FlushReply{}, s.syncFile(h.fd, false)
	case w.FsyncRequest:
		h, err := s.getHandle(v.Node, v.Handle, false, 0)
		if err != nil {
			return nil, err
		}
		return w.FsyncReply{}, s.syncFile(h.fd, v.DataOnly)
	case w.FsyncDirRequest:
		h, err := s.getHandle(v.Node, v.Handle, true, 0)
		if err != nil {
			return nil, err
		}
		return w.FsyncDirReply{}, s.syncFile(h.fd, v.DataOnly)
	case w.ReleaseRequest:
		return w.ReleaseReply{}, s.release(v.Node, v.Handle, false)
	case w.ReleaseDirRequest:
		return w.ReleaseDirReply{}, s.release(v.Node, v.Handle, true)
	case w.ReadDirRequest:
		h, err := s.getHandle(v.Node, v.Handle, true, 1)
		if err != nil {
			return nil, err
		}
		entries, err := readDir(h.fd, v.Cookie, v.MaxBytes)
		return w.ReadDirReply{Entries: entries}, err
	case w.MkdirRequest:
		e, err := o.makeNode(v.Parent, v.Name, func(fd int, name string) error { return unix.Mkdirat(fd, name, v.Mode&07777) })
		return w.MkdirReply{Entry: e}, err
	case w.MknodRequest:
		// The syscall dev argument is uint32 even on 64-bit Linux. Never
		// silently truncate a wire rdev and create a different device.
		if v.Rdev > uint64(^uint32(0)) {
			return nil, unix.EINVAL
		}
		mode := v.Mode
		if mode&unix.S_IFMT == 0 {
			mode |= unix.S_IFREG
		}
		e, err := o.makeNode(v.Parent, v.Name, func(fd int, name string) error { return unix.Mknodat(fd, name, mode, int(v.Rdev)) })
		return w.MknodReply{Entry: e}, err
	case w.SymlinkRequest:
		e, err := o.makeNode(v.Parent, v.Name, func(fd int, name string) error { return unix.Symlinkat(string(v.Target), fd, name) })
		return w.SymlinkReply{Entry: e}, err
	case w.ReadlinkRequest:
		n, err := s.getNode(v.Node)
		if err != nil {
			return nil, err
		}
		data := make([]byte, w.MaxTarget+1)
		size, err := unix.Readlinkat(n.fd, "", data)
		if err != nil {
			return nil, err
		}
		if size > w.MaxTarget {
			return nil, unix.ENAMETOOLONG
		}
		return w.ReadlinkReply{Target: data[:size]}, nil
	case w.LinkRequest:
		return o.link(v)
	case w.RenameRequest:
		return w.RenameReply{}, o.rename(v)
	case w.UnlinkRequest:
		return w.UnlinkReply{}, o.unlink(v.Parent, v.Name, 0)
	case w.RmdirRequest:
		return w.RmdirReply{}, o.unlink(v.Parent, v.Name, unix.AT_REMOVEDIR)
	case w.AccessRequest:
		n, err := s.getNode(v.Node)
		if err != nil {
			return nil, err
		}
		return w.AccessReply{}, unix.Faccessat(n.fd, "", v.Mask, unix.AT_EMPTY_PATH|unix.AT_EACCESS|unix.AT_SYMLINK_NOFOLLOW)
	case w.GetXAttrRequest:
		data, size, err := o.getXattr(v.Node, string(v.Name), v.Size, false)
		return w.GetXAttrReply{Size: size, Value: data}, err
	case w.ListXAttrRequest:
		data, size, err := o.getXattr(v.Node, "", v.Size, true)
		return w.ListXAttrReply{Size: size, Names: data}, err
	case w.SetXAttrRequest:
		return w.SetXAttrReply{}, o.setXattr(v.Node, string(v.Name), v.Value, int(v.Flags), false)
	case w.RemoveXAttrRequest:
		return w.RemoveXAttrReply{}, o.setXattr(v.Node, string(v.Name), nil, 0, true)
	case w.StatFSRequest:
		n, err := s.getNode(v.Node)
		if err != nil {
			return nil, err
		}
		var st unix.Statfs_t
		err = unix.Fstatfs(n.fd, &st)
		return w.StatFSReply{Stat: w.FSStat{Blocks: st.Blocks, BlocksFree: st.Bfree, BlocksAvailable: st.Bavail, Files: st.Files, FilesFree: st.Ffree, BlockSize: uint32(st.Bsize), NameLength: uint32(st.Namelen), FragmentSize: uint32(st.Frsize)}}, err
	case w.ForgetRequest:
		return w.ForgetReply{}, s.forget(v.Entries)
	case w.FallocateRequest:
		h, err := s.getHandle(v.Node, v.Handle, false, 2)
		if err != nil {
			return nil, err
		}
		o.changed(h.node, true)
		o.changed(h.node, false)
		return w.FallocateReply{}, unix.Fallocate(h.fd, v.Mode, int64(v.Offset), int64(v.Length))
	case w.LseekRequest:
		h, err := s.getHandle(v.Node, v.Handle, false, 0)
		if err != nil {
			return nil, err
		}
		offset, err := unix.Seek(h.fd, int64(v.Offset), int(v.Whence))
		return w.LseekReply{Offset: uint64(offset)}, err
	}
	return nil, unix.ENOSYS
}
func (o *operation) prepareIO(h *handle, flags uint32) error {
	// Access mode remains the immutable grant. SYNC/DSYNC cannot be toggled by
	// F_SETFL, whereas DIRECT and NOATIME really are mutable descriptor status.
	if flags&(w.OpenDSync|w.OpenSync) & ^h.flags != 0 {
		return unix.EINVAL
	}
	current, err := unix.FcntlInt(uintptr(h.fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	const mutable = unix.O_DIRECT | unix.O_NOATIME | unix.O_NONBLOCK | unix.O_ASYNC
	desired := (current &^ (mutable | unix.O_APPEND)) | (openFlags(flags) & mutable)
	if flags&w.OpenNonblock == 0 {
		desired &^= unix.O_NONBLOCK
	}
	if desired == current {
		return nil
	}
	// With a caller, fcntl performs the actual owner/CAP_FOWNER check under that
	// exact identity. An identity-less grant cannot borrow service UID ownership
	// to newly enable NOATIME; it can keep an existing authorization or clear it.
	if o.request.Auth.Kind != w.CallerAuth && desired&unix.O_NOATIME != 0 && current&unix.O_NOATIME == 0 {
		return unix.EPERM
	}
	_, err = unix.FcntlInt(uintptr(h.fd), unix.F_SETFL, desired)
	return err
}
