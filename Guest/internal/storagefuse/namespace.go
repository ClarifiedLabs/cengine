package storagefuse

import (
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func (f *rawFS) Lookup(_ <-chan struct{}, h *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	defer markCallbackPanic(h.Opcode)
	*out = fuse.EntryOut{}
	r, s := f.call(h, 0, func() w.RequestBody { return w.LookupRequest{Parent: f.node(h.NodeId), Name: []byte(name)} })
	if s != 0 {
		return s
	}
	return f.entry(r, out, h.Opcode)
}
func (f *rawFS) GetAttr(_ <-chan struct{}, in *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.AttrOut{}
	provenance := w.NodeMetadataAuth
	if in.Flags()&1 != 0 {
		provenance = w.OpenGrantAuth
	}
	r, s := f.call(&in.InHeader, provenance, func() w.RequestBody {
		if in.Flags()&^uint32(1) != 0 {
			return nil
		}
		return w.GetAttrRequest{Node: f.node(in.NodeId), Handle: f.optionalHandle(in.NodeId, in.Fh(), in.Flags()&1 != 0)}
	})
	if s != 0 {
		return s
	}
	return f.attrReply(r, out, in.Opcode)
}
func (f *rawFS) SetAttr(_ <-chan struct{}, in *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.AttrOut{}
	r, s := f.call(&in.InHeader, 0, func() w.RequestBody {
		// Linux 6.18.44 fuse_do_setattr adds LOCKOWNER to every SIZE request.
		// Locks are client-local: accept but do not forward the opaque token.
		const supported = fuse.FATTR_MODE | fuse.FATTR_UID | fuse.FATTR_GID | fuse.FATTR_SIZE | fuse.FATTR_ATIME | fuse.FATTR_MTIME | fuse.FATTR_FH | fuse.FATTR_ATIME_NOW | fuse.FATTR_MTIME_NOW | fuse.FATTR_LOCKOWNER | fuse.FATTR_CTIME
		if in.Valid & ^uint32(supported) != 0 || in.Valid&fuse.FATTR_ATIME_NOW != 0 && in.Valid&fuse.FATTR_ATIME == 0 || in.Valid&fuse.FATTR_MTIME_NOW != 0 && in.Valid&fuse.FATTR_MTIME == 0 {
			return nil
		}
		b := w.SetAttrRequest{Node: f.node(in.NodeId), Handle: f.optionalHandle(in.NodeId, in.Fh, in.Valid&fuse.FATTR_FH != 0)}
		if in.Valid&fuse.FATTR_MODE != 0 {
			b.Valid |= w.SetMode
			b.Mode = in.Mode & 07777
		}
		if in.Valid&fuse.FATTR_UID != 0 {
			b.Valid |= w.SetUID
			b.UID = in.Uid
		}
		if in.Valid&fuse.FATTR_GID != 0 {
			b.Valid |= w.SetGID
			b.GID = in.Gid
		}
		if in.Valid&fuse.FATTR_SIZE != 0 {
			b.Valid |= w.SetSize
			b.Size = in.Size
		}
		// CTIME has no direct timestamp attribute. Captured MetadataCTime in
		// Client.Do carries its intent; the backing kernel selects current_time.
		if in.Valid&fuse.FATTR_ATIME != 0 {
			b.Valid |= w.SetATime
			b.ATime = w.Timestamp{Seconds: int64(in.Atime), Nanoseconds: in.Atimensec}
			if in.Valid&fuse.FATTR_ATIME_NOW != 0 {
				b.Valid |= w.SetATimeNow
			}
		}
		if in.Valid&fuse.FATTR_MTIME != 0 {
			b.Valid |= w.SetMTime
			b.MTime = w.Timestamp{Seconds: int64(in.Mtime), Nanoseconds: in.Mtimensec}
			if in.Valid&fuse.FATTR_MTIME_NOW != 0 {
				b.Valid |= w.SetMTimeNow
			}
		}
		return b
	})
	if s != 0 {
		return s
	}
	return f.attrReply(r, out, in.Opcode)
}
func (f *rawFS) Create(_ <-chan struct{}, in *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.CreateOut{}
	r, s := f.call(&in.InHeader, 0, func() w.RequestBody {
		flags, ok := openFlags(in.Flags, f.arch)
		if !ok {
			return nil
		}
		// Linux fuse_create_in.open_flags occupies go-fuse's legacy Padding field.
		return w.CreateRequest{Parent: f.node(in.NodeId), Name: []byte(name), Flags: flags, FuseOpenFlags: in.Padding, Mode: in.Mode, Umask: in.Umask}
	})
	if s != 0 {
		return s
	}
	if s = f.entry(r, &out.EntryOut, in.Opcode); s != 0 {
		return s
	}
	return f.opened(r, &out.OpenOut, in.Opcode)
}
func (f *rawFS) Mkdir(_ <-chan struct{}, in *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.EntryOut{}
	r, s := f.call(&in.InHeader, 0, func() w.RequestBody {
		return w.MkdirRequest{Parent: f.node(in.NodeId), Name: []byte(name), Mode: in.Mode, Umask: in.Umask}
	})
	if s != 0 {
		return s
	}
	return f.entry(r, out, in.Opcode)
}
func (f *rawFS) Mknod(_ <-chan struct{}, in *fuse.MknodIn, name string, out *fuse.EntryOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.EntryOut{}
	r, s := f.call(&in.InHeader, 0, func() w.RequestBody {
		return w.MknodRequest{Parent: f.node(in.NodeId), Name: []byte(name), Mode: in.Mode, Umask: in.Umask, Rdev: uint64(in.Rdev)}
	})
	if s != 0 {
		return s
	}
	return f.entry(r, out, in.Opcode)
}
func (f *rawFS) Symlink(_ <-chan struct{}, h *fuse.InHeader, target, name string, out *fuse.EntryOut) fuse.Status {
	defer markCallbackPanic(h.Opcode)
	*out = fuse.EntryOut{}
	r, s := f.call(h, 0, func() w.RequestBody {
		return w.SymlinkRequest{Parent: f.node(h.NodeId), Name: []byte(name), Target: []byte(target)}
	})
	if s != 0 {
		return s
	}
	return f.entry(r, out, h.Opcode)
}
func (f *rawFS) Link(_ <-chan struct{}, in *fuse.LinkIn, name string, out *fuse.EntryOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.EntryOut{}
	r, s := f.call(&in.InHeader, 0, func() w.RequestBody {
		return w.LinkRequest{Source: f.node(in.Oldnodeid), Parent: f.node(in.NodeId), Name: []byte(name)}
	})
	if s != 0 {
		return s
	}
	return f.entry(r, out, in.Opcode)
}
func (f *rawFS) Readlink(_ <-chan struct{}, h *fuse.InHeader) ([]byte, fuse.Status) {
	defer markCallbackPanic(h.Opcode)
	r, s := f.call(h, 0, func() w.RequestBody { return w.ReadlinkRequest{Node: f.node(h.NodeId)} })
	if s != 0 {
		return nil, s
	}
	return r.Reply.Body.(w.ReadlinkReply).Target, 0
}
func (f *rawFS) Rename(_ <-chan struct{}, in *fuse.RenameIn, old, new string) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.ack(&in.InHeader, 0, func() w.RequestBody {
		return w.RenameRequest{OldParent: f.node(in.NodeId), NewParent: f.node(in.Newdir), OldName: []byte(old), NewName: []byte(new), Flags: in.Flags}
	})
}
func (f *rawFS) Unlink(_ <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	defer markCallbackPanic(h.Opcode)
	return f.ack(h, 0, func() w.RequestBody { return w.UnlinkRequest{Parent: f.node(h.NodeId), Name: []byte(name)} })
}
func (f *rawFS) Rmdir(_ <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	defer markCallbackPanic(h.Opcode)
	return f.ack(h, 0, func() w.RequestBody { return w.RmdirRequest{Parent: f.node(h.NodeId), Name: []byte(name)} })
}
func (f *rawFS) Access(_ <-chan struct{}, in *fuse.AccessIn) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.ack(&in.InHeader, 0, func() w.RequestBody { return w.AccessRequest{Node: f.node(in.NodeId), Mask: in.Mask} })
}
func (f *rawFS) StatFs(_ <-chan struct{}, h *fuse.InHeader, out *fuse.StatfsOut) fuse.Status {
	defer markCallbackPanic(h.Opcode)
	*out = fuse.StatfsOut{}
	r, s := f.call(h, 0, func() w.RequestBody { return w.StatFSRequest{Node: f.node(h.NodeId)} })
	if s != 0 {
		return s
	}
	v := r.Reply.Body.(w.StatFSReply).Stat
	*out = fuse.StatfsOut{Blocks: v.Blocks, Bfree: v.BlocksFree, Bavail: v.BlocksAvailable, Files: v.Files, Ffree: v.FilesFree, Bsize: v.BlockSize, NameLen: v.NameLength, Frsize: v.FragmentSize}
	return 0
}
