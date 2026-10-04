package storagefuse

import (
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func (f *rawFS) Open(_ <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.OpenOut{}
	r, s := f.call(&in.InHeader, 0, func() w.RequestBody {
		flags, ok := openFlags(in.Flags, f.arch)
		if !ok {
			return nil
		}
		// Linux fuse_open_in.open_flags occupies go-fuse's legacy Mode field.
		return w.OpenRequest{Node: f.node(in.NodeId), Flags: flags, FuseOpenFlags: in.Mode}
	})
	if s != 0 {
		return s
	}
	return f.opened(r, out, in.Opcode)
}
func (f *rawFS) OpenDir(_ <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.OpenOut{}
	r, s := f.call(&in.InHeader, 0, func() w.RequestBody {
		flags, ok := openFlags(in.Flags, f.arch)
		if !ok || in.Mode != 0 {
			return nil
		}
		return w.OpenDirRequest{Node: f.node(in.NodeId), Flags: flags}
	})
	if s != 0 {
		return s
	}
	return f.opened(r, out, in.Opcode)
}
func (f *rawFS) Read(_ <-chan struct{}, in *fuse.ReadIn, _ []byte) (fuse.ReadResult, fuse.Status) {
	defer markCallbackPanic(in.Opcode)
	r, s := f.call(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		flags, ok := openFlags(in.Flags, f.arch)
		if !ok || in.ReadFlags&^uint32(fuse.READ_LOCKOWNER) != 0 {
			return nil
		}
		return w.ReadRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), Offset: in.Offset, Size: in.Size, IOFlags: flags}
	})
	if s != 0 {
		return nil, s
	}
	data := r.Reply.Body.(w.ReadReply).Data
	if len(data) > int(in.Size) {
		return nil, f.badAt(siteReplyReadSize, in.Opcode)
	}
	return fuse.ReadResultData(data), 0
}
func (f *rawFS) Write(_ <-chan struct{}, in *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	defer markCallbackPanic(in.Opcode)
	r, s := f.call(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		flags, ok := openFlags(in.Flags, f.arch)
		if !ok || in.Size != uint32(len(data)) || len(data) > w.MaxIO || in.WriteFlags & ^uint32(7) != 0 {
			return nil
		}
		// Keep the exact offset and CACHE. Legacy killpriv is rejected by wire
		// validation: ABI3 uses a separate semantic SETATTR. Never replay append or borrow
		// opener credentials. Client policy requires NONE OpenGrant for CACHE.
		return w.WriteRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), Offset: in.Offset, IOFlags: flags, WriteFlags: in.WriteFlags & ^uint32(fuse.WRITE_LOCKOWNER), Data: data}
	})
	if s != 0 {
		return 0, s
	}
	n := r.Reply.Body.(w.WriteReply).Written
	if n > in.Size {
		return 0, f.badAt(siteReplyWriteSize, in.Opcode)
	}
	return n, 0
}
func (f *rawFS) ReadDir(_ <-chan struct{}, in *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	r, s := f.call(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		if in.ReadFlags & ^uint32(fuse.READ_LOCKOWNER) != 0 {
			return nil
		}
		if _, ok := openFlags(in.Flags, f.arch); !ok {
			return nil
		}
		return w.ReadDirRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), Cookie: in.Offset, MaxBytes: in.Size}
	})
	if s != 0 {
		return s
	}
	for _, e := range r.Reply.Body.(w.ReadDirReply).Entries {
		if !out.AddDirEntry(fuse.DirEntry{Name: string(e.Name), Ino: e.Ino, Mode: e.Mode, Off: e.NextCookie}) {
			return f.badAt(siteReplyDirSize, in.Opcode)
		}
	}
	return 0
}
func (f *rawFS) Flush(_ <-chan struct{}, in *fuse.FlushIn) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.ack(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		return w.FlushRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh)}
	})
}
func (f *rawFS) Fsync(_ <-chan struct{}, in *fuse.FsyncIn) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.ack(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		if in.FsyncFlags & ^uint32(1) != 0 {
			return nil
		}
		return w.FsyncRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), DataOnly: in.FsyncFlags != 0}
	})
}
func (f *rawFS) FsyncDir(_ <-chan struct{}, in *fuse.FsyncIn) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.ack(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		if in.FsyncFlags & ^uint32(1) != 0 {
			return nil
		}
		return w.FsyncDirRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), DataOnly: in.FsyncFlags != 0}
	})
}
func (f *rawFS) Release(_ <-chan struct{}, in *fuse.ReleaseIn) {
	defer markCallbackPanic(in.Opcode)
	s := f.ack(&in.InHeader, w.LifecycleAuth, func() w.RequestBody {
		return w.ReleaseRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), ReleaseFlags: in.ReleaseFlags}
	})
	if s != 0 {
		f.badAt(siteReleaseStatus, in.Opcode)
	}
}
func (f *rawFS) ReleaseDir(in *fuse.ReleaseIn) {
	defer markCallbackPanic(in.Opcode)
	s := f.ack(&in.InHeader, w.LifecycleAuth, func() w.RequestBody {
		return w.ReleaseDirRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), ReleaseFlags: in.ReleaseFlags}
	})
	if s != 0 {
		f.badAt(siteReleaseStatus, in.Opcode)
	}
}
func (f *rawFS) Fallocate(_ <-chan struct{}, in *fuse.FallocateIn) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.ack(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		return w.FallocateRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), Offset: in.Offset, Length: in.Length, Mode: in.Mode}
	})
}
func (f *rawFS) Lseek(_ <-chan struct{}, in *fuse.LseekIn, out *fuse.LseekOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.LseekOut{}
	r, s := f.call(&in.InHeader, w.OpenGrantAuth, func() w.RequestBody {
		return w.LseekRequest{Node: f.node(in.NodeId), Handle: f.handle(in.NodeId, in.Fh), Offset: in.Offset, Whence: in.Whence}
	})
	if s != 0 {
		return s
	}
	out.Offset = r.Reply.Body.(w.LseekReply).Offset
	return 0
}
