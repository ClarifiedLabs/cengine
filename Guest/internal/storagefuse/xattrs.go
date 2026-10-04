package storagefuse

import (
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func (f *rawFS) GetXAttr(_ <-chan struct{}, h *fuse.InHeader, name string, dest []byte) (uint32, fuse.Status) {
	defer markCallbackPanic(h.Opcode)
	r, s := f.call(h, 0, func() w.RequestBody {
		if len(dest) > w.MaxXAttr {
			return nil
		}
		return w.GetXAttrRequest{Node: f.node(h.NodeId), Name: []byte(name), Size: uint32(len(dest))}
	})
	if s != 0 {
		if e, ok := r.Reply.Body.(w.XAttrSizeError); ok {
			return e.Size, s
		}
		return 0, s
	}
	b := r.Reply.Body.(w.GetXAttrReply)
	if len(dest) > 0 && len(b.Value) > len(dest) {
		return 0, f.badAt(siteReplyXattrSize, h.Opcode)
	}
	copy(dest, b.Value)
	return b.Size, 0
}
func (f *rawFS) ListXAttr(_ <-chan struct{}, h *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	defer markCallbackPanic(h.Opcode)
	r, s := f.call(h, 0, func() w.RequestBody {
		if len(dest) > w.MaxXAttr {
			return nil
		}
		return w.ListXAttrRequest{Node: f.node(h.NodeId), Size: uint32(len(dest))}
	})
	if s != 0 {
		if e, ok := r.Reply.Body.(w.XAttrSizeError); ok {
			return e.Size, s
		}
		return 0, s
	}
	b := r.Reply.Body.(w.ListXAttrReply)
	if len(dest) > 0 && len(b.Names) > len(dest) {
		return 0, f.badAt(siteReplyXattrSize, h.Opcode)
	}
	copy(dest, b.Names)
	return b.Size, 0
}
func (f *rawFS) SetXAttr(_ <-chan struct{}, in *fuse.SetXAttrIn, name string, data []byte) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.ack(&in.InHeader, 0, func() w.RequestBody {
		if len(data) > w.MaxXAttr || uint32(len(data)) != in.Size {
			return nil
		}
		return w.SetXAttrRequest{Node: f.node(in.NodeId), Name: []byte(name), Value: data, Flags: in.Flags}
	})
}
func (f *rawFS) RemoveXAttr(_ <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	defer markCallbackPanic(h.Opcode)
	return f.ack(h, 0, func() w.RequestBody { return w.RemoveXAttrRequest{Node: f.node(h.NodeId), Name: []byte(name)} })
}

// Unsupported callbacks still capture before returning a FUSE error. Locks remain
// kernel-local (EnableLocks=false); no distributed lock authority is invented.
func (f *rawFS) unsupported(h *fuse.InHeader, status fuse.Status) fuse.Status {
	defer markCallbackPanic(h.Opcode)
	_, s := f.call(h, 0, func() w.RequestBody { return nil })
	if s == fuse.EINVAL {
		return status
	}
	return s
}
func (f *rawFS) ReadDirPlus(_ <-chan struct{}, in *fuse.ReadIn, _ *fuse.DirEntryList) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.unsupported(&in.InHeader, fuse.ENOSYS)
}
func (f *rawFS) CopyFileRange(_ <-chan struct{}, in *fuse.CopyFileRangeIn) (uint32, fuse.Status) {
	defer markCallbackPanic(in.Opcode)
	return 0, f.unsupported(&in.InHeader, fuse.ENOSYS)
}
func (f *rawFS) GetLk(_ <-chan struct{}, in *fuse.LkIn, _ *fuse.LkOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.unsupported(&in.InHeader, fuse.ENOSYS)
}
func (f *rawFS) SetLk(_ <-chan struct{}, in *fuse.LkIn) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.unsupported(&in.InHeader, fuse.ENOSYS)
}
func (f *rawFS) SetLkw(_ <-chan struct{}, in *fuse.LkIn) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.unsupported(&in.InHeader, fuse.ENOSYS)
}
func (f *rawFS) Statx(_ <-chan struct{}, in *fuse.StatxIn, _ *fuse.StatxOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	return f.unsupported(&in.InHeader, fuse.ENOSYS)
}
