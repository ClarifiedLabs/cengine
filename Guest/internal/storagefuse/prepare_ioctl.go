package storagefuse

import (
	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Ioctl implements only the fixed restricted PREPARE ioctl on an actual open
// root directory. Capture uses the exact unreplied Unique, never header UID/PID.
func (f *rawFS) Ioctl(_ <-chan struct{}, in *fuse.IoctlIn, input []byte, out *fuse.IoctlOut, output []byte) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	if in.Cmd != w.PrepareIoctl {
		return f.unsupported(&in.InHeader, fuse.Status(w.ErrnoENOTTY))
	}
	if out != nil {
		*out = fuse.IoctlOut{}
	}
	var request w.PrepareRequest
	r, status := f.call(&in.InHeader, 0, func() w.RequestBody {
		// DIR is required and is the only permitted flag: no compat,
		// unrestricted, retry, or future unrecognized ABI interpretation.
		if out == nil || in.Flags != fuse.IOCTL_DIR || in.InSize != w.PrepareIoctlSize || in.OutSize != w.PrepareIoctlSize || len(input) != w.PrepareIoctlSize || len(output) != w.PrepareIoctlSize || in.NodeId != 1 {
			return nil
		}
		var err error
		request, err = w.DecodePrepareIoctl(input)
		if err != nil {
			return nil
		}
		root, err := f.client.Node(c.LocalNode(1))
		if err != nil || root.Node == 0 || root.Attr.Mode&0170000 != 0040000 {
			return nil
		}
		grant, err := f.client.Handle(c.LocalHandle(in.Fh))
		if err != nil || grant.Handle == 0 || !grant.Directory || grant.Node != root.Node {
			return nil
		}
		request.Node, request.Handle = root.Node, grant.Handle
		return request
	})
	if status != fuse.OK {
		return status
	}
	reply, ok := r.Reply.Body.(w.PrepareReply)
	if !ok || w.ValidatePrepareReplyFor(request, reply) != nil {
		return f.bad()
	}
	encoded, err := w.EncodePrepareIoctlReply(reply)
	if err != nil {
		return f.bad()
	}
	copy(output, encoded)
	return fuse.OK
}
