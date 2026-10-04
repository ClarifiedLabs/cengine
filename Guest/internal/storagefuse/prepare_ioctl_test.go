package storagefuse

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type prepareClient struct {
	*fakeClient
	root     w.Entry
	grant    c.HandleGrant
	grantErr error
}

func (p *prepareClient) Node(id c.LocalNode) (w.Entry, error) {
	if id != 1 {
		return w.Entry{}, c.ErrGrant
	}
	return p.root, nil
}
func (p *prepareClient) Handle(id c.LocalHandle) (c.HandleGrant, error) {
	if id != 8 {
		return c.HandleGrant{}, c.ErrGrant
	}
	return p.grant, p.grantErr
}
func prepareIoctlFixture(t *testing.T) (*rawFS, *prepareClient, fuse.IoctlIn, []byte) {
	t.Helper()
	f, fc := fixture()
	fc.result = &c.Result{Reply: w.Reply{Sequence: 1, Op: w.OpPrepare, Body: w.PrepareReply{}}}
	pc := &prepareClient{fakeClient: fc, root: w.Entry{Node: 101, Attr: w.Attr{Mode: 0040700}}, grant: c.HandleGrant{Node: 101, Handle: 808, Directory: true}}
	f.client = pc
	input, err := w.EncodePrepareIoctl(w.PrepareRequest{Action: w.FinishCopy, Intent: "11111111-1111-4111-8111-111111111111"})
	if err != nil {
		t.Fatal(err)
	}
	h := header()
	h.Opcode = 39
	in := fuse.IoctlIn{InHeader: h, Fh: 8, Flags: fuse.IOCTL_DIR, Cmd: w.PrepareIoctl, InSize: w.PrepareIoctlSize, OutSize: w.PrepareIoctlSize}
	return f, pc, in, input
}
func TestPrepareIoctlCapturesExactUniqueAndRootGrant(t *testing.T) {
	f, pc, in, input := prepareIoctlFixture(t)
	out := fuse.IoctlOut{Result: 9, Flags: 7, InIovs: 2, OutIovs: 3}
	output := bytes.Repeat([]byte{255}, w.PrepareIoctlSize)
	if status := f.Ioctl(nil, &in, input, &out, output); status != fuse.OK {
		t.Fatal(status)
	}
	if out != (fuse.IoctlOut{}) {
		t.Fatal(out)
	}
	if !reflect.DeepEqual(pc.captured, []uint64{in.Unique}) || pc.fd != 77 || pc.auth != 0 {
		t.Fatal(pc.fakeClient)
	}
	body := pc.body.(w.PrepareRequest)
	if body.Node != 101 || body.Handle != 808 || body.Action != w.FinishCopy {
		t.Fatal(body)
	}
	if _, err := w.DecodePrepareIoctlReply(output); err != nil {
		t.Fatal(err)
	}
}
func TestPrepareIoctlRejectsABIAndForeignGrantsAfterCapture(t *testing.T) {
	cases := map[string]func(*prepareClient, *fuse.IoctlIn, *[]byte, *[]byte){
		"not root":        func(_ *prepareClient, in *fuse.IoctlIn, _ *[]byte, _ *[]byte) { in.NodeId = 2 },
		"missing handle":  func(_ *prepareClient, in *fuse.IoctlIn, _ *[]byte, _ *[]byte) { in.Fh = 0 },
		"foreign handle":  func(p *prepareClient, _ *fuse.IoctlIn, _ *[]byte, _ *[]byte) { p.grant.Node++ },
		"file handle":     func(p *prepareClient, _ *fuse.IoctlIn, _ *[]byte, _ *[]byte) { p.grant.Directory = false },
		"file root":       func(p *prepareClient, _ *fuse.IoctlIn, _ *[]byte, _ *[]byte) { p.root.Attr.Mode = 0100600 },
		"released handle": func(p *prepareClient, _ *fuse.IoctlIn, _ *[]byte, _ *[]byte) { p.grantErr = c.ErrGrant },
		"zero grant":      func(p *prepareClient, _ *fuse.IoctlIn, _ *[]byte, _ *[]byte) { p.grant.Handle = 0 },
		"short input":     func(_ *prepareClient, _ *fuse.IoctlIn, b *[]byte, _ *[]byte) { *b = (*b)[:len(*b)-1] },
		"short output":    func(_ *prepareClient, _ *fuse.IoctlIn, _ *[]byte, b *[]byte) { *b = (*b)[:len(*b)-1] },
		"input size":      func(_ *prepareClient, in *fuse.IoctlIn, _ *[]byte, _ *[]byte) { in.InSize-- },
		"output size":     func(_ *prepareClient, in *fuse.IoctlIn, _ *[]byte, _ *[]byte) { in.OutSize++ },
		"tail":            func(_ *prepareClient, _ *fuse.IoctlIn, b *[]byte, _ *[]byte) { (*b)[len(*b)-1] = 1 },
	}
	for _, flag := range []uint32{0, fuse.IOCTL_COMPAT, fuse.IOCTL_UNRESTRICTED, fuse.IOCTL_RETRY, 1 << 31} {
		t.Run("flags", func(t *testing.T) {
			f, pc, in, input := prepareIoctlFixture(t)
			in.Flags = flag | fuse.IOCTL_DIR
			if flag == 0 {
				in.Flags = 0
			}
			if f.Ioctl(nil, &in, input, &fuse.IoctlOut{}, make([]byte, w.PrepareIoctlSize)) != fuse.EINVAL || pc.body != nil || len(pc.captured) != 1 {
				t.Fatal(flag, pc)
			}
		})
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f, pc, in, input := prepareIoctlFixture(t)
			output := make([]byte, w.PrepareIoctlSize)
			change(pc, &in, &input, &output)
			if f.Ioctl(nil, &in, input, &fuse.IoctlOut{}, output) != fuse.EINVAL || pc.body != nil || !reflect.DeepEqual(pc.captured, []uint64{in.Unique}) {
				t.Fatal(pc)
			}
		})
	}
}
func TestPrepareIoctlUnknownAndCredentialFailures(t *testing.T) {
	f, pc, in, input := prepareIoctlFixture(t)
	in.Cmd++
	if f.Ioctl(nil, &in, input, &fuse.IoctlOut{}, nil) != 25 || pc.body != nil || len(pc.captured) != 1 {
		t.Fatal(pc)
	}
	for _, missing := range []bool{false, true} {
		f, pc, in, input = prepareIoctlFixture(t)
		if missing {
			pc.state = none
		} else {
			pc.captureErr = errors.New("capture failed")
		}
		if f.Ioctl(nil, &in, input, &fuse.IoctlOut{}, make([]byte, w.PrepareIoctlSize)) != fuse.EIO || pc.body != nil || pc.aborted != 1 {
			t.Fatal(pc)
		}
	}
}
