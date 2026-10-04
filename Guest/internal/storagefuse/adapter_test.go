package storagefuse

import (
	"errors"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type fakeClient struct {
	state                            uint8
	captured                         []uint64
	fd                               int
	body                             w.RequestBody
	auth                             w.AuthKind
	result                           *c.Result
	captureErr, errorDo, errorForget error
	validationErr                    error
	aborted                          int
	forgotten                        uint64
}

func (fc *fakeClient) Capture(fd int, u uint64) (credential, error) {
	fc.fd = fd
	fc.captured = append(fc.captured, u)
	return credential{state: fc.state}, fc.captureErr
}
func (fc *fakeClient) Do(_ credential, auth w.AuthKind, b w.RequestBody) (c.Result, error) {
	fc.body = b
	fc.auth = auth
	if fc.errorDo != nil {
		return c.Result{}, fc.errorDo
	}
	wa := w.Auth{Kind: auth}
	if auth == 0 {
		wa = w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{FSUID: 123, FSGID: 456, Groups: []uint32{}}}
	}
	// Model only the stamping boundary for translation tests. Real capture/Do
	// provenance is independently covered in storageclient; fc.body stays raw.
	if v, ok := b.(w.SetAttrRequest); ok {
		v.Semantics = w.MetadataValid
		b = v
	}
	if err := (w.Request{Sequence: 1, Auth: wa, Body: b}).ValidatePolicy(a.ReadWrite); err != nil {
		fc.validationErr = err
		return c.Result{}, err
	}
	if fc.result != nil {
		return *fc.result, nil
	}
	return c.Result{Reply: w.Reply{Sequence: 1, Op: b.Operation(), Errno: 13}}, nil
}
func (fc *fakeClient) Node(id c.LocalNode) (w.Entry, error) {
	if id < 1 || id > 3 {
		return w.Entry{}, c.ErrGrant
	}
	return w.Entry{Node: w.NodeID(100 + id)}, nil
}
func (fc *fakeClient) Handle(id c.LocalHandle) (c.HandleGrant, error) {
	if id != 8 {
		return c.HandleGrant{}, c.ErrGrant
	}
	return c.HandleGrant{Node: 101, Handle: 808, Flags: w.OpenReadWrite}, nil
}
func (fc *fakeClient) Forget(id c.LocalNode, count uint64) error {
	fc.forgotten = count
	return fc.errorForget
}
func (fc *fakeClient) Abort(error) { fc.aborted++ }
func fixture() (*rawFS, *fakeClient) {
	fc := &fakeClient{state: present}
	return &rawFS{RawFileSystem: fuse.NewDefaultRawFileSystem(), client: fc, fd: 77, arch: "arm64", slots: make(chan struct{}, 2)}, fc
}
func header() fuse.InHeader {
	return fuse.InHeader{NodeId: 1, Unique: 0xfedcba9876543210, Caller: fuse.Caller{Owner: fuse.Owner{Uid: 0, Gid: 0}, Pid: 999}}
}

func TestAllWireCallbacksCaptureAndRemap(t *testing.T) {
	h := header()
	name := "raw\xff"
	tests := []struct {
		want w.RequestBody
		call func(*rawFS)
	}{
		{w.LookupRequest{Parent: 101, Name: []byte(name)}, func(f *rawFS) { f.Lookup(nil, &h, name, &fuse.EntryOut{}) }},
		{w.GetAttrRequest{Node: 101}, func(f *rawFS) { f.GetAttr(nil, &fuse.GetAttrIn{InHeader: h}, &fuse.AttrOut{}) }},
		{w.SetAttrRequest{Node: 101, Valid: w.SetMode, Mode: 0600}, func(f *rawFS) {
			f.SetAttr(nil, &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{InHeader: h, Valid: fuse.FATTR_MODE, Mode: 0100600}}, &fuse.AttrOut{})
		}},
		{w.CreateRequest{Parent: 101, Name: []byte(name), Flags: w.OpenCreate | w.OpenReadWrite | w.OpenTruncate, FuseOpenFlags: 0, Mode: 06755, Umask: 0027}, func(f *rawFS) {
			f.Create(nil, &fuse.CreateIn{InHeader: h, Flags: 0x242, Padding: 0, Mode: 06755, Umask: 0027}, name, &fuse.CreateOut{})
		}},
		{w.OpenRequest{Node: 101, Flags: w.OpenReadWrite, FuseOpenFlags: 0}, func(f *rawFS) { f.Open(nil, &fuse.OpenIn{InHeader: h, Flags: 0x2, Mode: 0}, &fuse.OpenOut{}) }},
		{w.ReadRequest{Node: 101, Handle: 808, Offset: 7, Size: 2, IOFlags: 2}, func(f *rawFS) {
			f.Read(nil, &fuse.ReadIn{InHeader: h, Fh: 8, Offset: 7, Size: 2, Flags: 2, ReadFlags: fuse.READ_LOCKOWNER}, nil)
		}},
		{w.WriteRequest{Node: 101, Handle: 808, Offset: 7, IOFlags: 2, WriteFlags: 0, Data: []byte("ab")}, func(f *rawFS) {
			f.Write(nil, &fuse.WriteIn{InHeader: h, Fh: 8, Offset: 7, Size: 2, Flags: 2, WriteFlags: 2}, []byte("ab"))
		}},
		{w.FlushRequest{Node: 101, Handle: 808}, func(f *rawFS) { f.Flush(nil, &fuse.FlushIn{InHeader: h, Fh: 8}) }},
		{w.FsyncRequest{Node: 101, Handle: 808, DataOnly: true}, func(f *rawFS) { f.Fsync(nil, &fuse.FsyncIn{InHeader: h, Fh: 8, FsyncFlags: 1}) }},
		{w.FsyncDirRequest{Node: 101, Handle: 808, DataOnly: true}, func(f *rawFS) { f.FsyncDir(nil, &fuse.FsyncIn{InHeader: h, Fh: 8, FsyncFlags: 1}) }},
		{w.ReleaseRequest{Node: 101, Handle: 808, ReleaseFlags: 1}, func(f *rawFS) { f.Release(nil, &fuse.ReleaseIn{InHeader: h, Fh: 8, ReleaseFlags: 1}) }},
		{w.ReleaseDirRequest{Node: 101, Handle: 808}, func(f *rawFS) { f.ReleaseDir(&fuse.ReleaseIn{InHeader: h, Fh: 8}) }},
		{w.OpenDirRequest{Node: 101, Flags: w.OpenDirectory}, func(f *rawFS) { f.OpenDir(nil, &fuse.OpenIn{InHeader: h, Flags: 0x4000}, &fuse.OpenOut{}) }},
		{w.ReadDirRequest{Node: 101, Handle: 808, Cookie: 44, MaxBytes: 128}, func(f *rawFS) {
			f.ReadDir(nil, &fuse.ReadIn{InHeader: h, Fh: 8, Offset: 44, Size: 128}, fuse.NewDirEntryList(make([]byte, 128), 44))
		}},
		{w.MkdirRequest{Parent: 101, Name: []byte(name), Mode: 02775, Umask: 0027}, func(f *rawFS) {
			f.Mkdir(nil, &fuse.MkdirIn{InHeader: h, Mode: 02775, Umask: 0027}, name, &fuse.EntryOut{})
		}},
		{w.MknodRequest{Parent: 101, Name: []byte(name), Mode: 0020600, Umask: 0027, Rdev: 0x103}, func(f *rawFS) {
			f.Mknod(nil, &fuse.MknodIn{InHeader: h, Mode: 0020600, Umask: 0027, Rdev: 0x103}, name, &fuse.EntryOut{})
		}},
		{w.SymlinkRequest{Parent: 101, Name: []byte(name), Target: []byte("../target")}, func(f *rawFS) { f.Symlink(nil, &h, "../target", name, &fuse.EntryOut{}) }},
		{w.ReadlinkRequest{Node: 101}, func(f *rawFS) { f.Readlink(nil, &h) }},
		{w.LinkRequest{Source: 103, Parent: 101, Name: []byte(name)}, func(f *rawFS) { f.Link(nil, &fuse.LinkIn{InHeader: h, Oldnodeid: 3}, name, &fuse.EntryOut{}) }},
		{w.RenameRequest{OldParent: 101, NewParent: 102, OldName: []byte(name), NewName: []byte("new"), Flags: 2}, func(f *rawFS) { f.Rename(nil, &fuse.RenameIn{InHeader: h, Newdir: 2, Flags: 2}, name, "new") }},
		{w.UnlinkRequest{Parent: 101, Name: []byte(name)}, func(f *rawFS) { f.Unlink(nil, &h, name) }},
		{w.RmdirRequest{Parent: 101, Name: []byte(name)}, func(f *rawFS) { f.Rmdir(nil, &h, name) }},
		{w.AccessRequest{Node: 101, Mask: 4}, func(f *rawFS) { f.Access(nil, &fuse.AccessIn{InHeader: h, Mask: 4}) }},
		{w.GetXAttrRequest{Node: 101, Name: []byte("user.a"), Size: 4}, func(f *rawFS) { f.GetXAttr(nil, &h, "user.a", make([]byte, 4)) }},
		{w.ListXAttrRequest{Node: 101, Size: 4}, func(f *rawFS) { f.ListXAttr(nil, &h, make([]byte, 4)) }},
		{w.SetXAttrRequest{Node: 101, Name: []byte("user.a"), Value: []byte("a"), Flags: 1}, func(f *rawFS) {
			f.SetXAttr(nil, &fuse.SetXAttrIn{InHeader: h, Size: 1, Flags: 1}, "user.a", []byte("a"))
		}},
		{w.RemoveXAttrRequest{Node: 101, Name: []byte("user.a")}, func(f *rawFS) { f.RemoveXAttr(nil, &h, "user.a") }},
		{w.StatFSRequest{Node: 101}, func(f *rawFS) { f.StatFs(nil, &h, &fuse.StatfsOut{}) }},
		{w.FallocateRequest{Node: 101, Handle: 808, Offset: 8, Length: 9, Mode: 3}, func(f *rawFS) { f.Fallocate(nil, &fuse.FallocateIn{InHeader: h, Fh: 8, Offset: 8, Length: 9, Mode: 3}) }},
		{w.LseekRequest{Node: 101, Handle: 808, Offset: 8, Whence: 3}, func(f *rawFS) {
			f.Lseek(nil, &fuse.LseekIn{InHeader: h, Fh: 8, Offset: 8, Whence: 3}, &fuse.LseekOut{})
		}},
	}
	if len(tests) != 30 {
		t.Fatal("operation coverage changed")
	}
	for _, tc := range tests {
		t.Run(string(tc.want.Operation()), func(t *testing.T) {
			f, fc := fixture()
			op := tc.want.Operation()
			if op == w.OpRelease || op == w.OpReleaseDir {
				fc.state = none
			}
			tc.call(f)
			if fc.validationErr != nil {
				t.Fatal(fc.validationErr)
			}
			if !reflect.DeepEqual(fc.body, tc.want) {
				t.Fatalf("got %#v want %#v", fc.body, tc.want)
			}
			if !reflect.DeepEqual(fc.captured, []uint64{h.Unique}) || fc.fd != 77 {
				t.Fatal(fc.captured, fc.fd)
			}
		})
	}
	f, fc := fixture()
	f.Forget(2, 9)
	if fc.forgotten != 9 || len(fc.captured) != 0 || fc.body != nil {
		t.Fatal("FORGET must be local no-reply bookkeeping")
	}
}
func TestCredentialFailuresNeverBecomeNone(t *testing.T) {
	h := header()
	for _, state := range []uint8{0, 3, none} {
		f, fc := fixture()
		fc.state = state
		if f.Lookup(nil, &h, "x", &fuse.EntryOut{}) != fuse.EIO || fc.body != nil || fc.aborted != 1 {
			t.Fatal(state, fc)
		}
	}
	f, fc := fixture()
	fc.captureErr = errors.New("ioctl")
	f.GetAttr(nil, &fuse.GetAttrIn{InHeader: h}, &fuse.AttrOut{})
	if fc.body != nil || fc.aborted != 1 {
		t.Fatal(fc)
	}
}
func TestExplicitNoneAndCacheWrite(t *testing.T) {
	h := header()
	f, fc := fixture()
	fc.state = none
	f.GetAttr(nil, &fuse.GetAttrIn{InHeader: h}, &fuse.AttrOut{})
	if fc.auth != w.NodeMetadataAuth {
		t.Fatal(fc.auth)
	}
	f.GetAttr(nil, &fuse.GetAttrIn{InHeader: h, Flags_: 1, Fh_: 8}, &fuse.AttrOut{})
	if fc.auth != w.OpenGrantAuth || *fc.body.(w.GetAttrRequest).Handle != 808 {
		t.Fatal(fc.body)
	}
	f.Write(nil, &fuse.WriteIn{InHeader: h, Fh: 8, Size: 1, Offset: 999, Flags: 0x402, WriteFlags: 1}, []byte("a"))
	if fc.auth != w.OpenGrantAuth || fc.body.(w.WriteRequest).Offset != 999 || fc.body.(w.WriteRequest).WriteFlags != 1 {
		t.Fatal(fc.body)
	}
	f, fc = fixture()
	f.Write(nil, &fuse.WriteIn{InHeader: h, Fh: 8, Size: 1, WriteFlags: 1}, []byte("a"))
	if fc.body != nil || fc.aborted != 1 {
		t.Fatal("PRESENT cache write")
	}
}
func TestCanceledChannelDoesNotCancelRPC(t *testing.T) {
	f, fc := fixture()
	ch := make(chan struct{})
	close(ch)
	h := header()
	f.Lookup(ch, &h, "x", &fuse.EntryOut{})
	if fc.body == nil {
		t.Fatal("canceled after admission")
	}
}
func TestAbortRetireOnceAndNoReuse(t *testing.T) {
	f, fc := fixture()
	aborts, retires := 0, 0
	f.abortMount = func(error) { aborts++ }
	f.retire = func(error) { retires++ }
	f.deliveryFailed(99, errors.New("discarded grant"))
	f.OnUnmount()
	f.deliveryFailed(100, errors.New("again"))
	h := header()
	f.Lookup(nil, &h, "x", &fuse.EntryOut{})
	if fc.aborted != 1 || aborts != 1 || retires != 1 || fc.body != nil {
		t.Fatal(fc, aborts, retires)
	}
}
