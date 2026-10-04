package storagefuse

import (
	"context"
	"errors"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestGrantRepliesUseLocalIDsAndZeroCaching(t *testing.T) {
	f, fc := fixture()
	h := header()
	e := w.Entry{Node: 999, Generation: 7, Attr: w.Attr{Ino: 500, Mode: 0100644, Nlink: 0, UID: 123, GID: 456, ATime: w.Timestamp{Seconds: -2, Nanoseconds: 3}}}
	fc.result = &c.Result{Node: 2, Handle: 9, Reply: w.Reply{Body: w.CreateReply{Entry: e, Opened: w.Opened{Handle: 777}}}}
	out := fuse.CreateOut{EntryOut: fuse.EntryOut{EntryValid: 10, AttrValid: 10}, OpenOut: fuse.OpenOut{OpenFlags: 255, BackingID: 10}}
	if s := f.Create(nil, &fuse.CreateIn{InHeader: h, Flags: 0x42, Mode: 0644}, "x", &out); s != 0 {
		t.Fatal(s)
	}
	if out.NodeId != 2 || out.Fh != 9 || out.Ino != 500 || out.Generation != 7 || out.AttrValid != 0 || out.EntryValid != 0 || out.OpenFlags != 0 || out.BackingID != 0 || int64(out.Atime) != -2 || out.Uid != 123 || out.Nlink != 0 {
		t.Fatalf("%+v", out)
	}
}
func TestCountsErrnosAndXattrProbe(t *testing.T) {
	h := header()
	f, fc := fixture()
	fc.result = &c.Result{Reply: w.Reply{Errno: 61}}
	if _, s := f.GetXAttr(nil, &h, "user.a", nil); s != 61 {
		t.Fatal("Linux ENODATA must not become Darwin errno", s)
	}
	fc.result = &c.Result{Reply: w.Reply{Errno: w.ErrnoERANGE, Body: w.XAttrSizeError{Size: 99}}}
	if n, s := f.GetXAttr(nil, &h, "user.a", make([]byte, 1)); n != 99 || s != 34 {
		t.Fatal(n, s)
	}
	fc.result = &c.Result{Reply: w.Reply{Body: w.GetXAttrReply{Size: 99, Value: []byte{}}}}
	if n, s := f.GetXAttr(nil, &h, "user.a", nil); n != 99 || s != 0 {
		t.Fatal(n, s)
	}
	fc.result = &c.Result{Reply: w.Reply{Body: w.WriteReply{Written: 1}}}
	if n, s := f.Write(nil, &fuse.WriteIn{InHeader: h, Fh: 8, Flags: 2, Size: 2}, []byte("ab")); n != 1 || s != 0 {
		t.Fatal(n, s)
	}
	fc.result = &c.Result{Reply: w.Reply{Body: w.WriteReply{Written: 3}}}
	if n, s := f.Write(nil, &fuse.WriteIn{InHeader: h, Fh: 8, Flags: 2, Size: 2}, []byte("ab")); n != 0 || s != fuse.EIO || fc.aborted != 1 {
		t.Fatal(n, s)
	}
}
func TestDirectoryCookiesAndAttrDeviceRange(t *testing.T) {
	f, fc := fixture()
	h := header()
	fc.result = &c.Result{Reply: w.Reply{Body: w.ReadDirReply{Entries: []w.DirEntry{{Name: []byte("x"), Mode: 0100644, Ino: 55, NextCookie: 3}, {Name: []byte("y"), Mode: 0100644, Ino: 56, NextCookie: 2}}}}}
	out := fuse.NewDirEntryList(make([]byte, 128), 99)
	if s := f.ReadDir(nil, &fuse.ReadIn{InHeader: h, Fh: 8, Offset: 99, Size: 128}, out); s != 0 || out.Offset != 2 {
		t.Fatal(s, out.Offset)
	}
	if _, ok := attr(w.Attr{Rdev: 1 << 44}); ok {
		t.Fatal("unrepresentable device major")
	}
}
func TestBoundedCallbacksAndUnsupportedCapture(t *testing.T) {
	f, fc := fixture()
	h := header()
	f.slots <- struct{}{}
	f.slots <- struct{}{}
	if s := f.Lookup(nil, &h, "x", &fuse.EntryOut{}); s != fuse.EIO || fc.body != nil || fc.aborted != 1 {
		t.Fatal(s)
	}
	f, fc = fixture()
	if s := f.Ioctl(nil, &fuse.IoctlIn{InHeader: h}, nil, nil, nil); s != 25 || len(fc.captured) != 1 || fc.body != nil {
		t.Fatal(s, fc)
	}
	f, fc = fixture()
	fc.state = present
	f.Release(nil, &fuse.ReleaseIn{InHeader: h, Fh: 8})
	if fc.body != nil || fc.aborted != 1 {
		t.Fatal("release must be captured NONE lifecycle")
	}
}
func TestSetattrNow(t *testing.T) {
	f, fc := fixture()
	h := header()
	f.SetAttr(nil, &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{InHeader: h, Valid: fuse.FATTR_ATIME | fuse.FATTR_ATIME_NOW, Atime: 999}}, &fuse.AttrOut{})
	want := w.SetAttrRequest{Node: 101, Valid: w.SetATime | w.SetATimeNow, ATime: w.Timestamp{Seconds: 999}}
	if fc.validationErr != nil || !reflect.DeepEqual(fc.body, want) {
		t.Fatalf("%#v: %v", fc.body, fc.validationErr)
	}
}

func TestSetattrSizeDiscardsLockOwner(t *testing.T) {
	// Linux 6.18.44 fs/fuse/dir.c fuse_do_setattr always includes LOCKOWNER
	// for SIZE, including the FH ftruncate shape. ABI3 kills use the snapshot.
	for _, tc := range []struct {
		name  string
		flags uint32
	}{
		{"size", 0},
		{"size_handle", fuse.FATTR_FH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, fc := fixture()
			h := header()
			fc.result = &c.Result{Reply: w.Reply{Body: w.SetAttrReply{Attr: w.Attr{Ino: 500, Mode: 0100644, Size: 17}}}}
			in := fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{
				InHeader: h, Valid: fuse.FATTR_SIZE | fuse.FATTR_LOCKOWNER | tc.flags,
				Fh: 8, Size: 17, LockOwner: 0xfedcba9876543210,
			}}
			out := fuse.AttrOut{}
			if s := f.SetAttr(nil, &in, &out); s != fuse.OK {
				t.Fatalf("setattr: %v (wire validation: %v)", s, fc.validationErr)
			}
			want := w.SetAttrRequest{Node: 101, Valid: w.SetSize, Size: 17}
			if tc.flags&fuse.FATTR_FH != 0 {
				handle := w.HandleID(808)
				want.Handle = &handle
			}
			if !reflect.DeepEqual(fc.body, want) || fc.validationErr != nil || fc.aborted != 0 {
				t.Fatalf("got %#v, want %#v (validation: %v, aborts: %d)", fc.body, want, fc.validationErr, fc.aborted)
			}
			if fc.auth != 0 || !reflect.DeepEqual(fc.captured, []uint64{h.Unique}) || fc.fd != 77 {
				t.Fatal("setattr must retain captured caller authority", fc)
			}
			if out.Size != 17 || out.Ino != 500 {
				t.Fatalf("%+v", out)
			}
		})
	}
}

type fakeNotifier struct {
	nodes       []uint64
	off, length int64
	parents     []uint64
	name        string
	err         fuse.Status
}

func (k *fakeNotifier) InodeNotify(n uint64, off, length int64) fuse.Status {
	k.nodes = append(k.nodes, n)
	k.off = off
	k.length = length
	return k.err
}
func (k *fakeNotifier) EntryNotify(n uint64, name string) fuse.Status {
	k.parents = append(k.parents, n)
	k.name = name
	return k.err
}
func event(kind w.EventKind) w.Event {
	return w.Event{EventSequence: 1, Volume: a.ID("11111111-1111-4111-8111-111111111111"), Object: w.ObjectID{1}, Kind: kind, Name: []byte{}}
}
func TestNotificationUsesRecipientLocalIDs(t *testing.T) {
	k := &fakeNotifier{}
	e := event(w.InvalidateAttr)
	n := c.Notification{Event: e, Nodes: []c.LocalNode{3, 8}}
	if err := invalidate(context.Background(), k, n); err != nil || !reflect.DeepEqual(k.nodes, []uint64{3, 8}) || k.off != -1 {
		t.Fatal(k, err)
	}
	e = event(w.InvalidateData)
	e.Offset = 12
	e.Length = 0
	k = &fakeNotifier{}
	if err := invalidate(context.Background(), k, c.Notification{Event: e, Nodes: []c.LocalNode{8}}); err != nil || k.off != 12 || k.length != 0 {
		t.Fatal(k, err)
	}
	e = event(w.InvalidateEntry)
	e.Parent = w.ObjectID{2}
	e.Name = []byte("x\xff")
	k = &fakeNotifier{}
	if err := invalidate(context.Background(), k, c.Notification{Event: e, Nodes: []c.LocalNode{8}, Parents: []c.LocalNode{4}}); err != nil || !reflect.DeepEqual(k.parents, []uint64{4}) || k.name != "x\xff" || len(k.nodes) != 0 {
		t.Fatal(k, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	k = &fakeNotifier{}
	if err := invalidate(ctx, k, n); !errors.Is(err, context.Canceled) || len(k.nodes) != 0 {
		t.Fatal(k, err)
	}
	k = &fakeNotifier{err: fuse.EIO}
	if err := invalidate(context.Background(), k, n); err == nil {
		t.Fatal("notification failure ignored")
	}
}

func TestABI3RawSetattrShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid uint32
		want  w.SetAttrRequest
		ok    bool
	}{
		{"ctime_only", fuse.FATTR_CTIME, w.SetAttrRequest{Node: 101}, true},
		{"empty", 0, w.SetAttrRequest{Node: 101}, true},
		{"mtime_now", fuse.FATTR_MTIME | fuse.FATTR_MTIME_NOW, w.SetAttrRequest{Node: 101, Valid: w.SetMTime | w.SetMTimeNow, MTime: w.Timestamp{Seconds: -2, Nanoseconds: 9}}, true},
		{"atime_now_missing", fuse.FATTR_ATIME_NOW, w.SetAttrRequest{}, false},
		{"mtime_now_missing", fuse.FATTR_MTIME_NOW, w.SetAttrRequest{}, false},
		{"legacy_kill", fuse.FATTR_KILL_SUIDGID, w.SetAttrRequest{}, false},
		{"legacy_size_kill", fuse.FATTR_SIZE | fuse.FATTR_KILL_SUIDGID, w.SetAttrRequest{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, fc := fixture()
			h := header()
			fc.result = &c.Result{Reply: w.Reply{Body: w.SetAttrReply{Attr: w.Attr{Mode: 0100644}}}}
			in := fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{InHeader: h, Valid: tc.valid, Mtime: ^uint64(1), Mtimensec: 9, Ctime: 777, Ctimensec: 123}}
			status := f.SetAttr(nil, &in, &fuse.AttrOut{})
			if tc.ok {
				if status != fuse.OK || !reflect.DeepEqual(fc.body, tc.want) {
					t.Fatalf("%v %#v", status, fc.body)
				}
			} else if status != fuse.EINVAL || fc.body != nil {
				t.Fatalf("invalid raw flags forwarded: %v %#v", status, fc.body)
			}
		})
	}
}
