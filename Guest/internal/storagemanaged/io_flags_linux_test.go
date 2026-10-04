//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
	"testing"
)

func TestPerRequestDirectFlagCanBeClearedAndReenabled(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("direct"), Flags: w.OpenReadWrite | w.OpenDirect, Mode: 0600}).(w.CreateReply)
	n, h := c.Entry.Node, c.Opened.Handle
	// A buffered odd-sized request must clear the original O_DIRECT, not merely
	// pass validation and let a stale backing-open flag reject it with EINVAL.
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, Data: []byte("abc")})
	got := f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, Size: 3}).(w.ReadReply)
	if string(got.Data) != "abc" {
		t.Fatal(got)
	}
	flags, err := unix.FcntlInt(uintptr(s.handles[h].fd), unix.F_GETFL, 0)
	must(t, err)
	if flags&unix.O_DIRECT != 0 {
		t.Fatal("O_DIRECT not cleared")
	}
	f.call(s, auth, w.WriteRequest{Node: n, Handle: h, IOFlags: w.OpenReadWrite | w.OpenDirect, Data: make([]byte, 4096)})
	flags, err = unix.FcntlInt(uintptr(s.handles[h].fd), unix.F_GETFL, 0)
	must(t, err)
	if flags&unix.O_DIRECT == 0 {
		t.Fatal("O_DIRECT not reenabled")
	}
	if s.handles[h].flags&w.OpenDirect == 0 || s.handles[h].flags&w.OpenAccessMask != w.OpenReadWrite {
		t.Fatal("original grant was rewritten")
	}
	f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, Size: 1}) // clear it again
}
func TestNoAtimeMutableFlagUsesCallerOwnershipNotServiceIdentity(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("noatime"), Flags: w.OpenReadWrite | w.OpenNoATime, Mode: 0666}).(w.CreateReply)
	n, h := c.Entry.Node, c.Opened.Handle
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Data: []byte("read")})
	// Make relatime updates eligible. Keeping an authorized NOATIME status must
	// preserve atime; clearing it must really let the next read update atime.
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataTimesSet, Valid: w.SetATime | w.SetMTime, ATime: w.Timestamp{Seconds: 1}, MTime: w.Timestamp{Seconds: 2}})
	f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Size: 4})
	st := f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	if st.ATime.Seconds != 1 {
		t.Fatal("NOATIME lost", st)
	}
	f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, Size: 4})
	flags, err := unix.FcntlInt(uintptr(s.handles[h].fd), unix.F_GETFL, 0)
	must(t, err)
	if flags&unix.O_NOATIME != 0 {
		t.Fatal("NOATIME not cleared")
	}
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(s.handles[h].fd, &fs))
	if fs.Flags&unix.ST_NOATIME == 0 {
		st = f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
		if st.ATime.Seconds == 1 {
			t.Fatal("clearing NOATIME did not restore native atime updates")
		}
	}
	// A grant without caller identity may not rely on service UID (even UID 0).
	f.wantError(s, grantAuth, w.ReadRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Size: 4}, unix.EPERM)
	f.wantError(s, caller(1002, 1002), w.ReadRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Size: 4}, unix.EPERM)
	f.wantError(s, caller(0, 0), w.ReadRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Size: 4}, unix.EPERM)
	f.call(s, auth, w.ReadRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Size: 4})
	// Ownership changed after open: caller status changes must recheck the owner,
	// not the immutable opener credentials stored nowhere in the grant.
	must(t, unix.Fchown(s.handles[h].fd, 1002, 1002))
	f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, Size: 1})
	f.wantError(s, auth, w.ReadRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Size: 1}, unix.EPERM)
	f.call(s, caller(1002, 1002), w.ReadRequest{Node: n, Handle: h, IOFlags: w.OpenNoATime, Size: 1})
	rootOwned := f.call(s, caller(0, 0), w.CreateRequest{Parent: root.Node, Name: []byte("root-owned"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	f.wantError(s, grantAuth, w.ReadRequest{Node: rootOwned.Entry.Node, Handle: rootOwned.Opened.Handle, IOFlags: w.OpenNoATime, Size: 1}, unix.EPERM)
}
