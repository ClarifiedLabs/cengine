//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

var grantAuth = w.Auth{Kind: w.OpenGrantAuth}
var lifecycle = w.Auth{Kind: w.LifecycleAuth}
var metadata = w.Auth{Kind: w.NodeMetadataAuth}

func TestEveryOperationAndRetainedUnlinkedData(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	created := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("file"), Flags: w.OpenReadWrite | w.OpenCreate, Mode: 0666, Umask: 0027}).(w.CreateReply)
	n, h := created.Entry.Node, created.Opened.Handle
	if created.Entry.Attr.Mode&0777 != 0640 {
		t.Fatal("umask", created.Entry.Attr)
	}
	lookup := f.call(s, auth, w.LookupRequest{Parent: root.Node, Name: []byte("file")}).(w.LookupReply)
	if lookup.Entry.Node != n || lookup.Entry.Object != created.Entry.Object {
		t.Fatal("inode was not interned")
	}
	f.call(s, auth, w.AccessRequest{Node: n, Mask: 6})
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, IOFlags: w.OpenReadWrite, Data: []byte("hello")})
	read := f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, Size: 10}).(w.ReadReply)
	if string(read.Data) != "hello" {
		t.Fatal(string(read.Data))
	}
	f.call(s, grantAuth, w.FlushRequest{Node: n, Handle: h})
	f.call(s, grantAuth, w.FsyncRequest{Node: n, Handle: h, DataOnly: true})
	f.call(s, grantAuth, w.FallocateRequest{Node: n, Handle: h, Offset: 0, Length: 4096, Mode: w.FallocateKeepSize})
	seek := f.call(s, grantAuth, w.LseekRequest{Node: n, Handle: h, Whence: w.SeekData}).(w.LseekReply)
	if seek.Offset != 0 {
		t.Fatal(seek)
	}
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetSize, Size: 3})
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 0600})
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataTimesSet, Valid: w.SetATime | w.SetMTime, ATime: w.Timestamp{Seconds: 42}, MTime: w.Timestamp{Seconds: 43}})
	st := f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	if st.Size != 3 || st.Mode&0777 != 0600 || st.ATime.Seconds != 42 || st.MTime.Seconds != 43 {
		t.Fatal(st)
	}
	f.call(s, auth, w.SetXAttrRequest{Node: n, Name: []byte("user.raw"), Value: []byte{0, 255, 1}, Flags: w.XAttrCreate})
	probe := f.call(s, auth, w.GetXAttrRequest{Node: n, Name: []byte("user.raw")}).(w.GetXAttrReply)
	if probe.Size != 3 || len(probe.Value) != 0 {
		t.Fatal(probe)
	}
	f.wantError(s, auth, w.GetXAttrRequest{Node: n, Name: []byte("user.raw"), Size: 1}, unix.ERANGE)
	value := f.call(s, auth, w.GetXAttrRequest{Node: n, Name: []byte("user.raw"), Size: 3}).(w.GetXAttrReply)
	if !bytes.Equal(value.Value, []byte{0, 255, 1}) {
		t.Fatal(value)
	}
	list := f.call(s, auth, w.ListXAttrRequest{Node: n, Size: 65536}).(w.ListXAttrReply)
	if !bytes.Contains(list.Names, []byte("user.raw\x00")) {
		t.Fatal(list)
	}
	f.call(s, auth, w.RemoveXAttrRequest{Node: n, Name: []byte("user.raw")})
	f.wantError(s, auth, w.GetXAttrRequest{Node: n, Name: []byte("user.raw")}, unix.ENODATA)
	f.call(s, auth, w.StatFSRequest{Node: n})
	dir := f.call(s, auth, w.MkdirRequest{Parent: root.Node, Name: []byte("dir"), Mode: 0777, Umask: 0077}).(w.MkdirReply).Entry
	dh := f.call(s, auth, w.OpenDirRequest{Node: dir.Node, Flags: w.OpenDirectory}).(w.OpenDirReply).Opened.Handle
	f.call(s, auth, w.SetXAttrRequest{Node: dir.Node, Name: []byte("user.dir"), Value: []byte{}})
	f.call(s, auth, w.GetXAttrRequest{Node: dir.Node, Name: []byte("user.dir"), Size: 1})
	f.call(s, auth, w.ListXAttrRequest{Node: dir.Node, Size: 65536})
	f.call(s, auth, w.RemoveXAttrRequest{Node: dir.Node, Name: []byte("user.dir")})
	f.call(s, grantAuth, w.ReadDirRequest{Node: dir.Node, Handle: dh, MaxBytes: 128})
	f.call(s, grantAuth, w.FsyncDirRequest{Node: dir.Node, Handle: dh})
	f.call(s, lifecycle, w.ReleaseDirRequest{Node: dir.Node, Handle: dh})
	fifo := f.call(s, auth, w.MknodRequest{Parent: root.Node, Name: []byte("fifo"), Mode: unix.S_IFIFO | 0600}).(w.MknodReply).Entry
	f.wantError(s, auth, w.OpenRequest{Node: fifo.Node}, unix.EPERM)
	link := f.call(s, auth, w.SymlinkRequest{Parent: root.Node, Name: []byte("sym"), Target: []byte("/outside/target")}).(w.SymlinkReply).Entry
	target := f.call(s, auth, w.ReadlinkRequest{Node: link.Node}).(w.ReadlinkReply)
	if string(target.Target) != "/outside/target" {
		t.Fatal(target)
	}
	f.wantError(s, auth, w.OpenRequest{Node: link.Node}, unix.ELOOP)
	f.call(s, auth, w.LinkRequest{Source: link.Node, Parent: root.Node, Name: []byte("sym2")})
	f.call(s, auth, w.LinkRequest{Source: n, Parent: root.Node, Name: []byte("alias")})
	f.call(s, auth, w.RenameRequest{OldParent: root.Node, OldName: []byte("file"), NewParent: dir.Node, NewName: []byte("moved"), Flags: w.RenameNoReplace})
	f.call(s, auth, w.UnlinkRequest{Parent: root.Node, Name: []byte("alias")})
	f.call(s, auth, w.UnlinkRequest{Parent: dir.Node, Name: []byte("moved")})
	st = f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	if st.Nlink != 0 {
		t.Fatal("fabricated nlink", st.Nlink)
	}
	opened := f.call(s, auth, w.OpenRequest{Node: n, Flags: w.OpenReadWrite}).(w.OpenReply).Opened.Handle
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: opened, Offset: 1, IOFlags: w.OpenReadWrite, Data: []byte("Z")})
	read = f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, Size: 10}).(w.ReadReply)
	if string(read.Data) != "hZl" {
		t.Fatal(string(read.Data))
	}
	f.call(s, lifecycle, w.ReleaseRequest{Node: n, Handle: opened})
	f.call(s, lifecycle, w.ReleaseRequest{Node: n, Handle: h, ReleaseFlags: w.ReleaseFlush})
	st = f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	if st.Nlink != 0 {
		t.Fatal(st)
	}
	f.call(s, lifecycle, w.ForgetRequest{Entries: []w.ForgetEntry{{Node: n, Count: 3}}})
	f.wantError(s, metadata, w.GetAttrRequest{Node: n}, unix.ESTALE)
	f.call(s, auth, w.RmdirRequest{Parent: root.Node, Name: []byte("dir")})
}

func TestExactAuthoritySharedObjectsAndBarrier(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	other, otherRoot := f.session(a.ReadWrite)
	if root.Object != otherRoot.Object {
		t.Fatal("root ObjectID is session-local")
	}
	created := f.call(s, caller(1001, 1001), w.CreateRequest{Parent: root.Node, Name: []byte("shared"), Flags: w.OpenReadWrite, Mode: 0666}).(w.CreateReply)
	e := f.call(other, caller(1002, 1002), w.LookupRequest{Parent: otherRoot.Node, Name: []byte("shared")}).(w.LookupReply).Entry
	if e.Object != created.Entry.Object {
		t.Fatal("cross-session inode identity differs")
	}
	bad, err := f.authority.Admit(other.principal, other.binding.Volume, false)
	must(t, err)
	f.gate.Lock()
	_, err = s.Dispatch(bad, w.Request{})
	f.gate.Unlock()
	bad.Release()
	if !errors.Is(err, a.ErrUnauthorized) {
		t.Fatal("foreign same-volume guard", err)
	}
	live, err := f.authority.Admit(s.principal, s.binding.Volume, false)
	must(t, err)
	live.Release()
	_, err = s.Dispatch(live, w.Request{})
	if !errors.Is(err, a.ErrClosed) {
		t.Fatal(err)
	}
	rootFD := int(s.root.Fd())
	metadataFD := int(s.metadataFD.Fd())
	nodeFD := s.nodes[created.Entry.Node].fd
	identityFD := s.nodes[created.Entry.Node].object.fd
	handleFD := s.handles[created.Opened.Handle].fd
	// The public authority retirement invokes Barrier only after joining guards.
	_, err = f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch})
	must(t, err)
	for _, fd := range []int{rootFD, handleFD, nodeFD, metadataFD} {
		if _, err = stat(fd); !errors.Is(err, unix.EBADF) {
			t.Fatal("retained attachment fd", fd, err)
		}
	}
	if _, err = stat(identityFD); err != nil {
		t.Fatal("other session lost shared inode", err)
	}
	if len(s.nodes) != 0 || len(s.handles) != 0 {
		t.Fatal("barrier leaked ownership records")
	}
}

func TestCallerACLUmaskKillprivAndGrantDoesNotBorrowOpener(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	// Linux POSIX ACL xattr version 2; default ACL beats umask but is restricted
	// by the unmasked creation mode. No userspace mode&^umask shortcut is valid.
	acl := make([]byte, 4+4*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, e := range []struct{ tag, perm uint16 }{{1, 7}, {4, 7}, {16, 7}, {32, 7}} {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(acl[off:], e.tag)
		binary.LittleEndian.PutUint16(acl[off+2:], e.perm)
		binary.LittleEndian.PutUint32(acl[off+4:], ^uint32(0))
	}
	must(t, unix.Fsetxattr(int(f.volume.Fd()), "system.posix_acl_default", acl, 0))
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("acl"), Flags: w.OpenReadWrite, Mode: 0666, Umask: 0077}).(w.CreateReply)
	if c.Entry.Attr.Mode&0777 != 0666 {
		t.Fatal("default ACL incorrectly masked", c.Entry.Attr)
	}
	n, h := c.Entry.Node, c.Opened.Handle
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 06777})
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, WriteFlags: w.WriteCache, IOFlags: w.OpenReadWrite, Data: []byte("x")})
	st := f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	if st.Mode&06000 != 0 {
		t.Fatal("cache write retained set-ID", st)
	}
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 0000})
	// Metadata ownership checks still run as caller, never as opener/service root.
	f.wantError(s, caller(1002, 1002), w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 0777}, unix.EPERM)
	f.wantError(s, caller(0, 0), w.OpenRequest{Node: n, Flags: w.OpenReadWrite}, unix.EACCES)
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, IOFlags: w.OpenReadWrite, Data: []byte("still granted")})
	f.wantError(s, auth, w.OpenRequest{Node: n}, unix.EACCES)
	// Exact metadata xattr syscall must not require data-open permission.
	f.wantError(s, auth, w.SetXAttrRequest{Node: n, Name: []byte("user.zero"), Value: []byte("v")}, unix.EACCES)
	// Setting a POSIX ACL is owner-authorized even when data opens are denied.
	f.call(s, auth, w.SetXAttrRequest{Node: n, Name: []byte("system.posix_acl_access"), Value: acl})
	f.call(s, auth, w.GetXAttrRequest{Node: n, Name: []byte("system.posix_acl_access"), Size: 65536})
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 0600})
	path := filepath.Join(f.path, "volumes", "data", "acl")
	must(t, os.Chown(path, 1001, 2002))
	must(t, os.Chmod(path, 0040))
	f.call(s, caller(3003, 3003, 7, 2002, 8), w.OpenRequest{Node: n})
	f.wantError(s, caller(3003, 3003, 7, 8), w.OpenRequest{Node: n}, unix.EACCES)
}

func TestBoundedDirectoryCookiesAndSymlinkXattrs(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	for i := 0; i < 40; i++ {
		name := []byte{byte('A' + i)}
		f.call(s, auth, w.MknodRequest{Parent: root.Node, Name: name, Mode: unix.S_IFREG | 0600})
	}
	h := f.call(s, auth, w.OpenDirRequest{Node: root.Node}).(w.OpenDirReply).Opened.Handle
	cookie := uint64(0)
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		entries := f.call(s, grantAuth, w.ReadDirRequest{Node: root.Node, Handle: h, Cookie: cookie, MaxBytes: 64}).(w.ReadDirReply).Entries
		if len(entries) == 0 {
			break
		}
		if len(entries) > 2 {
			t.Fatal("unbounded page")
		}
		for _, e := range entries {
			if seen[string(e.Name)] {
				t.Fatal("repeated name")
			}
			seen[string(e.Name)] = true
			cookie = e.NextCookie
		}
	}
	if len(seen) != 42 {
		t.Fatal("lost getdents continuation", len(seen))
	}
	target := filepath.Join(f.path, "outside")
	must(t, os.WriteFile(target, []byte("outside"), 0600))
	must(t, unix.Setxattr(target, "user.proof", []byte("safe"), 0))
	link := f.call(s, auth, w.SymlinkRequest{Parent: root.Node, Name: []byte("target"), Target: []byte(target)}).(w.SymlinkReply).Entry
	f.wantError(s, auth, w.GetXAttrRequest{Node: link.Node, Name: []byte("user.proof"), Size: 4}, unix.ENODATA)
	f.wantError(s, auth, w.SetXAttrRequest{Node: link.Node, Name: []byte("user.proof"), Value: []byte("bad")}, unix.EPERM)
	f.wantError(s, auth, w.RemoveXAttrRequest{Node: link.Node, Name: []byte("user.proof")}, unix.EPERM)
	got := make([]byte, 16)
	n, err := unix.Getxattr(target, "user.proof", got)
	must(t, err)
	if string(got[:n]) != "safe" {
		t.Fatal("followed symlink xattr")
	}
	raw, err := unix.Llistxattr(filepath.Join(f.path, "volumes", "data", "target"), nil)
	must(t, err)
	list := f.call(s, auth, w.ListXAttrRequest{Node: link.Node}).(w.ListXAttrReply)
	if list.Size != uint32(raw) {
		t.Fatal(list)
	}
}
