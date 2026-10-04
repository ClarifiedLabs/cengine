//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// These use the real storage ioctl. Missing /dev/fuse or the experimental ABI
// fails root execution; there is deliberately no chmod/truncate emulation.
func TestMetadataSessionCurrentCallerAndExactRetainedHandle(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("retained"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	n, h := c.Entry.Node, c.Opened.Handle
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, Data: []byte("retained data")})
	// Possession of the token neither permits nonroot mint nor borrows root for apply.
	device, err := os.OpenFile("/dev/fuse", os.O_RDWR|unix.O_CLOEXEC, 0)
	must(t, err)
	defer device.Close()
	err = f.worker.Do(*auth.Caller, 0, func() error {
		fd, _, errno := unix.RawSyscall(unix.SYS_IOCTL, device.Fd(), storageSessionIOCTL, 0)
		if errno == 0 {
			unix.Close(int(fd))
		}
		return errno
	})
	if !errors.Is(err, unix.EPERM) {
		t.Fatal("nonroot minted using root-opened device", err)
	}
	for _, other := range []w.Auth{caller(1002, 1002), caller(0, 0)} {
		f.wantError(s, other, w.SetAttrRequest{Node: n, Valid: w.SetMode, Mode: 0777, Semantics: w.MetadataValid | w.MetadataCTime}, unix.EPERM)
	}
	f.call(s, auth, w.SetAttrRequest{Node: n, Valid: w.SetMode, Semantics: w.MetadataValid | w.MetadataCTime})
	f.call(s, auth, w.UnlinkRequest{Parent: root.Node, Name: []byte("retained")})
	// An optional FH alone must NOT turn a pathname truncate into FD authority.
	f.wantError(s, auth, w.SetAttrRequest{Node: n, Handle: &h, Valid: w.SetSize, Size: 3, Semantics: w.MetadataValid | w.MetadataCTime}, unix.EACCES)
	got := f.call(s, auth, w.SetAttrRequest{Node: n, Handle: &h, Valid: w.SetSize, Size: 3, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataFile}).(w.SetAttrReply).Attr
	if got.Size != 3 || got.Nlink != 0 || got.Mode&0777 != 0 {
		t.Fatal(got)
	}
	flags, err := unix.FcntlInt(s.metadataFD.Fd(), unix.F_GETFD, 0)
	must(t, err)
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("metadata capability can survive exec")
	}
}

func TestMetadataSessionEmptyChownAndImplicitKillBeforeWrite(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("kill"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	n, h := c.Entry.Node, c.Opened.Handle
	path := filepath.Join(f.path, "volumes", "data", "kill")
	caps := make([]byte, 20)
	binary.LittleEndian.PutUint32(caps, 0x02000001)
	binary.LittleEndian.PutUint32(caps[4:], 1<<10)
	for _, semantics := range []w.MetadataSemantics{
		// chown(-1,-1) on an executable SGID regular file.
		w.MetadataValid | w.MetadataCTime | w.MetadataKillSUID | w.MetadataKillSGID | w.MetadataKillPriv,
		// __remove_privs before an ordinary caller write.
		w.MetadataValid | w.MetadataForce | w.MetadataKillSUID | w.MetadataKillSGID | w.MetadataKillPriv,
	} {
		must(t, unix.Fchmod(s.handles[h].fd, 06755))
		must(t, unix.Setxattr(path, "security.capability", caps, 0))
		before, err := stat(s.nodes[n].fd)
		must(t, err)
		time.Sleep(time.Millisecond)
		f.wantError(s, auth, w.RemoveXAttrRequest{Node: n, Name: []byte("security.capability")}, unix.EPERM)
		got := f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: semantics}).(w.SetAttrReply).Attr
		if got.Mode&06000 != 0 || got.UID != 1001 || got.GID != 1001 || got.CTime == attributes(before).CTime {
			t.Fatal("empty metadata intent lost", got)
		}
		if _, err := unix.Getxattr(path, "security.capability", nil); !errors.Is(err, unix.ENODATA) {
			t.Fatal("implicit kill did not precede data write", err)
		}
		f.call(s, auth, w.WriteRequest{Node: n, Handle: h, Data: []byte("x")})
	}
}

func TestMetadataSessionSymlinkReadOnlyAndTimestamps(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("target"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	link := f.call(s, auth, w.SymlinkRequest{Parent: root.Node, Name: []byte("link"), Target: []byte("target")}).(w.SymlinkReply).Entry
	before := f.call(s, metadata, w.GetAttrRequest{Node: c.Entry.Node}).(w.GetAttrReply).Attr
	f.call(s, auth, w.UnlinkRequest{Parent: root.Node, Name: []byte("link")})
	got := f.call(s, auth, w.SetAttrRequest{Node: link.Node, Valid: w.SetATime | w.SetMTime | w.SetMTimeNow, ATime: w.Timestamp{Seconds: 42, Nanoseconds: 17}, MTime: w.Timestamp{Seconds: 1}, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataTimesSet}).(w.SetAttrReply).Attr
	if got.ATime.Seconds != 42 || got.ATime.Nanoseconds != 17 || got.MTime.Seconds <= 1 || got.Nlink != 0 {
		t.Fatal(got)
	}
	f.wantError(s, auth, w.SetAttrRequest{Node: link.Node, Valid: w.SetMode, Mode: 0600, Semantics: w.MetadataValid | w.MetadataCTime}, unix.EOPNOTSUPP)
	after := f.call(s, metadata, w.GetAttrRequest{Node: c.Entry.Node}).(w.GetAttrReply).Attr
	if after != before {
		t.Fatal("symlink operation touched target", before, after)
	}
	ro, roRoot := f.session(a.ReadOnly)
	rn := f.call(ro, auth, w.LookupRequest{Parent: roRoot.Node, Name: []byte("target")}).(w.LookupReply).Entry.Node
	v := w.SetAttrRequest{Node: rn, Valid: w.SetMode, Mode: 0777, Semantics: w.MetadataValid | w.MetadataCTime}
	// Mutation admission rejects RO before Dispatch. Use a live read-only guard
	// to exercise the backend's independent wire-policy rejection without changing
	// the authenticated binding or the detached read-only backing view.
	g, err := f.authority.Admit(ro.principal, ro.binding.Volume, false)
	must(t, err)
	f.sequence[ro]++
	r := w.Request{Sequence: f.sequence[ro], Auth: auth, Body: v}
	result, err := ro.Dispatch(g, r)
	g.Release()
	must(t, err)
	must(t, w.ValidateReplyFor(r, result.Reply))
	if result.Reply.Errno != uint32(unix.EROFS) || len(result.Events) != 0 {
		t.Fatal("RO wire policy did not reject metadata mutation", result)
	}
	// Bypass only the wire RO policy to prove mnt_want_write on the exact view.
	attr := metadataAttr(v, ro.nodes[rn].fd)
	err = f.worker.Do(*auth.Caller, 0, func() error { return platformApplyMetadata(int(ro.metadataFD.Fd()), &attr) })
	if !errors.Is(err, unix.EROFS) {
		t.Fatal("RO pin gained metadata write", err)
	}
	after = f.call(s, metadata, w.GetAttrRequest{Node: c.Entry.Node}).(w.GetAttrReply).Attr
	if after != before {
		t.Fatal("rejected RO metadata changed target", before, after)
	}
}

func TestCreateCollisionRequiresSourceLookupOpen(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("existing"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	f.call(s, grantAuth, w.WriteRequest{Node: c.Entry.Node, Handle: c.Opened.Handle, Data: []byte("keep")})
	// Privileged fixture setup only; no invented source metadata intent.
	must(t, unix.Fchmod(s.handles[c.Opened.Handle].fd, 06755))
	nodes, handles := len(s.nodes), len(s.handles)
	for _, flags := range []uint32{w.OpenReadWrite, w.OpenReadWrite | w.OpenTruncate, w.OpenReadWrite | w.OpenTruncate | w.OpenExclusive} {
		f.wantError(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("existing"), Flags: flags, Mode: 0600}, unix.EEXIST)
	}
	got := f.call(s, metadata, w.GetAttrRequest{Node: c.Entry.Node}).(w.GetAttrReply).Attr
	if got.Size != 4 || got.Mode&06000 != 06000 || len(s.nodes) != nodes || len(s.handles) != handles {
		t.Fatal("collision mutated inode or granted a created handle", got)
	}
	// Do not fabricate the missing SETATTR: the actual mounted/raw syscall probes
	// must prove that source VFS performs lookup, non-created OPEN and truncation.
}

func TestMetadataFailureKeepsInvalidationsAndSyncs(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("failure"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	calls := 0
	f.registry.syncOps.syncfs = func(fd int) error { calls++; return unix.Syncfs(fd) }
	result := f.dispatch(s, caller(1002, 1002), w.SetAttrRequest{Node: c.Entry.Node, Valid: w.SetMode, Mode: 0777, Semantics: w.MetadataValid | w.MetadataCTime})
	if result.Reply.Errno != uint32(unix.EPERM) || len(result.Events) != 1 || calls != 1 {
		t.Fatal("failed apply lost sync/event", result, calls)
	}
	// The actual ioctl completed; a later durability failure must not retry it.
	f.registry.syncOps.syncfs = func(int) error { return unix.EIO }
	f.expectFaults = true
	result, err := dispatchRaw(f, s, auth, w.SetAttrRequest{Node: c.Entry.Node, Valid: w.SetMode, Mode: 0640, Semantics: w.MetadataValid | w.MetadataCTime})
	if !errors.Is(err, ErrVolumeFault) || len(result.Events) != 1 {
		t.Fatal(result, err)
	}
	st, err := stat(s.nodes[c.Entry.Node].fd)
	must(t, err)
	if st.Mode&0777 != 0640 {
		t.Fatal("partial success hidden", st)
	}
}

func TestMetadataSessionSetupFailureClosesCapability(t *testing.T) {
	f := newFixture(t)
	b, p := f.principal(a.ReadWrite)
	g, err := f.authority.Admit(p, b.Volume, false)
	must(t, err)
	defer g.Release()
	// Exhaust the private object bookkeeping budget, not OS resources. This fails
	// initialize AFTER mint; restore the test-only records before cleanup.
	objects := f.registry.objects
	f.registry.objects = make(map[inodeKey]*object, MaxObjects)
	for i := 0; i < MaxObjects; i++ {
		f.registry.objects[inodeKey{ino: uint64(i)}] = nil
	}
	defer func() { f.registry.objects = objects }()
	before := metadataFDCount(t)
	for i := 0; i < 4; i++ {
		_, _, err := New(g, p, b, f.gate, f.worker, f.registry)
		if !errors.Is(err, unix.ENFILE) {
			t.Fatal("unexpected setup failure", err)
		}
	}
	after := metadataFDCount(t)
	if after != before {
		t.Fatal("setup leaked metadata FDs", before, after)
	}
}

func metadataFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	must(t, err)
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		} // directory enumeration FD
		must(t, err)
		if strings.Contains(target, "cengine-storage") {
			count++
		}
	}
	return count
}

func TestMetadataSessionFDCountReturnsToBaseline(t *testing.T) {
	f := newFixture(t)
	before := metadataFDCount(t)
	s, _ := f.session(a.ReadWrite)
	if got := metadataFDCount(t); got != before+1 {
		t.Fatal("session did not own exactly one metadata FD", before, got)
	}
	_, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch})
	must(t, err)
	if got := metadataFDCount(t); got != before {
		t.Fatal("barrier leaked metadata FD", before, got)
	}
}
