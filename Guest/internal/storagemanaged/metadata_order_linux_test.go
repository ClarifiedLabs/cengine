//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
	"unsafe"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestSecurityCapabilityChownOrderingAndCacheKillpriv(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("caps"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	path := filepath.Join(f.path, "volumes", "data", "caps")
	// VFS_CAP_REVISION_2 | EFFECTIVE, CAP_NET_BIND_SERVICE in permitted low word.
	caps := make([]byte, 20)
	binary.LittleEndian.PutUint32(caps, 0x02000001)
	binary.LittleEndian.PutUint32(caps[4:], 1<<10)
	must(t, unix.Setxattr(path, "security.capability", caps, 0))
	f.call(s, grantAuth, w.WriteRequest{Node: c.Entry.Node, Handle: c.Opened.Handle, WriteFlags: w.WriteCache, Data: []byte("data")})
	if _, err := unix.Getxattr(path, "security.capability", nil); !errors.Is(err, unix.ENODATA) {
		t.Fatal("grant borrowed service/opener caps", err)
	}
	must(t, unix.Setxattr(path, "security.capability", caps, 0))
	// Explicit service capabilities are only used when present in caller snapshot.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var words [2]unix.CapUserData
	must(t, unix.Capget(&hdr, &words[0]))
	rootCaller := caller(0, 0)
	rootCaller.Caller.EffectiveCaps = uint64(words[0].Effective) | uint64(words[1].Effective)<<32
	f.call(s, rootCaller, w.SetAttrRequest{Node: c.Entry.Node, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataKillSUID | w.MetadataKillPriv, Valid: w.SetUID | w.SetGID, UID: 1002, GID: 1002})
	f.call(s, rootCaller, w.SetAttrRequest{Node: c.Entry.Node, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 06755})
	st := f.call(s, metadata, w.GetAttrRequest{Node: c.Entry.Node}).(w.GetAttrReply).Attr
	if st.UID != 1002 || st.GID != 1002 || st.Mode&07777 != 06755 {
		t.Fatal("chown/chmod ordering", st)
	}
	if _, err := unix.Getxattr(path, "security.capability", nil); !errors.Is(err, unix.ENODATA) {
		t.Fatal("chown did not clear file capability", err)
	}
}
func TestTruncateReadOnlyHandleMatchesLinux(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("truncate"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	n := c.Entry.Node
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: c.Opened.Handle, Data: []byte("unchanged")})
	h := f.call(s, auth, w.OpenRequest{Node: n, Flags: w.OpenReadOnly}).(w.OpenReply).Opened.Handle
	before := f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	// Compare the actual native syscall under the same identity and grant.
	// The caller can open for write, but this immutable read grant cannot upgrade.
	err := f.worker.Do(*auth.Caller, 0, func() error { return unix.Ftruncate(s.handles[h].fd, 0) })
	if !errors.Is(err, unix.EINVAL) {
		t.Fatal("Linux ftruncate on a valid read-only FD", err)
	}
	f.wantError(s, auth, w.SetAttrRequest{Node: n, Handle: &h, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataFile, Valid: w.SetSize}, unix.EINVAL)
	// A valid handle for another inode, and a released handle, are still EBADF.
	other := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("other"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	f.wantError(s, auth, w.SetAttrRequest{Node: n, Handle: &other.Opened.Handle, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataFile, Valid: w.SetSize}, unix.EBADF)
	f.call(s, lifecycle, w.ReleaseRequest{Node: n, Handle: h})
	f.wantError(s, auth, w.SetAttrRequest{Node: n, Handle: &h, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataFile, Valid: w.SetSize}, unix.EBADF)
	after := f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	if after != before {
		t.Fatal("rejected truncate changed metadata", before, after)
	}
	data := f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: c.Opened.Handle, Size: 32}).(w.ReadReply).Data
	if string(data) != "unchanged" {
		t.Fatal("rejected truncate changed data", string(data))
	}
}

func TestDeviceOpenRejection(t *testing.T) {
	f := newFixture(t)
	rw, rwRoot := f.session(a.ReadWrite)
	path := filepath.Join(f.path, "volumes", "data", "device")
	must(t, unix.Mknod(path, unix.S_IFCHR|0666, int(unix.Mkdev(1, 3))))
	n := f.call(rw, caller(1001, 1001), w.LookupRequest{Parent: rwRoot.Node, Name: []byte("device")}).(w.LookupReply).Entry
	if n.Attr.Rdev != unix.Mkdev(1, 3) {
		t.Fatal("rdev was not device identity", n.Attr)
	}
	nodes, handles := len(rw.nodes), len(rw.handles)
	f.wantError(rw, caller(0, 0), w.OpenRequest{Node: n.Node, Flags: w.OpenReadWrite}, unix.EPERM)
	// Managed CREATE is backing-exclusive even without source O_EXCL. Linux
	// fs/fuse/dir.c:fuse_atomic_open resolves nonexclusive EEXIST via a fresh
	// lookup and normal open, never an existing-inode CreateReply (FMODE_CREATED).
	for _, flags := range []uint32{w.OpenReadWrite, w.OpenReadWrite | w.OpenTruncate, w.OpenReadWrite | w.OpenTruncate | w.OpenExclusive} {
		f.wantError(rw, caller(0, 0), w.CreateRequest{Parent: rwRoot.Node, Name: []byte("device"), Flags: flags, Mode: 0666}, unix.EEXIST)
	}
	// The subsequent wire LOOKUP/OPEN must still enforce the device policy.
	found := f.call(rw, caller(0, 0), w.LookupRequest{Parent: rwRoot.Node, Name: []byte("device")}).(w.LookupReply).Entry
	f.wantError(rw, caller(0, 0), w.OpenRequest{Node: found.Node, Flags: w.OpenReadWrite}, unix.EPERM)
	if found != n || len(rw.nodes) != nodes || len(rw.handles) != handles {
		t.Fatal("device collision changed inode or granted resources", n, found)
	}
}
func TestDirectBuffersAndArchitectureFlagTranslation(t *testing.T) {
	for _, size := range []int{0, 1, 512, 4096, w.MaxIO} {
		b := ioBuffer(size, w.OpenDirect)
		if len(b) != size {
			t.Fatal("length")
		}
		if size > 0 && uintptr(unsafe.Pointer(&b[0]))&65535 != 0 {
			t.Fatal("unaligned direct buffer")
		}
	}
	got := openFlags(w.OpenDirect | w.OpenDirectory | w.OpenNoFollow | w.OpenAppend | w.OpenSync)
	if got&unix.O_DIRECT == 0 || got&unix.O_DIRECTORY == 0 || got&unix.O_NOFOLLOW == 0 || got&unix.O_SYNC != unix.O_SYNC || got&unix.O_APPEND != 0 {
		t.Fatalf("flags %#x", got)
	}
}
