//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func fullCaller(t *testing.T) w.Auth {
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var words [2]unix.CapUserData
	must(t, unix.Capget(&h, &words[0]))
	auth := caller(0, 0)
	auth.Caller.EffectiveCaps = uint64(words[0].Effective) | uint64(words[1].Effective)<<32
	return auth
}
func testACL() []byte {
	b := make([]byte, 44)
	binary.LittleEndian.PutUint32(b, 2)
	for i, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 7, ^uint32(0)}, {2, 4, 1003}, {4, 0, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(b[off:], e.tag)
		binary.LittleEndian.PutUint16(b[off+2:], e.perm)
		binary.LittleEndian.PutUint32(b[off+4:], e.id)
	}
	return b
}

type xattrCase struct {
	label, name string
	kind        int
	value       []byte
}

var xattrCases = []xattrCase{
	{label: "get-user", name: "user.proof", kind: 0},
	{label: "get-acl", name: "system.posix_acl_access", kind: 0},
	{label: "list", kind: 1},
	{label: "set-user", name: "user.proof", kind: 2, value: []byte("changed")},
	{label: "remove-user", name: "user.proof", kind: 3},
	{label: "set-acl", name: "system.posix_acl_access", kind: 2, value: testACL()},
	{label: "remove-acl", name: "system.posix_acl_access", kind: 3},
	{label: "set-trusted", name: "trusted.proof", kind: 2, value: []byte{}},
}

func xattrRequest(node w.NodeID, c xattrCase) w.RequestBody {
	switch c.kind {
	case 0:
		return w.GetXAttrRequest{Node: node, Name: []byte(c.name), Size: w.MaxXAttr}
	case 1:
		return w.ListXAttrRequest{Node: node, Size: w.MaxXAttr}
	case 2:
		return w.SetXAttrRequest{Node: node, Name: []byte(c.name), Value: c.value}
	default:
		return w.RemoveXAttrRequest{Node: node, Name: []byte(c.name)}
	}
}
func compareXattr(t *testing.T, f *fixture, s *Session, node w.NodeID, auth w.Auth, c xattrCase, native func([]byte) (int, error)) {
	t.Helper()
	buffer := make([]byte, w.MaxXAttr)
	var n int
	var nativeErr error
	must(t, f.worker.Do(*auth.Caller, 0, func() error { n, nativeErr = native(buffer); return nil }))
	reply := f.dispatch(s, auth, xattrRequest(node, c)).Reply
	if nativeErr != nil {
		if reply.Errno != errno(nativeErr) {
			t.Fatalf("native=%v managed=%d", nativeErr, reply.Errno)
		}
		return
	}
	if reply.Errno != 0 {
		t.Fatalf("native success managed errno=%d", reply.Errno)
	}
	switch b := reply.Body.(type) {
	case w.GetXAttrReply:
		if !bytes.Equal(b.Value, buffer[:n]) {
			t.Fatalf("get mismatch %x != %x", b.Value, buffer[:n])
		}
	case w.ListXAttrReply:
		if !bytes.Equal(b.Names, buffer[:n]) {
			t.Fatalf("list mismatch %x != %x", b.Names, buffer[:n])
		}
	}
}
func TestModeZeroXattrsMatchDirectExt4UnderEveryCaller(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	identities := []struct {
		name string
		auth w.Auth
	}{{"owner", caller(1001, 1001)}, {"other", caller(1002, 1002)}, {"uid-zero-no-caps", caller(0, 0)}, {"root-explicit-caps", fullCaller(t)}}
	sequence := 0
	for _, id := range identities {
		for _, kind := range []string{"file", "directory", "unlinked-file"} {
			for _, c := range xattrCases {
				t.Run(id.name+"/"+kind+"/"+c.label, func(t *testing.T) {
					previous := f.t
					f.t = t
					defer func() { f.t = previous }()
					sequence++
					var fd [2]int
					var names [2]string
					for i := range fd {
						names[i] = fmt.Sprintf("xattr-%d-%d", sequence, i)
						if kind == "directory" {
							must(t, unix.Mkdirat(int(f.volume.Fd()), names[i], 0700))
							var err error
							fd[i], err = unix.Openat(int(f.volume.Fd()), names[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
							must(t, err)
						} else {
							var err error
							fd[i], err = unix.Openat(int(f.volume.Fd()), names[i], unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
							must(t, err)
						}
						defer unix.Close(fd[i])
						must(t, unix.Fchown(fd[i], 1001, 1001))
						must(t, unix.Fsetxattr(fd[i], "user.proof", []byte{0, 255, 1}, 0))
						must(t, unix.Fsetxattr(fd[i], "system.posix_acl_access", testACL(), 0))
						must(t, unix.Fchmod(fd[i], 0))
					}
					node := f.call(s, caller(1001, 1001), w.LookupRequest{Parent: root.Node, Name: []byte(names[1])}).(w.LookupReply).Entry.Node
					if kind == "unlinked-file" {
						must(t, unix.Unlinkat(int(f.volume.Fd()), names[0], 0))
						f.call(s, caller(1001, 1001), w.UnlinkRequest{Parent: root.Node, Name: []byte(names[1])})
					}
					compareXattr(t, f, s, node, id.auth, c, func(buffer []byte) (int, error) {
						switch c.kind {
						case 0:
							return unix.Fgetxattr(fd[0], c.name, buffer)
						case 1:
							return unix.Flistxattr(fd[0], buffer)
						case 2:
							return 0, unix.Fsetxattr(fd[0], c.name, c.value, 0)
						default:
							return 0, unix.Fremovexattr(fd[0], c.name)
						}
					})
				})
			}
		}
	}
}
func TestSymlinkXattrsMatchDirectExt4AndNeverTouchTarget(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	target, err := unix.Openat(int(f.volume.Fd()), "target", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0666)
	must(t, err)
	defer unix.Close(target)
	must(t, unix.Fsetxattr(target, "user.proof", []byte("unchanged"), 0))
	for _, name := range []string{"native-link", "managed-link"} {
		must(t, unix.Symlinkat("target", int(f.volume.Fd()), name))
		must(t, unix.Fchownat(int(f.volume.Fd()), name, 1001, 1001, unix.AT_SYMLINK_NOFOLLOW))
	}
	node := f.call(s, caller(1001, 1001), w.LookupRequest{Parent: root.Node, Name: []byte("managed-link")}).(w.LookupReply).Entry.Node
	for i, auth := range []w.Auth{caller(1001, 1001), caller(1002, 1002), caller(0, 0), fullCaller(t)} {
		for _, c := range xattrCases {
			t.Run(fmt.Sprintf("caller-%d/%s", i, c.label), func(t *testing.T) {
				previous := f.t
				f.t = t
				defer func() { f.t = previous }()
				path := procFD(int(f.volume.Fd())) + "/native-link"
				compareXattr(t, f, s, node, auth, c, func(buffer []byte) (int, error) {
					switch c.kind {
					case 0:
						return unix.Lgetxattr(path, c.name, buffer)
					case 1:
						return unix.Llistxattr(path, buffer)
					case 2:
						return 0, unix.Lsetxattr(path, c.name, c.value, 0)
					default:
						return 0, unix.Lremovexattr(path, c.name)
					}
				})
			})
		}
	}
	value := make([]byte, 64)
	n, err := unix.Fgetxattr(target, "user.proof", value)
	must(t, err)
	if string(value[:n]) != "unchanged" {
		t.Fatal("symlink target metadata changed")
	}
	if _, err = pinnedXattr(s.nodes[node].fd, "user.proof", value, 0, 0); err != unix.ENODATA {
		t.Fatal("pure procfd jump followed symlink target", err)
	}
}
