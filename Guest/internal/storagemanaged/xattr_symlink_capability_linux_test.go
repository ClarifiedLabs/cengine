//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func symlinkCapabilityForTest(permitted uint32) []byte {
	value := make([]byte, 20)
	binary.LittleEndian.PutUint32(value, 0x02000001) // VFS_CAP_REVISION_2 | EFFECTIVE
	binary.LittleEndian.PutUint32(value[4:], permitted)
	return value
}

func TestSymlinkValidCapabilityXattrsMatchDirectExt4(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("DIRECT-EXT4 requires root with CAP_SETFCAP and worker setup capabilities")
	}
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	if fullCaller(t).Caller.EffectiveCaps&(1<<unix.CAP_SETFCAP) == 0 {
		t.Fatal("DIRECT-EXT4 requires CAP_SETFCAP")
	}
	rootCap := caller(0, 0)
	rootCap.Caller.EffectiveCaps = 1 << unix.CAP_SETFCAP
	identities := []struct {
		name   string
		auth   w.Auth
		mutate bool
	}{
		{"root-cap-setfcap", rootCap, true},
		{"uid-zero-no-caps", caller(0, 0), false},
		{"nonroot-owner", caller(1001, 1001), false},
	}
	initial := symlinkCapabilityForTest(1 << unix.CAP_NET_BIND_SERVICE)
	changed := symlinkCapabilityForTest(1 << unix.CAP_CHOWN)
	cases := []xattrCase{
		{label: "get-capability", name: "security.capability", kind: 0},
		{label: "list-capability", kind: 1},
		{label: "set-valid-capability", name: "security.capability", kind: 2, value: changed},
		{label: "remove-capability", name: "security.capability", kind: 3},
	}
	target, err := unix.Openat(int(f.volume.Fd()), "capability-target", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	must(t, err)
	defer unix.Close(target)
	must(t, unix.Fsetxattr(target, "security.capability", initial, 0))
	must(t, unix.Fsetxattr(target, "user.proof", []byte("untouched"), 0))
	var before unix.Stat_t
	must(t, unix.Fstat(target, &before))
	sequence := 0
	for _, literal := range []string{"capability-target", "missing-target"} {
		for _, id := range identities {
			for _, c := range cases {
				t.Run(literal+"/"+id.name+"/"+c.label, func(t *testing.T) {
					previous := f.t
					f.t = t
					defer func() { f.t = previous }()
					sequence++
					var names, paths [2]string
					for i := range names {
						names[i] = fmt.Sprintf("capability-%d-%d", sequence, i)
						paths[i] = procFD(int(f.volume.Fd())) + "/" + names[i]
						must(t, unix.Symlinkat(literal, int(f.volume.Fd()), names[i]))
						must(t, unix.Fchownat(int(f.volume.Fd()), names[i], 1001, 1001, unix.AT_SYMLINK_NOFOLLOW))
						// Positive direct-ext4 control on each live/dangling inode.
						// Malformed one-byte capability denial cannot stand in for it.
						must(t, unix.Lsetxattr(paths[i], "security.capability", initial, 0))
					}
					node := f.call(s, caller(1001, 1001), w.LookupRequest{Parent: root.Node, Name: []byte(names[1])}).(w.LookupReply).Entry.Node
					var nativeErr error
					compareXattr(t, f, s, node, id.auth, c, func(buffer []byte) (int, error) {
						var n int
						switch c.kind {
						case 0:
							n, nativeErr = unix.Lgetxattr(paths[0], c.name, buffer)
						case 1:
							n, nativeErr = unix.Llistxattr(paths[0], buffer)
						case 2:
							nativeErr = unix.Lsetxattr(paths[0], c.name, c.value, 0)
						case 3:
							nativeErr = unix.Lremovexattr(paths[0], c.name)
						}
						return n, nativeErr
					})
					if c.kind < 2 || id.mutate {
						must(t, nativeErr)
					} else if !errors.Is(nativeErr, unix.EPERM) {
						t.Fatalf("valid capability mutation without CAP_SETFCAP = %v, want EPERM", nativeErr)
					}
					want := initial
					if id.mutate && c.kind == 2 {
						want = changed
					} else if id.mutate && c.kind == 3 {
						want = nil
					}
					for _, path := range paths {
						buffer := make([]byte, w.MaxXAttr)
						n, err := unix.Lgetxattr(path, "security.capability", buffer)
						if want == nil {
							if !errors.Is(err, unix.ENODATA) {
								t.Fatalf("removed capability still present: %v", err)
							}
						} else if err != nil || !bytes.Equal(buffer[:n], want) {
							t.Fatalf("capability changed unexpectedly: %x, %v", buffer, err)
						}
					}
				})
			}
		}
	}
	var after unix.Stat_t
	must(t, unix.Fstat(target, &after))
	if before != after {
		t.Fatal("symlink operation changed target metadata")
	}
	buffer := make([]byte, 64)
	n, err := unix.Fgetxattr(target, "security.capability", buffer)
	must(t, err)
	if !bytes.Equal(buffer[:n], initial) {
		t.Fatal("symlink operation changed target capability")
	}
	n, err = unix.Fgetxattr(target, "user.proof", buffer)
	must(t, err)
	if string(buffer[:n]) != "untouched" {
		t.Fatal("symlink operation changed target user xattr")
	}
}
