//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestChownKillSignalMatchesKernelSGIDDecision(t *testing.T) {
	for _, mode := range []uint32{06755, 06644} {
		for _, fsetid := range []bool{false, true} {
			for _, valid := range []uint32{0, w.SetUID, w.SetGID, w.SetUID | w.SetGID} {
				t.Run(fmt.Sprintf("mode-%o/fsetid-%t/mask-%d", mode, fsetid, valid), func(t *testing.T) {
					f := newFixture(t)
					s, root := f.session(a.ReadWrite)
					auth := fullCaller(t)
					if auth.Caller.EffectiveCaps&(1<<unix.CAP_FSETID) == 0 {
						t.Fatal("requires CAP_FSETID")
					}
					if !fsetid {
						auth.Caller.EffectiveCaps &^= 1 << unix.CAP_FSETID
					}
					// Neither FSGID nor supplementary groups matches inode GID 2002.
					var fds [2]int
					caps := make([]byte, 20)
					binary.LittleEndian.PutUint32(caps, 0x02000001)
					binary.LittleEndian.PutUint32(caps[4:], 1<<10)
					for i, name := range []string{"native", "managed"} {
						var err error
						fds[i], err = unix.Openat(int(f.volume.Fd()), name, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0600)
						must(t, err)
						defer unix.Close(fds[i])
						must(t, unix.Fchown(fds[i], 1001, 2002))
						must(t, unix.Fchmod(fds[i], mode))
						must(t, unix.Fsetxattr(fds[i], "security.capability", caps, 0))
					}
					n := f.call(s, auth, w.LookupRequest{Parent: root.Node, Name: []byte("managed")}).(w.LookupReply).Entry.Node
					uid, gid := -1, -1
					if valid&w.SetUID != 0 {
						uid = 1001
					}
					if valid&w.SetGID != 0 {
						gid = 2002
					}
					must(t, f.worker.Do(*auth.Caller, 0, func() error {
						return unix.Fchownat(fds[0], "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
					}))
					// chown_common always supplies CTIME/KILL_SUID/KILL_PRIV;
					// setattr_should_drop_sgid depends on execute/group/FSETID.
					semantics := w.MetadataValid | w.MetadataCTime | w.MetadataKillSUID | w.MetadataKillPriv
					if mode&0010 != 0 || !fsetid {
						semantics |= w.MetadataKillSGID
					}
					request := w.SetAttrRequest{Node: n, Valid: valid, Semantics: semantics}
					if uid >= 0 {
						request.UID = uint32(uid)
					}
					if gid >= 0 {
						request.GID = uint32(gid)
					}
					got := f.call(s, auth, request).(w.SetAttrReply).Attr
					native, err := stat(fds[0])
					must(t, err)
					if got.Mode != native.Mode || got.UID != native.Uid || got.GID != native.Gid {
						t.Fatal("chown parity", got, native)
					}
					want := uint32(0)
					if mode&0010 == 0 && fsetid {
						want = 02000
					}
					if got.Mode&06000 != want {
						t.Fatalf("kernel SGID decision lost: mode=%o want set-ID=%o", got.Mode, want)
					}
					for _, fd := range fds {
						if _, err := unix.Fgetxattr(fd, "security.capability", nil); !errors.Is(err, unix.ENODATA) {
							t.Fatal("real chown killpriv missing", err)
						}
					}
				})
			}
		}
	}
}
