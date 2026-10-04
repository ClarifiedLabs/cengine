//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"fmt"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestReadOnlyViewPreservesAtimeAndSeparatesOperationalPins(t *testing.T) {
	for _, firstMode := range []a.Mode{a.ReadWrite, a.ReadOnly} {
		t.Run(string(firstMode)+"-first", func(t *testing.T) {
			f := newFixture(t)
			rootFD := int(f.volume.Fd())
			fd, err := unix.Openat(rootFD, "file", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0644)
			must(t, err)
			_, err = unix.Write(fd, []byte("unchanged"))
			must(t, err)
			must(t, unix.Close(fd))
			must(t, unix.Mkdirat(rootFD, "dir", 0755))
			must(t, unix.Symlinkat("file", rootFD, "symlink"))
			names := []string{"file", "dir", "symlink"}
			before := make(map[string]unix.Stat_t)
			for _, name := range names {
				must(t, unix.Fchownat(rootFD, name, 1001, 1001, unix.AT_SYMLINK_NOFOLLOW))
				must(t, unix.UtimesNanoAt(rootFD, name, []unix.Timespec{{Sec: 1}, {Sec: 2}}, unix.AT_SYMLINK_NOFOLLOW))
				var st unix.Stat_t
				must(t, unix.Fstatat(rootFD, name, &st, unix.AT_SYMLINK_NOFOLLOW))
				before[name] = st
			}
			var canonicalBefore unix.Statfs_t
			must(t, unix.Fstatfs(rootFD, &canonicalBefore))
			first, firstRoot := f.session(firstMode)
			secondMode := a.ReadOnly
			if firstMode == a.ReadOnly {
				secondMode = a.ReadWrite
			}
			second, secondRoot := f.session(secondMode)
			rw, rwRoot, ro, roRoot := first, firstRoot, second, secondRoot
			if firstMode == a.ReadOnly {
				rw, rwRoot, ro, roRoot = second, secondRoot, first, firstRoot
			}
			if rwRoot.Object != roRoot.Object {
				t.Fatal("root identity differs by view")
			}
			roMount, err := mountID(ro.nodes[roRoot.Node].fd)
			must(t, err)
			rwMount, err := mountID(rw.nodes[rwRoot.Node].fd)
			must(t, err)
			canonicalMount, err := mountID(rootFD)
			must(t, err)
			if roMount == rwMount || rwMount != canonicalMount {
				t.Fatal("mount provenance", roMount, rwMount, canonicalMount)
			}
			nonowner := caller(1002, 1002) // no NOATIME owner privilege or capabilities
			for _, name := range names {
				// The first session also interns the child first, exercising both global-pin orders.
				x := f.call(first, nonowner, w.LookupRequest{Parent: firstRoot.Node, Name: []byte(name)}).(w.LookupReply).Entry
				y := f.call(second, nonowner, w.LookupRequest{Parent: secondRoot.Node, Name: []byte(name)}).(w.LookupReply).Entry
				roEntry, rwEntry := y, x
				if firstMode == a.ReadOnly {
					roEntry, rwEntry = x, y
				}
				rn, wn := ro.nodes[roEntry.Node], rw.nodes[rwEntry.Node]
				if x.Object != y.Object || rn.object != wn.object || rn.fd == wn.fd || rn.fd == rn.object.fd || wn.fd == wn.object.fd {
					t.Fatal("identity/operational pin ownership conflated", name)
				}
				for _, pair := range []struct {
					fd    int
					mount uint64
				}{{rn.fd, roMount}, {wn.fd, rwMount}} {
					m, err := mountID(pair.fd)
					must(t, err)
					if m != pair.mount {
						t.Fatal("child migrated between views", name)
					}
				}
				switch name {
				case "file":
					h := f.call(ro, nonowner, w.OpenRequest{Node: rn.id}).(w.OpenReply).Opened.Handle
					got := f.call(ro, grantAuth, w.ReadRequest{Node: rn.id, Handle: h, Size: 32}).(w.ReadReply)
					if string(got.Data) != "unchanged" {
						t.Fatal(got)
					}
					f.call(ro, lifecycle, w.ReleaseRequest{Node: rn.id, Handle: h})
					// Bypass request policy to prove the backing view itself cannot write.
					must(t, f.worker.Do(*caller(1001, 1001).Caller, 0, func() error {
						dataFD, e := unix.Open(procFD(rn.fd), unix.O_WRONLY|unix.O_CLOEXEC, 0)
						if e == nil {
							unix.Close(dataFD)
							return fmt.Errorf("RO pin permitted data write")
						}
						if !errors.Is(e, unix.EROFS) {
							return e
						}
						return nil
					}))
					// RW must not reuse an earlier RO identity pin for opens or link source.
					hw := f.call(rw, caller(1001, 1001), w.OpenRequest{Node: wn.id, Flags: w.OpenReadWrite}).(w.OpenReply).Opened.Handle
					f.call(rw, lifecycle, w.ReleaseRequest{Node: wn.id, Handle: hw})
					f.call(rw, caller(1001, 1001), w.LinkRequest{Source: wn.id, Parent: rwRoot.Node, Name: []byte("rw-alias")})
					// Neither failed read-open nor an EROFS write-open may deny listxattr.
					f.call(rw, caller(1001, 1001), w.SetAttrRequest{Node: wn.id, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 0})
				case "dir":
					h := f.call(ro, nonowner, w.OpenDirRequest{Node: rn.id}).(w.OpenDirReply).Opened.Handle
					f.call(ro, grantAuth, w.ReadDirRequest{Node: rn.id, Handle: h, MaxBytes: 128})
					f.call(ro, lifecycle, w.ReleaseDirRequest{Node: rn.id, Handle: h})
				case "symlink":
					got := f.call(ro, nonowner, w.ReadlinkRequest{Node: rn.id}).(w.ReadlinkReply)
					if string(got.Target) != "file" {
						t.Fatal(got)
					}
				}
				f.call(ro, nonowner, w.ListXAttrRequest{Node: rn.id, Size: w.MaxXAttr})
				st, err := stat(rn.fd)
				must(t, err)
				if st.Atim != before[name].Atim {
					t.Fatal("RO changed backing atime", name, before[name].Atim, st.Atim)
				}
			}
			var canonicalAfter unix.Statfs_t
			must(t, unix.Fstatfs(rootFD, &canonicalAfter))
			if canonicalAfter.Flags != canonicalBefore.Flags {
				t.Fatal("clone changed canonical mount flags")
			}
		})
	}
}
