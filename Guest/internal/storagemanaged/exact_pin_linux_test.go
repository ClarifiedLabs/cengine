//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"os"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestExactPinsRecoverUnobservedAliasesWithoutEnumeration(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "file"
		if symlink {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			s, root := f.session(a.ReadWrite)
			owner := caller(1001, 1001)
			protected, err := os.ReadFile("/proc/sys/fs/protected_hardlinks")
			must(t, err)
			if strings.TrimSpace(string(protected)) != "1" {
				t.Fatal("requires protected_hardlinks=1")
			}
			rootFD := int(f.volume.Fd())
			target, err := unix.Openat(rootFD, "target", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0666)
			must(t, err)
			defer unix.Close(target)
			_, err = unix.Write(target, []byte("unchanged"))
			must(t, err)
			must(t, unix.Fsetxattr(target, "user.proof", []byte("unchanged"), 0))
			targetBefore, err := stat(target)
			must(t, err)
			must(t, unix.Mkdirat(rootFD, "hidden", 0111))
			hidden, err := pinAt(rootFD, "hidden")
			must(t, err)
			defer unix.Close(hidden)
			for _, name := range []string{"known", "native"} {
				if symlink {
					must(t, unix.Symlinkat("target", rootFD, name))
				} else {
					fd, err := unix.Openat(rootFD, name, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0600)
					must(t, err)
					must(t, unix.Close(fd))
				}
				must(t, unix.Fchownat(rootFD, name, 1001, 1001, unix.AT_SYMLINK_NOFOLLOW))
			}
			must(t, unix.Linkat(rootFD, "known", hidden, "never-observed", 0))
			n := f.call(s, owner, w.LookupRequest{Parent: root.Node, Name: []byte("known")}).(w.LookupReply).Entry
			f.call(s, owner, w.UnlinkRequest{Parent: root.Node, Name: []byte("known")})
			// There is deliberately no session lookup of hidden or its alias; caller
			// can search it but cannot enumerate it, even for bounded recovery scans.
			must(t, f.worker.Do(*owner.Caller, 0, func() error {
				fd, e := unix.Openat(rootFD, "hidden", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
				if e == nil {
					unix.Close(fd)
					return errors.New("hidden directory was enumerable")
				}
				if !errors.Is(e, unix.EACCES) {
					return e
				}
				return nil
			}))
			f.wantError(s, caller(1002, 1002), w.LinkRequest{Source: n.Node, Parent: root.Node, Name: []byte("denied")}, unix.EPERM)
			alias := f.call(s, owner, w.LinkRequest{Source: n.Node, Parent: root.Node, Name: []byte("restored")}).(w.LinkReply).Entry
			if alias.Object != n.Object || alias.Attr.Nlink != 2 || alias.Attr.Mode&unix.S_IFMT != n.Attr.Mode&unix.S_IFMT {
				t.Fatal("wrong exact source", alias)
			}
			for _, unlinked := range []bool{false, true} {
				if unlinked {
					f.call(s, owner, w.UnlinkRequest{Parent: root.Node, Name: []byte("restored")})
					must(t, unix.Unlinkat(hidden, "never-observed", 0))
					f.wantError(s, owner, w.LinkRequest{Source: n.Node, Parent: root.Node, Name: []byte("resurrected")}, unix.ENOENT)
				}
				if symlink {
					for _, auth := range []w.Auth{owner, caller(1002, 1002), fullCaller(t)} {
						for _, c := range xattrCases {
							path := procFD(rootFD) + "/native"
							compareXattr(t, f, s, n.Node, auth, c, func(b []byte) (int, error) {
								switch c.kind {
								case 0:
									return unix.Lgetxattr(path, c.name, b)
								case 1:
									return unix.Llistxattr(path, b)
								case 2:
									return 0, unix.Lsetxattr(path, c.name, c.value, 0)
								default:
									return 0, unix.Lremovexattr(path, c.name)
								}
							})
						}
					}
				}
			}
			targetAfter, err := stat(target)
			must(t, err)
			if targetBefore != targetAfter {
				t.Fatal("exact symlink operation touched target inode", targetBefore, targetAfter)
			}
			value := make([]byte, 32)
			count, err := unix.Fgetxattr(target, "user.proof", value)
			must(t, err)
			if string(value[:count]) != "unchanged" {
				t.Fatal("target xattr changed")
			}
			count, err = unix.Pread(target, value, 0)
			must(t, err)
			if string(value[:count]) != "unchanged" {
				t.Fatal("target data changed")
			}
		})
	}
}
