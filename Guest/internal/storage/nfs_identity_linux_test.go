//go:build linux

package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	nfs "github.com/willscott/go-nfs"
	"golang.org/x/sys/unix"
)

func TestNFSRequestIdentityKernelPermissions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root with SETUID/SETGID capabilities")
	}
	root := t.TempDir()
	h := newVolumeNFSHandler(root)
	if h.filesystem.rootErr != nil {
		t.Fatal(h.filesystem.rootErr)
	}
	defer h.filesystem.confined.Close()
	defer h.filesystem.rootFile.Close()
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	beforeGroups, _ := unix.Getgroups()
	uid, gid := os.Geteuid(), os.Getegid()
	run := func(id nfs.Identity, fn func() error) {
		t.Helper()
		if err := h.WithIdentity(context.Background(), id, fn); err != nil {
			t.Fatal(err)
		}
	}
	owner := nfs.Identity{UID: 10001, GID: 10001}
	stranger := nfs.Identity{UID: 10002, GID: 10002}
	f := h.filesystem
	run(owner, func() error {
		file, err := f.OpenFile("secret", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.(*nfsOSFile).Fd()), &stat); err != nil {
			return err
		}
		if stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&07777 != 0600 {
			return fmt.Errorf("immediate descriptor metadata: %+v", stat)
		}
		_, err = file.Write([]byte("disposable"))
		return err
	})
	run(stranger, func() error {
		for _, flags := range []int{os.O_RDONLY, os.O_WRONLY, os.O_WRONLY | os.O_TRUNC} {
			file, err := f.OpenFile("secret", flags, 0)
			if file != nil {
				file.Close()
			}
			if !errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("unauthorized open %d: %v", flags, err)
			}
		}
		mask, err := f.Access("secret", 1|4|8|32)
		if err != nil || mask != 0 {
			return fmt.Errorf("unauthorized ACCESS: %x %v", mask, err)
		}
		if err := f.Chmod("secret", 0644); !errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("unauthorized chmod: %v", err)
		}
		if err := f.Lchown("secret", 10002, 10002); !errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("unauthorized chown: %v", err)
		}
		size := uint64(0)
		if err := (&nfs.SetFileAttributes{SetSize: &size}).Apply(f, f, "secret"); err == nil {
			return fmt.Errorf("unauthorized SETATTR size")
		}
		return nil
	})
	run(owner, func() error {
		if err := f.Lchown("secret", 0, 0); !errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("owner can chown to root: %v", err)
		}
		file, err := f.Open("secret")
		if err != nil {
			return err
		}
		return file.Close()
	})
	if err := os.Mkdir(filepath.Join(root, "group"), 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(root, "group"), 0, 2000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "group"), os.ModeSetgid|0770); err != nil {
		t.Fatal(err)
	}
	run(nfs.Identity{UID: 10001, GID: 10001, Groups: []uint32{2000}}, func() error {
		if err := f.MkdirAll("group/dir", 0770); err != nil {
			return err
		}
		if err := f.Symlink("dir", "group/link"); err != nil {
			return err
		}
		file, err := f.OpenFile("group/file", os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		file.Close()
		for _, name := range []string{"group/dir", "group/link", "group/file"} {
			info, err := f.Lstat(name)
			if err != nil {
				return err
			}
			attr := nfs.ToFileAttribute(info, name)
			if attr.UID != 10001 || attr.GID != 2000 {
				return fmt.Errorf("setgid ownership %s: %d:%d", name, attr.UID, attr.GID)
			}
			if name == "group/dir" && attr.FileMode&02000 == 0 {
				return fmt.Errorf("setgid mode not inherited")
			}
		}
		return nil
	})
	run(stranger, func() error {
		for name, op := range map[string]func() error{
			"mkdir":   func() error { return f.MkdirAll("group/no", 0700) },
			"symlink": func() error { return f.Symlink("file", "group/no") },
			"unlink":  func() error { return f.Remove("group/file") },
			"rmdir":   func() error { return f.Remove("group/dir") },
			"rename":  func() error { return f.Rename("group/file", "stolen") },
			"link":    func() error { return f.Link("group/file", "stolen") },
			"fifo":    func() error { return f.Mkfifo("group/no", 0600) },
			"socket":  func() error { return f.Socket("group/no") },
			"mknod":   func() error { return f.Mknod("device", unix.S_IFCHR|0600, 1, 3) },
		} {
			if err := op(); !errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("unauthorized %s: %v", name, err)
			}
		}
		return nil
	})
	// Every concurrently running request gets its own primary/supplementary IDs.
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := nfs.Identity{UID: uint32(11000 + i), GID: uint32(12000 + i), Groups: []uint32{uint32(13000 + i)}}
			errs <- h.WithIdentity(context.Background(), id, func() error {
				if uint32(os.Geteuid()) != id.UID || uint32(os.Getegid()) != id.GID {
					return fmt.Errorf("identity leaked")
				}
				groups, err := unix.Getgroups()
				if err != nil || !reflect.DeepEqual(groups, []int{13000 + i}) {
					return fmt.Errorf("groups leaked: %v %v", groups, err)
				}
				file, err := f.OpenFile(fmt.Sprintf("concurrent-%d", i), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					return err
				}
				return file.Close()
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	afterGroups, _ := unix.Getgroups()
	if os.Geteuid() != uid || os.Getegid() != gid || !reflect.DeepEqual(beforeGroups, afterGroups) {
		t.Fatal("service credentials changed")
	}
}

func TestNFSExportRootIsSearchableRegardlessOfServiceCreationOrder(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root")
	}
	for _, mode := range []os.FileMode{0700, 0755} {
		t.Run(fmt.Sprintf("initial=%o", mode), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "export")
			if err := os.MkdirAll(filepath.Join(root, "volumes"), mode); err != nil {
				t.Fatal(err)
			}
			h := newVolumeNFSHandler(root)
			if h.filesystem.rootErr != nil {
				t.Fatal(h.filesystem.rootErr)
			}
			defer h.filesystem.confined.Close()
			defer h.filesystem.rootFile.Close()
			volume := filepath.Join(root, "named")
			if err := os.Mkdir(volume, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(volume, 10001, 10001); err != nil {
				t.Fatal(err)
			}
			if err := h.prepareExportRoot(); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(volume)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatalf("named root changed: %v %v", info, err)
			}
			if err := h.WithIdentity(context.Background(), nfs.Identity{UID: 10001, GID: 10001}, func() error {
				file, err := h.filesystem.OpenFile("named/probe", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if err != nil {
					return err
				}
				file.Close()
				file, err = h.filesystem.Open("named/probe")
				if err != nil {
					return err
				}
				return file.Close()
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNFSIdentityPanicReleasesSlotAndRetiresCredentials(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root")
	}
	h := newVolumeNFSHandler(t.TempDir())
	defer h.filesystem.confined.Close()
	defer h.filesystem.rootFile.Close()
	for i := 0; i < 65; i++ {
		err := h.WithIdentity(context.Background(), nfs.Identity{UID: 10001, GID: 10001}, func() error { panic("request data must not escape") })
		if err == nil || err.Error() != "NFS identity callback panicked" {
			t.Fatalf("panic result: %v", err)
		}
	}
	if err := h.WithIdentity(context.Background(), nfs.Identity{UID: 10002, GID: 10002}, func() error {
		if os.Geteuid() != 10002 || os.Getegid() != 10002 {
			return errors.New("credentials reused after panic")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Fatal("service identity changed")
	}
}

func TestNFSAccessStickySymlinkUsesLinkOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root")
	}
	root := t.TempDir()
	h := newVolumeNFSHandler(root)
	defer h.filesystem.confined.Close()
	defer h.filesystem.rootFile.Close()
	if err := os.Chmod(root, os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(root, "target"), 10001, 10001); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(filepath.Join(root, "link"), 10002, 10002); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []uint32{10001, 10002} {
		if err := h.WithIdentity(context.Background(), nfs.Identity{UID: uid, GID: uid}, func() error {
			mask, err := h.filesystem.Access("link", 16)
			if err != nil {
				return err
			}
			if (mask&16 != 0) != (uid == 10002) {
				return fmt.Errorf("DELETE mask=%d for uid=%d", mask, uid)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNFSMetadataAndDataStayConfined(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	h := newVolumeNFSHandler(root)
	defer h.filesystem.confined.Close()
	defer h.filesystem.rootFile.Close()
	f := h.filesystem
	if err := f.Symlink(outside, "escape"); err != nil {
		t.Fatal(err)
	}
	for name, op := range map[string]func() error{
		"chmod": func() error { return f.Chmod("escape/target", 0777) },
		"chown": func() error { return f.Lchown("escape/target", 1234, 1234) },
		"create": func() error {
			file, err := f.Create("escape/new")
			if file != nil {
				file.Close()
			}
			return err
		},
		"link":   func() error { return f.Link("escape/target", "stolen") },
		"remove": func() error { return f.Remove("escape/target") },
	} {
		if err := op(); err == nil {
			t.Errorf("%s escaped export", name)
		}
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("outside metadata changed: %v %v", info, err)
	}
}
