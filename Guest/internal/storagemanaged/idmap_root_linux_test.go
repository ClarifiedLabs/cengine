//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestManagedRootStatmountResultValidation(t *testing.T) {
	if unsafe.Sizeof(mountIDRequest{}) != 24 || unsafe.Sizeof(mountStatus{}) != 512 || unsafe.Offsetof(mountStatus{}.ID) != 40 || unsafe.Offsetof(mountStatus{}.Attr) != 64 {
		t.Fatal("statmount UAPI layout mismatch")
	}
	valid := mountStatus{Size: 512, Mask: statmountMountBasic, ID: 1 << 32}
	for _, tc := range []struct {
		name string
		edit func(*mountStatus)
		want error
	}{
		{"unmapped", func(*mountStatus) {}, nil},
		{"idmapped", func(s *mountStatus) { s.Attr = unix.MOUNT_ATTR_IDMAP }, unix.EXDEV},
		{"missing-mask", func(s *mountStatus) { s.Mask = 0 }, unix.EOPNOTSUPP},
		{"short-result", func(s *mountStatus) { s.Size = 71 }, unix.EOPNOTSUPP},
		{"oversized-result", func(s *mountStatus) { s.Size = 513 }, unix.EOPNOTSUPP},
		{"wrong-mount", func(s *mountStatus) { s.ID++ }, unix.ESTALE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := valid
			tc.edit(&st)
			if err := validateUnmappedMount(st, valid.ID); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := requireUnmappedMount(-1); !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid descriptor accepted: %v", err)
	}
}

const idmapRootProbeEnv = "CENGINE_MANAGED_IDMAP_ROOT_PROBE"
const idmapUserNSHelperEnv = "CENGINE_MANAGED_IDMAP_USERNS_HELPER"

// All mount changes happen in this test-only subprocess's private namespace.
// Non-root runs skip; root runs must fail, not skip, for missing kernel support.
func TestManagedSetupRejectsIDMappedBackingRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root and ext4 TMPDIR")
	}
	if os.Getenv(idmapRootProbeEnv) != "1" {
		binary, err := os.Executable()
		must(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestManagedSetupRejectsIDMappedBackingRoot$", "-test.v")
		cmd.Env = append(os.Environ(), idmapRootProbeEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated idmap root probe: %v\n%s", err, output)
		}
		return
	}
	must(t, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
	path := t.TempDir()
	var fs unix.Statfs_t
	must(t, unix.Statfs(path, &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatalf("TMPDIR must be ext4, got %#x", fs.Type)
	}
	root, err := os.Open(path)
	must(t, err)
	t.Cleanup(func() { must(t, root.Close()) })
	canonicalID, err := requireUnmappedMount(int(root.Fd()))
	must(t, err)
	canonical, err := stat(int(root.Fd()))
	must(t, err)
	for _, mode := range []a.Mode{a.ReadWrite, a.ReadOnly} {
		t.Run("ordinary-"+string(mode), func(t *testing.T) {
			s := idmapSetupSession(t, root, mode)
			entry, err := s.initialize()
			must(t, err)
			view := s.nodes[entry.Node].fd
			viewID, err := uniqueMountID(view)
			must(t, err)
			got, err := stat(view)
			must(t, err)
			if got.Dev != canonical.Dev || got.Ino != canonical.Ino || got.Uid != canonical.Uid || got.Gid != canonical.Gid {
				t.Fatalf("view lost canonical inode/ownership: canonical=%+v view=%+v", canonical, got)
			}
			if mode == a.ReadOnly {
				if viewID == canonicalID {
					t.Fatal("RO reused canonical mount instead of cloning")
				}
				var viewFS unix.Statfs_t
				must(t, unix.Fstatfs(view, &viewFS))
				if viewFS.Flags&(unix.ST_RDONLY|unix.ST_NOATIME) != unix.ST_RDONLY|unix.ST_NOATIME {
					t.Fatal("clone lacks RO/noatime", viewFS.Flags)
				}
				flags, err := unix.FcntlInt(uintptr(view), unix.F_GETFD, 0)
				must(t, err)
				if flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("clone is not CLOEXEC")
				}
			} else if viewID != canonicalID {
				t.Fatal("RW substituted canonical mount")
			}
			id, err := requireUnmappedMount(int(root.Fd()))
			must(t, err)
			var after unix.Statfs_t
			must(t, unix.Fstatfs(int(root.Fd()), &after))
			if id != canonicalID || after.Flags != fs.Flags {
				t.Fatal("view setup changed canonical mount")
			}
		})
	}

	userns := idmapTestUserNamespace(t)
	clone, err := unix.OpenTree(int(root.Fd()), "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	must(t, err)
	t.Cleanup(func() { must(t, unix.Close(clone)) })
	must(t, unix.MountSetattr(clone, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_IDMAP, Userns_fd: uint64(userns.Fd())}))
	before, err := stat(int(root.Fd()))
	must(t, err)
	mapped, err := stat(clone)
	must(t, err)
	if before.Dev != mapped.Dev || before.Ino != mapped.Ino || before.Uid == mapped.Uid || before.Gid == mapped.Gid {
		t.Fatalf("fixture must preserve inode and change ownership: before=%+v mapped=%+v", before, mapped)
	}
	t.Run("detached-canonical-fails-closed", func(t *testing.T) {
		if _, err := requireUnmappedMount(clone); err == nil {
			t.Fatal("unqueryable detached idmap accepted as canonical")
		}
	})

	// Only the fixture attaches mounts: Linux 6.18's authoritative unique-ID
	// query can then reject this real idmapped canonical root in both modes.
	target := filepath.Join(path, "mapped")
	must(t, os.Mkdir(target, 0700))
	must(t, unix.MoveMount(clone, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH))
	t.Cleanup(func() { must(t, unix.Unmount(target, unix.MNT_DETACH)) })
	bound, err := os.Open(target)
	must(t, err)
	t.Cleanup(func() { must(t, bound.Close()) })
	for _, mode := range []a.Mode{a.ReadWrite, a.ReadOnly} {
		t.Run("idmapped-"+string(mode), func(t *testing.T) {
			s := idmapSetupSession(t, bound, mode)
			if entry, err := s.initialize(); !errors.Is(err, unix.EXDEV) || entry != (w.Entry{}) {
				t.Fatalf("idmapped root initialized: entry=%+v err=%v", entry, err)
			}
			if len(s.nodes) != 0 || len(s.registry.objects) != 0 {
				t.Fatal("rejected root retained operational/identity pins")
			}
			if mode == a.ReadOnly {
				if fd, err := s.operationRoot(); !errors.Is(err, unix.EXDEV) || fd != -1 {
					if fd >= 0 {
						unix.Close(fd)
					}
					t.Fatalf("RO clone bypassed canonical idmap check: fd=%d err=%v", fd, err)
				}
			}
		})
	}
	t.Run("clone-inherits-idmap-through-ro-noatime", func(t *testing.T) {
		inherited, err := unix.OpenTree(int(bound.Fd()), "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
		must(t, err)
		t.Cleanup(func() { must(t, unix.Close(inherited)) })
		must(t, unix.MountSetattr(inherited, "", unix.AT_EMPTY_PATH, &unix.MountAttr{
			Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOATIME,
			Attr_clr: unix.MOUNT_ATTR__ATIME,
		}))
		got, err := stat(inherited)
		must(t, err)
		if got.Dev != mapped.Dev || got.Ino != mapped.Ino || got.Uid != mapped.Uid || got.Gid != mapped.Gid {
			t.Fatal("clone/flag-only setattr changed inherited identity", mapped, got)
		}
		id, err := uniqueMountID(inherited)
		must(t, err)
		sourceID, err := uniqueMountID(int(bound.Fd()))
		must(t, err)
		if id == sourceID {
			t.Fatal("clone reused source mount")
		}
		// Attach only in this private test namespace to query the inherited map.
		inheritedPath := filepath.Join(path, "inherited")
		must(t, os.Mkdir(inheritedPath, 0700))
		must(t, unix.MoveMount(inherited, "", unix.AT_FDCWD, inheritedPath, unix.MOVE_MOUNT_F_EMPTY_PATH))
		t.Cleanup(func() { must(t, unix.Unmount(inheritedPath, unix.MNT_DETACH)) })
		if _, err := requireUnmappedMount(inherited); !errors.Is(err, unix.EXDEV) {
			t.Fatalf("flag-only setattr removed inherited idmap: %v", err)
		}
	})
}

func idmapSetupSession(t *testing.T, root *os.File, mode a.Mode) *Session {
	t.Helper()
	r, err := NewRegistry(new(sync.Mutex))
	must(t, err)
	s := &Session{root: root, binding: a.Binding{Mode: mode}, registry: r, nodes: make(map[w.NodeID]*node), byInode: make(map[inodeKey]*node)}
	t.Cleanup(func() {
		for _, n := range s.nodes {
			must(t, unix.Close(n.fd))
		}
		for _, obj := range r.objects {
			must(t, unix.Close(obj.fd))
		}
	})
	return s
}

func idmapTestUserNamespace(t *testing.T) *os.File {
	t.Helper()
	binary, err := os.Executable()
	must(t, err)
	readyR, readyW, err := os.Pipe()
	must(t, err)
	defer readyR.Close()
	defer readyW.Close()
	doneR, doneW, err := os.Pipe()
	must(t, err)
	defer doneR.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestManagedIDMapUserNamespaceHelper$")
	cmd.Env = append(os.Environ(), idmapUserNSHelperEnv+"=1")
	cmd.ExtraFiles = []*os.File{readyW, doneR}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 100000, Size: 65536}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 100000, Size: 65536}},
		GidMappingsEnableSetgroups: false,
	}
	if err := cmd.Start(); err != nil {
		cancel()
		doneW.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { doneW.Close(); must(t, cmd.Wait()); cancel() })
	must(t, readyW.Close())
	var ready [1]byte
	_, err = io.ReadFull(readyR, ready[:])
	must(t, err)
	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/user", cmd.Process.Pid))
	must(t, err)
	t.Cleanup(func() { must(t, ns.Close()) })
	return ns
}

func TestManagedIDMapUserNamespaceHelper(t *testing.T) {
	if os.Getenv(idmapUserNSHelperEnv) != "1" {
		t.Skip("controlled idmapped-mount fixture helper only")
	}
	ready := os.NewFile(3, "ready")
	done := os.NewFile(4, "done")
	defer ready.Close()
	defer done.Close()
	_, err := ready.Write([]byte{1})
	must(t, err)
	_, err = io.Copy(io.Discard, done)
	must(t, err)
}
