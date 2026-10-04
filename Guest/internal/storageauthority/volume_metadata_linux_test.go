//go:build linux

package storageauthority

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Requires actual Linux root. Darwin and cross-compilation cannot establish
// kernel credential enforcement; the parent runs this separately when available.
func TestVolumeCreateNativeDefaultsAndTraversal(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires actual Linux root:root for fresh-volume credential proof")
	}
	f := newFixture(t, nil)
	created, err := f.a.CreateVolume(f.control, createRequest(t, f, "nonroot-defaults"))
	must(t, err)
	binding, peer := f.runtime(created.Volume, ReadWrite)
	guard, err := f.a.Admit(peer, created.Volume.ID, false)
	must(t, err)
	defer guard.Release()
	root, err := guard.DupVolumeRoot()
	must(t, err)
	defer root.Close()
	var stat unix.Stat_t
	must(t, unix.Fstat(int(root.Fd()), &stat))
	if stat.Mode&07777 != 0755 || stat.Uid != 0 || stat.Gid != 0 {
		t.Fatalf("fresh production root mode=%#o uid=%d gid=%d", stat.Mode&07777, stat.Uid, stat.Gid)
	}
	// Inherited root capability models the root presented to a consumer without
	// making the authority/export parent traversable. Exec is pinned too: the
	// dropped-credential child never traverses the test runner's private paths.
	executable, err := os.Open("/proc/self/exe")
	must(t, err)
	defer executable.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/fd/4", "-test.run=^TestVolumeCreateTraversalChild$", "-test.count=1")
	command.ExtraFiles = []*os.File{root, executable}
	command.Env = []string{"CENGINE_VOLUME_TRAVERSAL_CHILD=1", "GORACE=atexit_sleep_ms=0"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("nonroot traversal: %v\n%s", err, output)
	}
	must(t, root.Close())
	guard.Release()
	f.retire(binding)
}

func TestVolumeCreateTraversalChild(t *testing.T) {
	if os.Getenv("CENGINE_VOLUME_TRAVERSAL_CHILD") != "1" {
		return
	}
	if os.Geteuid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("kernel did not drop credentials")
	}
	groups, err := os.Getgroups()
	must(t, err)
	if len(groups) != 0 {
		t.Fatal("unexpected supplementary group")
	}
	fd, err := unix.Openat(3, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	must(t, err)
	defer unix.Close(fd)
	if _, err := unix.ReadDirent(fd, make([]byte, 4096)); err != nil {
		t.Fatal("default root not readable/traversable", err)
	}
	created, err := unix.Openat(3, "must-not-create", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
	if err == nil {
		unix.Close(created)
		t.Fatal("default root allowed nonroot write")
	}
	if !errors.Is(err, unix.EACCES) {
		t.Fatal("unexpected nonroot create result", err)
	}
}
