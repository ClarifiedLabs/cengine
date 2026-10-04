//go:build linux

package boot

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelFilesystemsMountDevptsAfterDevtmpfs(t *testing.T) {
	filesystems := kernelFilesystems()
	if len(filesystems) < 2 {
		t.Fatalf("kernel filesystem list has %d entries", len(filesystems))
	}
	if filesystems[0].kind != "devtmpfs" || filesystems[0].target != "/dev" {
		t.Fatalf("first kernel filesystem = %#v", filesystems[0])
	}
	if filesystems[1].kind != "devpts" || filesystems[1].target != "/dev/pts" {
		t.Fatalf("second kernel filesystem = %#v", filesystems[1])
	}
}

func TestFuseControlPrivateKernelFilesystem(t *testing.T) {
	seenSysfs, found := false, false
	for _, fs := range kernelFilesystems() {
		if fs.kind == "sysfs" {
			seenSysfs = true
		}
		if fs.kind == "fusectl" {
			found = true
			if !seenSysfs || fs.target != "/sys/fs/fuse/connections" || fs.flags != unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV {
				t.Fatal(fs)
			}
		}
	}
	if !found {
		t.Fatal("missing fusectl")
	}
	good := "20 1 0:21 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec - fusectl fusectl rw\n"
	if found, err := fuseControlMounted(good); !found || err != nil {
		t.Fatal(found, err)
	}
	if found, err := fuseControlMounted(""); found || err != nil {
		t.Fatal(found, err)
	}
	for _, bad := range []string{good + good, "20 1 0:21 / /sys/fs/fuse/connections rw - tmpfs tmpfs rw\n", "20 1 0:21 /subdir /sys/fs/fuse/connections rw,nosuid,nodev,noexec - fusectl fusectl rw\n"} {
		if _, err := fuseControlMounted(bad); err == nil {
			t.Fatal("substitution accepted")
		}
	}
}

func TestLinkPseudoTerminalMultiplexer(t *testing.T) {
	deviceRoot := t.TempDir()
	path := filepath.Join(deviceRoot, "ptmx")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := linkPseudoTerminalMultiplexer(deviceRoot); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(path)
	if err != nil {
		t.Fatal(err)
	}
	if target != "pts/ptmx" {
		t.Fatalf("ptmx target = %q", target)
	}
}
