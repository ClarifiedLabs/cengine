//go:build linux

package boot

import (
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
