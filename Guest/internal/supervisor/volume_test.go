//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
)

func TestSharedVolumeRequiresEngineManagedServer(t *testing.T) {
	spec := protocol.WorkloadSpec{Mounts: []protocol.Mount{{Kind: "volume", Source: "data"}}}
	err := validateVolumeMounts(spec)
	if err == nil || !strings.Contains(err.Error(), "has no volume server") {
		t.Fatalf("validateVolumeMounts error = %v, want missing volume server", err)
	}
	spec.VolumeServer = "100.64.0.1"
	if err := validateVolumeMounts(spec); err != nil {
		t.Fatalf("shared volume with server was rejected: %v", err)
	}
}

func TestPrepareVolumeRejectsPathNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "nested/data"} {
		err := prepareVolume(protocol.Mount{Kind: "volume", Source: name, Device: "/dev/vdb"})
		if err == nil || !strings.Contains(err.Error(), "invalid volume name") {
			t.Fatalf("prepareVolume(%q) error = %v, want invalid volume name", name, err)
		}
	}
}

func TestFreshExt4VolumeIsEmptyForDockerCopyUp(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "lost+found"), 0700); err != nil {
		t.Fatal(err)
	}
	empty, err := dockerVolumeIsEmpty(root)
	if err != nil || !empty {
		t.Fatalf("dockerVolumeIsEmpty() = %v, %v, want true", empty, err)
	}
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("present"), 0600); err != nil {
		t.Fatal(err)
	}
	empty, err = dockerVolumeIsEmpty(root)
	if err != nil || empty {
		t.Fatalf("dockerVolumeIsEmpty() = %v, %v, want false", empty, err)
	}
}
