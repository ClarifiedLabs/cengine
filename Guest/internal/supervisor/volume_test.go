//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
)

func TestVolumeRequiresBlockDeviceOrManagedAttachment(t *testing.T) {
	for _, mount := range []protocol.Mount{
		{Kind: "volume", Source: "data"},
		{Kind: "volume", Source: "data", Device: "/dev/vdb"},
		{Kind: "volume", Source: "data", ManagedAttachment: "managed"},
	} {
		err := validateVolumeMounts(protocol.WorkloadSpec{Mounts: []protocol.Mount{mount}})
		valid := mount.Device != "" || mount.ManagedAttachment != ""
		if (err == nil) != valid {
			t.Fatalf("mount %+v: %v", mount, err)
		}
	}
}

func TestPrepareVolumeRejectsPathNames(t *testing.T) {
	for _, name := range []string{
		"", ".", "..", "nested/data", "data\x00suffix", strings.Repeat("a", 256),
	} {
		err := prepareVolume(protocol.Mount{Kind: "volume", Source: name, Device: "/dev/vdb"})
		if err == nil || !strings.Contains(err.Error(), "invalid volume name") {
			t.Fatalf("prepareVolume(%q) error = %v, want invalid volume name", name, err)
		}
	}
}

func TestInitializeVolumeRejectsSymlinkedCopySource(t *testing.T) {
	rootfs := t.TempDir()
	volume := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootfs, "data")); err != nil {
		t.Fatal(err)
	}
	err := initializeVolumeAt(rootfs, volume, protocol.Mount{Destination: "/data"})
	if err == nil {
		t.Fatal("symlinked copy-up source unexpectedly accepted")
	}
	entries, readErr := os.ReadDir(volume)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("volume changed after rejected source: %#v", entries)
	}
}

func TestInitializeVolumeLostFoundAuthority(t *testing.T) {
	for _, kind := range []string{"empty-directory", "populated-directory", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			rootfs, volume := t.TempDir(), t.TempDir()
			// Go's TempDir does not promise a particular permission mode.
			if err := os.Chmod(volume, 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(rootfs, "data")
			if err := os.Mkdir(source, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "seed"), []byte("image"), 0600); err != nil {
				t.Fatal(err)
			}
			lostFound := filepath.Join(volume, "lost+found")
			sentinel := lostFound
			switch kind {
			case "empty-directory", "populated-directory":
				if err := os.Mkdir(lostFound, 0700); err != nil {
					t.Fatal(err)
				}
				sentinel = filepath.Join(lostFound, "sentinel")
				if kind == "populated-directory" {
					if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "file":
				if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				// Even a link to an empty directory is authoritative, not ext4's directory.
				if err := os.Symlink(t.TempDir(), lostFound); err != nil {
					t.Fatal(err)
				}
			}
			empty, err := dockerVolumeIsEmpty(volume)
			wantEmpty := kind == "empty-directory"
			if err != nil || empty != wantEmpty {
				t.Fatalf("emptiness = %v, %v; want %v", empty, err, wantEmpty)
			}
			if err := initializeVolumeAt(rootfs, volume, protocol.Mount{Destination: "/data"}); err != nil {
				t.Fatal(err)
			}
			seed, err := os.ReadFile(filepath.Join(volume, "seed"))
			if wantEmpty {
				if err != nil || string(seed) != "image" {
					t.Fatalf("fresh volume seed = %q, %v", seed, err)
				}
			} else {
				if !os.IsNotExist(err) {
					t.Fatalf("authoritative volume was seeded: %q, %v", seed, err)
				}
				assertVolumeRootMetadata(t, volume, uint32(os.Geteuid()), uint32(os.Getegid()), 0700)
				if kind == "symlink" {
					if _, err := os.Readlink(lostFound); err != nil {
						t.Fatal(err)
					}
				} else if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
					t.Fatalf("sentinel = %q, %v", data, err)
				}
			}
		})
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
