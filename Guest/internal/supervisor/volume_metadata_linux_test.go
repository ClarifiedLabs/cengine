//go:build linux

package supervisor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestInitializeVolumeCopiesRootMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for non-root ownership")
	}
	for _, populated := range []bool{false, true} {
		for _, mode := range []uint32{0700, 02770, 07770, 0000} {
			t.Run(fmt.Sprintf("populated=%v/mode=%o", populated, mode), func(t *testing.T) {
				rootfs, volume := t.TempDir(), t.TempDir()
				source := filepath.Join(rootfs, "data")
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
				if populated {
					if err := os.WriteFile(filepath.Join(source, "seed"), []byte("seed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chown(source, 10001, 10002); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chmod(source, mode); err != nil {
					t.Fatal(err)
				}
				if err := initializeVolumeAt(rootfs, volume, protocol.Mount{Destination: "/data"}); err != nil {
					t.Fatal(err)
				}
				assertVolumeRootMetadata(t, volume, 10001, 10002, mode)
				if _, err := os.Lstat(filepath.Join(volume, confinedCopyTransactionName)); !os.IsNotExist(err) {
					t.Fatalf("transaction remains: %v", err)
				}
			})
		}
	}
}

func TestInitializeNonemptyVolumePreservesRootMetadata(t *testing.T) {
	rootfs, volume := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(rootfs, "data"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volume, "existing"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(volume, 02710); err != nil {
		t.Fatal(err)
	}
	if err := initializeVolumeAt(rootfs, volume, protocol.Mount{Destination: "/data"}); err != nil {
		t.Fatal(err)
	}
	assertVolumeRootMetadata(t, volume, uint32(os.Geteuid()), uint32(os.Getegid()), 02710)
}

func TestRecoverCopyupRestoresRootMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for non-root ownership")
	}
	for _, populated := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("populated=%v/partial=%v", populated, partial), func(t *testing.T) {
				sourcePath, destinationPath := t.TempDir(), t.TempDir()
				if populated {
					if err := os.WriteFile(filepath.Join(sourcePath, "seed"), []byte("seed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chown(destinationPath, 10003, 10004); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chmod(destinationPath, 03750); err != nil {
					t.Fatal(err)
				}
				source, err := openConfinedRoot(sourcePath)
				if err != nil {
					t.Fatal(err)
				}
				defer source.close()
				destination, err := openConfinedRoot(destinationPath)
				if err != nil {
					t.Fatal(err)
				}
				defer destination.close()
				publishStaleConfinedCopyTransaction(t, source, destination)
				// Simulate interruption after chown, or after the final chmod.
				if err := os.Chown(destinationPath, 10001, 10002); err != nil {
					t.Fatal(err)
				}
				if !partial {
					if err := unix.Chmod(destinationPath, 0000); err != nil {
						t.Fatal(err)
					}
				}
				if err := recoverConfinedCopyTransaction(destination); err != nil {
					t.Fatal(err)
				}
				assertVolumeRootMetadata(t, destinationPath, 10003, 10004, 03750)
				entries, err := os.ReadDir(destinationPath)
				if err != nil || len(entries) != 0 {
					t.Fatalf("rollback entries = %v, %v", entries, err)
				}
			})
		}
	}
}

func TestFailedCopyupPreservesRootMetadata(t *testing.T) {
	sourcePath, destinationPath := t.TempDir(), t.TempDir()
	if err := unix.Mkfifo(filepath.Join(sourcePath, "unsupported"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(destinationPath, 03750); err != nil {
		t.Fatal(err)
	}
	source, err := openConfinedRoot(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	destination, err := openConfinedRoot(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.close()
	if err := copyConfinedDirectory(source, destination); err == nil {
		t.Fatal("special file accepted")
	}
	assertVolumeRootMetadata(t, destinationPath, uint32(os.Geteuid()), uint32(os.Getegid()), 03750)
}

func TestCopyupRecoveryAcceptsReassignedDeviceAndRejectsForeignFilesystem(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreign=%v", foreign), func(t *testing.T) {
			sourcePath, destinationPath := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(sourcePath, "seed"), []byte("seed"), 0600); err != nil {
				t.Fatal(err)
			}
			source, err := openConfinedRoot(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.close()
			destination, err := openConfinedRoot(destinationPath)
			if err != nil {
				t.Fatal(err)
			}
			defer destination.close()
			publishStaleConfinedCopyTransaction(t, source, destination)
			manifestPath := filepath.Join(destinationPath, confinedCopyTransactionName, confinedCopyManifestName)
			data, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest confinedCopyManifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.Root.Device++
			for index := range manifest.Entries {
				manifest.Entries[index].Device = manifest.Root.Device
			}
			if foreign {
				manifest.Root.Filesystem[0]++
			}
			data, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			err = recoverConfinedCopyTransaction(destination)
			if foreign {
				if err == nil {
					t.Fatal("foreign filesystem accepted")
				}
				if _, err := os.Stat(filepath.Join(destinationPath, "seed")); err != nil {
					t.Fatal("foreign recovery removed contents")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(destinationPath)
				if err != nil || len(entries) != 0 {
					t.Fatalf("reassigned recovery = %v, %v", entries, err)
				}
			}
		})
	}
}

func TestCopyupRecoveryRejectsUntrustedJournal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for forged unprivileged journal")
	}
	for _, untrustedOwner := range []bool{false, true} {
		t.Run(fmt.Sprintf("untrustedOwner=%v", untrustedOwner), func(t *testing.T) {
			path := t.TempDir()
			root, err := openConfinedRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.close()
			original, err := confinedRootMetadata(root.fd)
			if err != nil {
				t.Fatal(err)
			}
			transactionPath := filepath.Join(path, confinedCopyTransactionName)
			if err := os.Mkdir(transactionPath, 0700); err != nil {
				t.Fatal(err)
			}
			transaction, err := openConfinedRoot(transactionPath)
			if err != nil {
				t.Fatal(err)
			}
			defer transaction.close()
			forged := original
			forged.UID, forged.GID, forged.Mode = 10001, 10001, 0777
			if err := writeConfinedCopyManifest(transaction.fd, nil, &forged); err != nil {
				t.Fatal(err)
			}
			if untrustedOwner {
				if err := os.Chown(transactionPath, 10001, 10001); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Chmod(transactionPath, 0770); err != nil {
					t.Fatal(err)
				}
			}
			if err := recoverConfinedCopyTransaction(root); err == nil {
				t.Fatal("untrusted journal accepted")
			}
			assertVolumeRootMetadata(t, path, original.UID, original.GID, original.Mode)
		})
	}
}

func assertVolumeRootMetadata(t *testing.T, path string, uid, gid, mode uint32) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Uid != uid || stat.Gid != gid || stat.Mode&07777 != mode {
		t.Fatalf("root metadata = %d:%d %#o, want %d:%d %#o", stat.Uid, stat.Gid, stat.Mode&07777, uid, gid, mode)
	}
}
