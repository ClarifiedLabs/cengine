//go:build linux

package supervisor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

// Use real stat/name_to_handle_at results. Only the persisted journal fixture's
// handle changes; there is no production syscall override or fake-handle waiver.
// Run on a Linux filesystem with real regular-file handles (the ext4 test volume).
func TestCopyupIdentityUncertainPreservesWholeTransaction(t *testing.T) {
	for _, later := range []bool{false, true} {
		for _, changeType := range []bool{false, true} {
			name := "first-published"
			if later {
				name = "early-match-later-uncertain"
			}
			if changeType {
				name += "-handle-type"
			}
			t.Run(name, func(t *testing.T) {
				rootfs, volume := t.TempDir(), t.TempDir()
				sourcePath := filepath.Join(rootfs, "data")
				if err := os.Mkdir(sourcePath, 0700); err != nil {
					t.Fatal(err)
				}
				names := []string{"a", "z"}
				uncertain := "a"
				if later {
					names = []string{"a", "b", "z"}
					uncertain = "b"
				}
				for _, name := range names {
					if err := os.WriteFile(filepath.Join(sourcePath, name), []byte("image:"+name), 0640); err != nil {
						t.Fatal(err)
					}
				}
				if err := unix.Chmod(volume, 03750); err != nil {
					t.Fatal(err)
				}
				if err := unix.Setxattr(volume, "user.containment", []byte("before"), 0); err != nil {
					t.Fatal(err)
				}
				source, destination := openCopyupTestRoots(t, sourcePath, volume)
				stageConfinedCopyTransaction(t, source, destination, "manifest")
				transaction := filepath.Join(volume, confinedCopyTransactionName)
				for _, name := range names[:len(names)-1] {
					if err := os.Rename(filepath.Join(transaction, confinedCopyStagingName, name), filepath.Join(volume, name)); err != nil {
						t.Fatal(err)
					}
				}
				manifestPath := filepath.Join(transaction, confinedCopyManifestName)
				data, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				var manifest confinedCopyManifest
				if err := json.Unmarshal(data, &manifest); err != nil {
					t.Fatal(err)
				}
				// Order only this flat journal fixture; directory enumeration order
				// is filesystem-dependent. An earlier removable entry must not be
				// rolled back when preflight reaches the later ambiguous entry.
				sort.Slice(manifest.Entries, func(i, j int) bool {
					return manifest.Entries[i].Path < manifest.Entries[j].Path
				})
				if len(manifest.Entries) != len(names) {
					t.Fatalf("manifest entries = %v", manifest.Entries)
				}
				for index := range manifest.Entries {
					entry := &manifest.Entries[index]
					if entry.Path != names[index] {
						t.Fatalf("entry order = %v, want %v", manifest.Entries, names)
					}
					if entry.Path == "z" {
						continue // Deliberately retain unpublished staging/z.
					}
					state, err := confinedManifestEntryIdentity(destination, *entry)
					if err != nil || state != confinedManifestMatching {
						t.Fatalf("real filesystem must provide stable regular-file handles: %v, %v", state, err)
					}
					if entry.Path == uncertain {
						if len(entry.Handle) == 0 {
							t.Fatal("missing real file handle")
						}
						if changeType {
							entry.HandleType ^= 1
						} else {
							entry.Handle[0] ^= 1
						}
						state, err = confinedManifestEntryIdentity(destination, *entry)
						if state != confinedManifestUncertain || !errors.Is(err, errConfinedCopyIdentityUncertain) {
							t.Fatalf("same dev/inode/type, changed handle = %v, %v", state, err)
						}
					}
				}
				data, err = json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifestPath, data, 0600); err != nil {
					t.Fatal(err)
				}
				// Simulate interrupted metadata publication. These must NOT be
				// restored to the journal's old values on an uncertain identity.
				if err := unix.Chmod(volume, 02710); err != nil {
					t.Fatal(err)
				}
				if err := unix.Setxattr(volume, "user.containment", []byte("published"), 0); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(volume, time.Unix(1600000000, 123000000), time.Unix(1700000000, 456000000)); err != nil {
					t.Fatal(err)
				}
				before := snapshotCopyupContainmentTree(t, volume)
				for attempt := 0; attempt < 2; attempt++ {
					var rootBefore, rootAfter unix.Stat_t
					if err := unix.Lstat(volume, &rootBefore); err != nil {
						t.Fatal(err)
					}
					err := initializeVolumeAt(rootfs, volume, protocol.Mount{Destination: "/data"})
					if !errors.Is(err, errConfinedCopyIdentityUncertain) || !strings.Contains(err.Error(), "recover volume copy-up") {
						t.Fatalf("attempt %d accepted incomplete initialization: %v", attempt, err)
					}
					if err := unix.Lstat(volume, &rootAfter); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(rootBefore, rootAfter) {
						t.Fatalf("root metadata/timestamps changed: before=%+v after=%+v", rootBefore, rootAfter)
					}
					if after := snapshotCopyupContainmentTree(t, volume); !reflect.DeepEqual(before, after) {
						t.Fatalf("attempt %d changed journal/staging/published data or metadata:\nbefore=%+v\nafter=%+v", attempt, before, after)
					}
				}
			})
		}
	}
}

type copyupContainmentEntry struct {
	Stat  unix.Stat_t
	Data  string
	Xattr string
}

func snapshotCopyupContainmentTree(t *testing.T, root string) map[string]copyupContainmentEntry {
	t.Helper()
	result := make(map[string]copyupContainmentEntry)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		var snapshot copyupContainmentEntry
		if err := unix.Lstat(path, &snapshot.Stat); err != nil {
			return err
		}
		// Reading the manifest can update its atime; reads of our own snapshot
		// also update directory atime. Root timestamps are checked separately
		// around recovery, before this observer enumerates the tree again.
		snapshot.Stat.Atim = unix.Timespec{}
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			snapshot.Data = string(data)
		}
		value := make([]byte, 128)
		n, err := unix.Lgetxattr(path, "user.containment", value)
		if err != nil && !errors.Is(err, unix.ENODATA) {
			return err
		}
		if err == nil {
			snapshot.Xattr = string(value[:n])
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[relative] = snapshot
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCopyupIdentityOrdinaryReplacementControls(t *testing.T) {
	for _, replacement := range []string{"absent", "regular", "symlink", "directory"} {
		t.Run(replacement, func(t *testing.T) {
			sourcePath, volume := t.TempDir(), t.TempDir()
			for _, name := range []string{"a", "b"} {
				if err := os.WriteFile(filepath.Join(sourcePath, name), []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			source, destination := openCopyupTestRoots(t, sourcePath, volume)
			publishStaleConfinedCopyTransaction(t, source, destination)
			path := filepath.Join(volume, "b")
			// Pin the old inode so this control cannot accidentally exercise inode
			// reuse, which is deliberately classified as uncertain by containment.
			old, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "regular":
				err = os.WriteFile(path, []byte("replacement"), 0640)
			case "symlink":
				err = os.Symlink("a", path)
			case "directory":
				err = os.Mkdir(path, 0750)
			}
			if err != nil {
				t.Fatal(err)
			}
			var before unix.Stat_t
			if replacement != "absent" {
				if err := unix.Lstat(path, &before); err != nil {
					t.Fatal(err)
				}
			}
			if err := recoverConfinedCopyTransaction(destination); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"a", confinedCopyTransactionName} {
				if _, err := os.Lstat(filepath.Join(volume, name)); !os.IsNotExist(err) {
					t.Fatalf("matching entry/journal survived: %s, %v", name, err)
				}
			}
			var after unix.Stat_t
			err = unix.Lstat(path, &after)
			if replacement == "absent" {
				if !errors.Is(err, unix.ENOENT) {
					t.Fatalf("absent entry = %v", err)
				}
			} else if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("replacement changed: %+v, %+v, %v", before, after, err)
			}
		})
	}
}
