//go:build linux

package supervisor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These are DIRECT-EXT4 contract tests, not optional xattr probes. Run with a
// privileged Linux test process and TMPDIR on ext4; missing setup is a failure.
func directExt4XattrRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("DIRECT-EXT4 requires root for ownership, ACL and capability setup")
	}
	root := t.TempDir()
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatalf("DIRECT-EXT4 requires ext4 TMPDIR, got filesystem %#x", fs.Type)
	}
	return root
}

func setRequiredXattr(t *testing.T, path, name string, value []byte) {
	t.Helper()
	if err := unix.Setxattr(path, name, value, 0); err != nil {
		t.Fatalf("required xattr setup %s %s: %v", path, name, err)
	}
}

func directExt4ACL(namedUID uint32) []byte {
	// Linux posix_acl_xattr_header + user_obj, named user, group_obj, mask, other.
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, entry := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, namedUID}, {4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		binary.LittleEndian.PutUint16(acl[4+i*8:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(acl[6+i*8:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(acl[8+i*8:], entry[2])
	}
	return acl
}

func directExt4Capability() []byte {
	// VFS_CAP_REVISION_2 | EFFECTIVE, permitted CAP_NET_BIND_SERVICE.
	capability := make([]byte, 20)
	binary.LittleEndian.PutUint32(capability, 0x02000001)
	binary.LittleEndian.PutUint32(capability[4:], 1<<unix.CAP_NET_BIND_SERVICE)
	return capability
}

func fileXattrsForTest(t *testing.T, path string) *confinedXattrSnapshot {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	snapshot, err := snapshotConfinedXattrs(fd)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != "supported" {
		t.Fatal("DIRECT-EXT4 did not report xattr support")
	}
	return snapshot
}

func rootXattrsForTest(t *testing.T, root *confinedRoot) *confinedXattrSnapshot {
	t.Helper()
	metadata, err := confinedRootMetadata(root.fd)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Xattrs.State != "supported" {
		t.Fatal("DIRECT-EXT4 did not report xattr support")
	}
	return metadata.Xattrs
}

func TestDirectExt4CopyupRootXattrFidelity(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(fmt.Sprintf("populated=%v", populated), func(t *testing.T) {
			sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
			// Destination's default ACL is inherited by staging and its children.
			setRequiredXattr(t, destinationPath, "system.posix_acl_default", directExt4ACL(12346))
			setRequiredXattr(t, destinationPath, "user.destination-only", []byte("remove"))
			setRequiredXattr(t, destinationPath, "user.overwrite", []byte("old"))
			setRequiredXattr(t, sourcePath, "user.overwrite", []byte("new\x00value"))
			setRequiredXattr(t, sourcePath, "user.empty", []byte{})
			setRequiredXattr(t, sourcePath, "user.\xff", []byte("raw-name"))
			setRequiredXattr(t, sourcePath, "system.posix_acl_access", directExt4ACL(12345))
			setRequiredXattr(t, sourcePath, "system.posix_acl_default", directExt4ACL(12345))
			if err := os.Chown(sourcePath, 10001, 10002); err != nil {
				t.Fatal(err)
			}
			if err := unix.Chmod(sourcePath, 02750); err != nil {
				t.Fatal(err)
			}
			if populated {
				// Clear source inherited ACLs: destination-only inherited ACLs must
				// not survive either directory or regular-file metadata copying.
				child := filepath.Join(sourcePath, "child")
				if err := os.Mkdir(child, 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
					if err := unix.Removexattr(child, name); err != nil {
						t.Fatal(err)
					}
				}
				file := filepath.Join(child, "seed")
				if err := os.WriteFile(file, []byte("seed"), 0600); err != nil {
					t.Fatal(err)
				}
				setRequiredXattr(t, file, "security.capability", directExt4Capability())
			}
			source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
			want := rootXattrsForTest(t, source)
			if err := copyConfinedDirectory(source, destination); err != nil {
				t.Fatal(err)
			}
			if got := rootXattrsForTest(t, destination); !reflect.DeepEqual(got, want) {
				t.Fatalf("root attrs = %#v, want %#v", got, want)
			}
			assertVolumeRootMetadata(t, destinationPath, 10001, 10002, 02750)
			if populated {
				for _, relative := range []string{"child", "child/seed"} {
					var snapshots [2]*confinedXattrSnapshot
					for i, base := range []string{sourcePath, destinationPath} {
						fd, err := unix.Open(filepath.Join(base, relative), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
						if err != nil {
							t.Fatal(err)
						}
						snapshots[i], err = snapshotConfinedXattrs(fd)
						_ = unix.Close(fd)
						if err != nil {
							t.Fatal(err)
						}
					}
					if !reflect.DeepEqual(snapshots[0], snapshots[1]) {
						t.Fatalf("child %s attrs differ: %#v != %#v", relative, snapshots[0], snapshots[1])
					}
				}
			}
		})
	}
}

func TestDirectExt4RecoveryRestoresExactRootXattrs(t *testing.T) {
	for _, populated := range []bool{false, true} {
		for _, originalEmpty := range []bool{false, true} {
			t.Run(fmt.Sprintf("populated=%v/empty=%v", populated, originalEmpty), func(t *testing.T) {
				sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
				if populated {
					if err := os.WriteFile(filepath.Join(sourcePath, "seed"), []byte("seed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if !originalEmpty {
					setRequiredXattr(t, destinationPath, "user.overwrite", []byte("original"))
					setRequiredXattr(t, destinationPath, "user.removed", []byte{})
					setRequiredXattr(t, destinationPath, "user.\xff", []byte("raw-name"))
					setRequiredXattr(t, destinationPath, "system.posix_acl_access", directExt4ACL(12345))
					setRequiredXattr(t, destinationPath, "system.posix_acl_default", directExt4ACL(12345))
				}
				if err := unix.Chmod(destinationPath, 03750); err != nil {
					t.Fatal(err)
				}
				source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
				want := rootXattrsForTest(t, destination)
				publishStaleConfinedCopyTransaction(t, source, destination)
				setRequiredXattr(t, destinationPath, "user.added", []byte("transaction"))
				if !originalEmpty {
					setRequiredXattr(t, destinationPath, "user.overwrite", []byte("transaction"))
					if err := unix.Removexattr(destinationPath, "user.removed"); err != nil {
						t.Fatal(err)
					}
					if err := unix.Removexattr(destinationPath, "system.posix_acl_default"); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chown(destinationPath, 10001, 10002); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chmod(destinationPath, 0000); err != nil {
					t.Fatal(err)
				}
				for attempt := 0; attempt < 2; attempt++ {
					if err := recoverConfinedCopyTransaction(destination); err != nil {
						t.Fatal(err)
					}
					if got := rootXattrsForTest(t, destination); !reflect.DeepEqual(got, want) {
						t.Fatalf("rollback attrs = %#v, want %#v", got, want)
					}
					assertVolumeRootMetadata(t, destinationPath, uint32(os.Geteuid()), uint32(os.Getegid()), 03750)
					entries, err := os.ReadDir(destinationPath)
					if err != nil || len(entries) != 0 {
						t.Fatalf("rollback left entries: %v, %v", entries, err)
					}
				}
			})
		}
	}
}

func TestDirectExt4RootXattrsUsePinnedIdentity(t *testing.T) {
	parent := directExt4XattrRoot(t)
	sourcePath, destinationPath := filepath.Join(parent, "source"), filepath.Join(parent, "destination")
	outside := filepath.Join(parent, "outside")
	for _, path := range []string{sourcePath, destinationPath, outside} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	setRequiredXattr(t, sourcePath, "user.identity", []byte("source"))
	setRequiredXattr(t, destinationPath, "user.identity", []byte("destination"))
	setRequiredXattr(t, outside, "user.identity", []byte("outside"))
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	for _, path := range []string{sourcePath, destinationPath} {
		if err := os.Rename(path, path+"-pinned"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyConfinedDirectory(source, destination); err != nil {
		t.Fatal(err)
	}
	want := rootXattrsForTest(t, source)
	if got := rootXattrsForTest(t, destination); !reflect.DeepEqual(got, want) {
		t.Fatal("copy followed replacement")
	}
	publishStaleConfinedCopyTransaction(t, source, destination)
	setRequiredXattr(t, destinationPath+"-pinned", "user.identity", []byte("changed"))
	if err := recoverConfinedCopyTransaction(destination); err != nil {
		t.Fatal(err)
	}
	if got := rootXattrsForTest(t, destination); !reflect.DeepEqual(got, want) {
		t.Fatal("recovery followed replacement")
	}
	buffer := make([]byte, 32)
	n, err := unix.Getxattr(outside, "user.identity", buffer)
	if err != nil || string(buffer[:n]) != "outside" {
		t.Fatalf("outside changed: %q, %v", buffer, err)
	}
}

func TestDirectExt4XattrJournalValidationAndRecoveryFailure(t *testing.T) {
	for _, invalid := range []string{"missing", "state", "entries", "name", "duplicate", "value", "unsupported-values", "unsupported-downgrade", "null-manifest-entries", "missing-manifest-entries", "oversize", "kernel-rejects"} {
		t.Run(invalid, func(t *testing.T) {
			sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
			setRequiredXattr(t, destinationPath, "user.keep", []byte("original"))
			if err := os.WriteFile(filepath.Join(sourcePath, "seed"), []byte("published"), 0600); err != nil {
				t.Fatal(err)
			}
			source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
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
			xattrs := manifest.Root.Xattrs
			switch invalid {
			case "missing":
				manifest.Root.Xattrs = nil
			case "state":
				xattrs.State = "unknown"
			case "entries":
				xattrs.Entries = nil
			case "name":
				xattrs.Entries[0].Name = "user.bad\x00name"
			case "duplicate":
				xattrs.Entries = append(xattrs.Entries, xattrs.Entries[0])
			case "value":
				xattrs.Entries[0].Value = nil
			case "unsupported-values":
				xattrs.State = "unsupported"
			case "unsupported-downgrade":
				xattrs.State, xattrs.Entries = "unsupported", []confinedXattr{}
			case "null-manifest-entries", "missing-manifest-entries":
				manifest.Entries = nil
			case "oversize":
				xattrs.Entries[0].Value = make([]byte, maxConfinedXattrValueBytes+1)
			case "kernel-rejects":
				xattrs.Entries = append(xattrs.Entries, confinedXattr{Name: "system.posix_acl_access", Value: []byte{1}})
			}
			data, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if invalid == "missing-manifest-entries" {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(data, &object); err != nil {
					t.Fatal(err)
				}
				delete(object, "entries")
				data, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(manifestPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			setRequiredXattr(t, destinationPath, "user.keep", []byte("uncommitted"))
			if err := os.Chown(destinationPath, 10001, 10002); err != nil {
				t.Fatal(err)
			}
			if err := unix.Chmod(destinationPath, 0711); err != nil {
				t.Fatal(err)
			}
			before, err := confinedRootMetadata(destination.fd)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := recoverConfinedCopyTransaction(destination); err == nil {
					t.Fatal("invalid xattr recovery succeeded")
				}
				if invalid != "kernel-rejects" {
					after, err := confinedRootMetadata(destination.fd)
					if err != nil || !reflect.DeepEqual(after, before) {
						t.Fatalf("invalid journal changed root metadata: %#v, %v", after, err)
					}
				}
				got, err := os.ReadFile(manifestPath)
				if err != nil || string(got) != string(data) {
					t.Fatalf("failed recovery discarded journal: %v", err)
				}
				if seed, err := os.ReadFile(filepath.Join(destinationPath, "seed")); err != nil || string(seed) != "published" {
					t.Fatalf("failed recovery changed published entry: %q, %v", seed, err)
				}
			}
		})
	}
}

func TestDirectExt4LegacyXattrJournalRecovery(t *testing.T) {
	for _, version := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
			if err := os.WriteFile(filepath.Join(sourcePath, "seed"), []byte("seed"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := unix.Chmod(destinationPath, 02750); err != nil {
				t.Fatal(err)
			}
			setRequiredXattr(t, destinationPath, "user.original", []byte("original"))
			source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
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
			manifest.Version = version
			if version == 1 {
				manifest.Root = nil
			} else {
				manifest.Root.Xattrs = nil
			}
			data, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			setRequiredXattr(t, destinationPath, "user.added", []byte("not-recorded"))
			if err := unix.Chmod(destinationPath, 0711); err != nil {
				t.Fatal(err)
			}
			want := rootXattrsForTest(t, destination)
			if err := recoverConfinedCopyTransaction(destination); err != nil {
				t.Fatal(err)
			}
			if got := rootXattrsForTest(t, destination); !reflect.DeepEqual(got, want) {
				t.Fatal("legacy journal deleted unrecorded xattrs")
			}
			mode := uint32(0711)
			if version == 2 {
				mode = 02750
			}
			assertVolumeRootMetadata(t, destinationPath, uint32(os.Geteuid()), uint32(os.Getegid()), mode)
			entries, err := os.ReadDir(destinationPath)
			if err != nil || len(entries) != 0 {
				t.Fatalf("legacy rollback entries: %v, %v", entries, err)
			}
		})
	}
}

func TestDirectExt4RegularFileCapabilityRestoredAfterChown(t *testing.T) {
	sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
	file := filepath.Join(sourcePath, "capable")
	if err := os.WriteFile(file, []byte("file capability fixture"), 0750); err != nil {
		t.Fatal(err)
	}
	capability := directExt4Capability()
	// Execution uses capabilities on regular files; valid bytes are also
	// storable on directories and symlinks. Prove chown clears this file value.
	setRequiredXattr(t, file, "security.capability", capability)
	if err := os.Chown(file, 10001, 10002); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, err := unix.Getxattr(file, "security.capability", buffer); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("fixture chown did not clear capability: %v", err)
	}
	if err := unix.Chmod(file, 0750); err != nil {
		t.Fatal(err)
	}
	setRequiredXattr(t, file, "security.capability", capability)
	want := fileXattrsForTest(t, file)
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	if err := copyConfinedDirectory(source, destination); err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(destinationPath, "capable")
	assertVolumeRootMetadata(t, copied, 10001, 10002, 0750)
	if got := fileXattrsForTest(t, copied); !reflect.DeepEqual(got, want) {
		t.Fatalf("regular-file chown lost capability: %#v, want %#v", got, want)
	}
}

func TestDirectExt4CopyupSymlinkDoesNotTouchTargetXattrs(t *testing.T) {
	sourcePath, destinationPath, outside := directExt4XattrRoot(t), directExt4XattrRoot(t), directExt4XattrRoot(t)
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("outside"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(target, 10003, 10004); err != nil {
		t.Fatal(err)
	}
	setRequiredXattr(t, target, "user.outside", []byte("unchanged"))
	setRequiredXattr(t, target, "system.posix_acl_access", directExt4ACL(12345))
	setRequiredXattr(t, target, "security.capability", directExt4Capability())
	wantXattrs := fileXattrsForTest(t, target)
	var before unix.Stat_t
	if err := unix.Stat(target, &before); err != nil {
		t.Fatal(err)
	}
	// A live absolute target detects metadata following; a dangling target also
	// proves copying never needs to resolve the link to enumerate target attrs.
	for name, literal := range map[string]string{"live": target, "dangling": filepath.Join(outside, "missing")} {
		link := filepath.Join(sourcePath, name)
		if err := os.Symlink(literal, link); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(link, 10001, 10002); err != nil {
			t.Fatal(err)
		}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, link, []unix.Timespec{{Sec: 1700000000}, {Sec: 1700000001}}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatal(err)
		}
		// Real no-follow ext4 control: valid revision-2 capability bytes, not
		// the malformed one-byte denial used by the compatibility probe.
		if err := unix.Lsetxattr(link, "security.capability", directExt4Capability(), 0); err != nil {
			t.Fatalf("DIRECT-EXT4 valid capability on %s symlink: %v", name, err)
		}
	}
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	if err := copyConfinedDirectory(source, destination); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"live", "dangling"} {
		wantAttrs := symlinkXattrsForTest(t, filepath.Join(sourcePath, name))
		if got := symlinkXattrsForTest(t, filepath.Join(destinationPath, name)); !reflect.DeepEqual(got, wantAttrs) {
			t.Fatalf("%s symlink xattrs = %#v, want %#v", name, got, wantAttrs)
		}
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(destinationPath, name), &st); err != nil {
			t.Fatal(err)
		}
		if st.Uid != 10001 || st.Gid != 10002 || st.Atim.Sec != 1700000000 || st.Mtim.Sec != 1700000001 {
			t.Fatalf("%s symlink metadata = %#v", name, st)
		}
		want, err := os.Readlink(filepath.Join(sourcePath, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.Readlink(filepath.Join(destinationPath, name))
		if err != nil || got != want {
			t.Fatalf("literal symlink %s changed: %q, want %q, %v", name, got, want, err)
		}
	}
	var after unix.Stat_t
	if err := unix.Stat(target, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("symlink metadata followed outside target: %#v, want %#v", after, before)
	}
	if got := fileXattrsForTest(t, target); !reflect.DeepEqual(got, wantXattrs) {
		t.Fatalf("symlink copy changed outside target xattrs: %#v, want %#v", got, wantXattrs)
	}
}

// Simulate the NFS-like xattr surface only on the pinned destination root.
// An empty directory can still carry source metadata that must not be lost.
func TestDirectExt4RootOnlyXattrsRejectUnsupportedDestination(t *testing.T) {
	for _, populatedAttrs := range []bool{false, true} {
		t.Run(fmt.Sprintf("attrs=%v", populatedAttrs), func(t *testing.T) {
			sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
			if populatedAttrs {
				setRequiredXattr(t, sourcePath, "user.root-only", []byte("must-not-disappear"))
			}
			if err := unix.Chmod(sourcePath, 0751); err != nil {
				t.Fatal(err)
			}
			source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
			original, err := confinedRootMetadata(destination.fd)
			if err != nil {
				t.Fatal(err)
			}
			operations := confinedXattrSyscalls()
			unsupportedCalls := 0
			operations.list = func(fd int, buffer []byte) (int, error) {
				var stat unix.Stat_t
				if err := unix.Fstat(fd, &stat); err != nil {
					return 0, err
				}
				if stat.Dev == original.Device && stat.Ino == original.Inode {
					unsupportedCalls++
					return 0, unix.EOPNOTSUPP
				}
				return unix.Flistxattr(fd, buffer)
			}
			operations.set = func(int, string, []byte, int) error {
				t.Fatal("attempted to set xattrs after destination reported unsupported")
				return unix.EOPNOTSUPP
			}
			operations.remove = func(int, string) error {
				t.Fatal("attempted to remove xattrs after destination reported unsupported")
				return unix.EOPNOTSUPP
			}
			err = copyConfinedDirectoryWithRootXattrs(source, destination, operations)
			wantCalls := 2 // Destination snapshot and forward application.
			if populatedAttrs {
				wantCalls++ // Rollback verifies the journal's unsupported state.
				if !errors.Is(err, unix.EOPNOTSUPP) || !strings.Contains(err.Error(), "apply copy-up root metadata") || strings.Contains(err.Error(), "rollback") {
					t.Fatalf("root-only metadata silently lost or rollback failed: %v", err)
				}
				after, err := confinedRootMetadata(destination.fd)
				if err != nil || !reflect.DeepEqual(after, original) {
					t.Fatalf("failed copy changed destination root: %#v, %v", after, err)
				}
			} else if err != nil {
				t.Fatalf("known-empty source should remain supported: %v", err)
			}
			if unsupportedCalls != wantCalls {
				t.Fatalf("unsupported destination calls = %d, want %d", unsupportedCalls, wantCalls)
			}
			entries, err := os.ReadDir(destinationPath)
			if err != nil || len(entries) != 0 {
				t.Fatalf("root-only copy left transaction entries: %v, %v", entries, err)
			}
		})
	}
}

func TestDirectExt4CopyupPartialRootXattrFailureRollsBack(t *testing.T) {
	for _, fault := range []struct{ forward, rollback string }{
		{"set", ""}, {"remove", ""}, {"set", "set"}, {"remove", "set"}, {"set", "remove"},
	} {
		for _, populated := range []bool{false, true} {
			t.Run(fmt.Sprintf("forward=%s/rollback=%s/populated=%v", fault.forward, fault.rollback, populated), func(t *testing.T) {
				sourcePath, destinationPath := directExt4XattrRoot(t), directExt4XattrRoot(t)
				if populated {
					if err := os.WriteFile(filepath.Join(sourcePath, "seed"), []byte("published"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if populated {
					link := filepath.Join(sourcePath, "capable-link")
					if err := os.Symlink("missing", link); err != nil {
						t.Fatal(err)
					}
					if err := unix.Lsetxattr(link, "security.capability", directExt4Capability(), 0); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{"user.a-remove", "user.b-remove", "user.overwrite"} {
					setRequiredXattr(t, destinationPath, name, []byte("original"))
				}
				setRequiredXattr(t, destinationPath, "user.z-empty", []byte{})
				setRequiredXattr(t, destinationPath, "system.posix_acl_access", directExt4ACL(12345))
				setRequiredXattr(t, destinationPath, "system.posix_acl_default", directExt4ACL(12345))
				setRequiredXattr(t, sourcePath, "system.posix_acl_access", directExt4ACL(12346))
				setRequiredXattr(t, sourcePath, "user.a-added", []byte("new"))
				setRequiredXattr(t, sourcePath, "user.overwrite", []byte("new"))
				setRequiredXattr(t, sourcePath, "user.z-added", []byte{})
				if err := os.Chown(sourcePath, 10001, 10002); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chmod(sourcePath, 0750); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(destinationPath, 10003, 10004); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chmod(destinationPath, 03750); err != nil {
					t.Fatal(err)
				}
				// Raw capabilities on root directories must survive partial
				// application, failed rollback, and replay of the v3 journal.
				setRequiredXattr(t, destinationPath, "security.capability", directExt4Capability())
				sourceCapability := directExt4Capability()
				binary.LittleEndian.PutUint32(sourceCapability[4:], 1<<unix.CAP_CHOWN)
				setRequiredXattr(t, sourcePath, "security.capability", sourceCapability)
				source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
				original, err := confinedRootMetadata(destination.fd)
				if err != nil {
					t.Fatal(err)
				}
				manifestPath := filepath.Join(destinationPath, confinedCopyTransactionName, confinedCopyManifestName)
				var durableManifest []byte
				forwardFailed, rollbackFailed := false, false
				inject := func(fd int, operation, name string) error {
					var stat unix.Stat_t
					if err := unix.Fstat(fd, &stat); err != nil {
						t.Fatal(err)
					}
					if stat.Dev != original.Device || stat.Ino != original.Inode {
						t.Fatal("root fault escaped the pinned destination")
					}
					if !forwardFailed && operation == fault.forward && ((operation == "set" && name == "user.z-added") || (operation == "remove" && name == "user.b-remove")) {
						// Earlier operations really changed the inode, not just a mock.
						buffer := make([]byte, 32)
						if _, err := unix.Fgetxattr(fd, "user.a-remove", buffer); !errors.Is(err, unix.ENODATA) {
							t.Fatalf("forward removal did not complete before fault: %v", err)
						}
						if operation == "set" {
							n, err := unix.Fgetxattr(fd, "user.overwrite", buffer)
							if err != nil || string(buffer[:n]) != "new" {
								t.Fatalf("forward set did not complete before fault: %q, %v", buffer, err)
							}
						}
						assertVolumeRootMetadata(t, destinationPath, 10001, 10002, 0750)
						var err error
						durableManifest, err = os.ReadFile(manifestPath)
						if err != nil {
							t.Fatal(err)
						}
						var manifest confinedCopyManifest
						if err := json.Unmarshal(durableManifest, &manifest); err != nil || manifest.Version != 3 || !reflect.DeepEqual(manifest.Root, &original) {
							t.Fatalf("partial application lacked original v3 snapshot: %#v, %v", manifest.Root, err)
						}
						forwardFailed = true
						return unix.EIO
					}
					if forwardFailed && !rollbackFailed && operation == fault.rollback && ((operation == "set" && name == "user.a-remove") || (operation == "remove" && name == "user.a-added")) {
						rollbackFailed = true
						return unix.ENOSPC
					}
					return nil
				}
				operations := confinedXattrSyscalls()
				operations.set = func(fd int, name string, value []byte, flags int) error {
					if err := inject(fd, "set", name); err != nil {
						return err
					}
					return unix.Fsetxattr(fd, name, value, flags)
				}
				operations.remove = func(fd int, name string) error {
					if err := inject(fd, "remove", name); err != nil {
						return err
					}
					return unix.Fremovexattr(fd, name)
				}
				err = copyConfinedDirectoryWithRootXattrs(source, destination, operations)
				if !forwardFailed || !errors.Is(err, unix.EIO) || !strings.Contains(err.Error(), "apply copy-up root metadata") {
					t.Fatalf("forward failure = %v, injected = %v", err, forwardFailed)
				}
				if fault.rollback != "" {
					if !rollbackFailed || !strings.Contains(err.Error(), "copy-up rollback:") || !strings.Contains(err.Error(), unix.ENOSPC.Error()) {
						t.Fatalf("rollback failure not reported: %v", err)
					}
					got, err := os.ReadFile(manifestPath)
					if err != nil || !bytes.Equal(got, durableManifest) {
						t.Fatalf("rollback failure discarded or rewrote journal: %v", err)
					}
					if populated {
						if data, err := os.ReadFile(filepath.Join(destinationPath, "seed")); err != nil || string(data) != "published" {
							t.Fatalf("failed root rollback removed published entry: %q, %v", data, err)
						}
					}
					if populated {
						if got, want := symlinkXattrsForTest(t, filepath.Join(destinationPath, "capable-link")), symlinkXattrsForTest(t, filepath.Join(sourcePath, "capable-link")); !reflect.DeepEqual(got, want) {
							t.Fatal("failed root rollback lost published symlink capability")
						}
					}
					if got := rootXattrsForTest(t, destination); reflect.DeepEqual(got, original.Xattrs) {
						t.Fatal("rollback fault did not leave a partial xattr set")
					}
					// The one-shot failure is gone; retry from the retained journal.
					if err := recoverConfinedCopyTransaction(destination); err != nil {
						t.Fatal(err)
					}
				} else if strings.Contains(err.Error(), "rollback") {
					t.Fatalf("one-shot forward failure also broke rollback: %v", err)
				}
				for attempt := 0; attempt < 2; attempt++ {
					after, err := confinedRootMetadata(destination.fd)
					if err != nil || !reflect.DeepEqual(after, original) {
						t.Fatalf("rollback did not restore exact root metadata: %#v, want %#v, %v", after, original, err)
					}
					entries, err := os.ReadDir(destinationPath)
					if err != nil || len(entries) != 0 {
						t.Fatalf("rollback left entries: %v, %v", entries, err)
					}
					if err := recoverConfinedCopyTransaction(destination); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestConfinedXattrManifestVersionsAndPersistence(t *testing.T) {
	path := t.TempDir()
	root, err := openConfinedRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	metadata, err := confinedRootMetadata(root.fd)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint32{1, 2, 3} {
		manifest := confinedCopyManifest{Version: version, Entries: []confinedCopyManifestEntry{}}
		if version > 1 {
			copy := metadata
			manifest.Root = &copy
		}
		if version == 2 {
			manifest.Root.Xattrs = nil
		}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, confinedCopyManifestName), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfinedCopyManifest(root.fd); err != nil {
			t.Fatalf("v%d: %v", version, err)
		}
	}
	if err := os.Remove(filepath.Join(path, confinedCopyManifestName)); err != nil {
		t.Fatal(err)
	}
	metadata.Xattrs = nil
	if err := writeConfinedCopyManifest(root.fd, nil, &metadata); err == nil {
		t.Fatal("persisted incomplete v3 snapshot")
	}
	if _, err := os.Stat(filepath.Join(path, confinedCopyManifestTemporary)); !os.IsNotExist(err) {
		t.Fatalf("invalid snapshot created temporary journal: %v", err)
	}
}
