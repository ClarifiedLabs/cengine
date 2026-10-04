//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storagemanaged

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	c "dev.cengine/guest/internal/copycontract"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// RTM100: a supervisor manifest-write EIO leaves an unsealed manifest.tmp.
// Exercise the actual ext4 preflight and ordinary DATA obligation, not a seam.
func TestNativeCopyManifestTemporaryRecovery(t *testing.T) {
	for _, kind := range []string{"empty", "partial", "full", "sealed", "sealed-cleaning", "foreign", "temporary-directory", "temporary-hardlink", "transaction-mismatch", "staging-mismatch", "manifest-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			path := identity102Root(t)
			keys := newCopyDataKeys(t)
			f := copyDataFixture(t, path, keys, nil, false)
			var s *Session
			var intent a.CopyIntent
			sealed := kind == "sealed" || kind == "sealed-cleaning" || kind == "manifest-mismatch"
			if sealed {
				var setup copyDataManifest
				s, setup, _ = copyDataSetup(t, f, "rename")
				intent = setup.Intent
			} else {
				s = copyDataOwner(t, f, nil)
				control := copyDataControl(t, f, s)
				intent = control(w.BeginCopy, "").Intent
				intent = control(w.BindCopyTransaction, intent.ID).Intent
			}
			control := copyDataControl(t, f, s)
			volume := filepath.Join(path, "volumes", "data")
			tx := filepath.Join(volume, copyTransactionPath)
			if !sealed {
				must(t, os.Mkdir(filepath.Join(tx, "staging"), 0700))
				must(t, os.WriteFile(filepath.Join(tx, "staging", "child"), []byte("private payload"), 0600))
			}
			transaction := f.call(s, caller(0, 0), w.LookupRequest{Parent: 1, Name: []byte(copyTransactionPath)}).(w.LookupReply).Entry
			handle := f.call(s, caller(0, 0), w.OpenDirRequest{Node: transaction.Node}).(w.OpenDirReply).Opened.Handle
			if !sealed {
				fd := int(s.root.Fd())
				st, err := stat(fd)
				must(t, err)
				var fs unix.Statfs_t
				must(t, unix.Fstatfs(fd, &fs))
				child, err := copyIdentityAt(fd, copyTransactionPath+"/staging/child")
				must(t, err)
				manifest := c.Manifest{Version: 4, Intent: intent.ID, Physical: intent.Root,
					Root:    &c.RootMetadata{Filesystem: fs.Fsid.Val, Device: st.Dev, Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, Xattrs: copyDataXattrs(t, fd)},
					Entries: []c.Entry{{Path: "child", Identity: child}}}
				must(t, c.ValidateManifest(manifest))
				raw, err := json.Marshal(manifest)
				must(t, err)
				switch kind {
				case "empty":
					raw = nil
				case "partial":
					raw = raw[:len(raw)/2]
				}
				must(t, os.WriteFile(filepath.Join(tx, "manifest.tmp"), raw, 0600))
				intent = control(w.StartCleanup, intent.ID).Intent
				if intent.Phase != a.CopyCleaning || intent.ManifestSize != 0 {
					t.Fatal("expected unsealed CLEANING", intent)
				}
			} else if kind == "sealed-cleaning" {
				intent = control(w.StartCleanup, intent.ID).Intent
			}
			switch kind {
			case "sealed", "sealed-cleaning":
				must(t, os.WriteFile(filepath.Join(tx, "manifest.tmp"), []byte("extra"), 0600))
			case "foreign":
				must(t, os.WriteFile(filepath.Join(tx, "foreign"), []byte("preserve"), 0600))
			case "temporary-directory":
				must(t, os.Remove(filepath.Join(tx, "manifest.tmp")))
				must(t, os.Mkdir(filepath.Join(tx, "manifest.tmp"), 0700))
			case "temporary-hardlink":
				public := filepath.Join(volume, "public-file")
				must(t, os.WriteFile(public, []byte("preserve public payload"), 0600))
				must(t, os.Remove(filepath.Join(tx, "manifest.tmp")))
				must(t, os.Link(public, filepath.Join(tx, "manifest.tmp")))
			case "transaction-mismatch":
				must(t, os.Rename(tx, filepath.Join(volume, "saved-transaction")))
				must(t, os.Mkdir(tx, 0700))
			case "staging-mismatch":
				must(t, os.Rename(filepath.Join(tx, "staging"), filepath.Join(volume, "saved-staging")))
				must(t, os.Mkdir(filepath.Join(tx, "staging"), 0700))
			case "manifest-mismatch":
				must(t, os.WriteFile(filepath.Join(tx, "manifest.json"), []byte("changed sealed evidence"), 0600))
			}
			positive := kind == "empty" || kind == "partial" || kind == "full"
			state, err := f.authority.Query(f.control)
			must(t, err)
			before := copyDataSnapshot(t, path)
			if kind == "temporary-hardlink" {
				public := before[filepath.Join(volume, "public-file")]
				temporary := before[filepath.Join(tx, "manifest.tmp")]
				if public.Stat.Nlink != 2 || public.Stat.Ino != temporary.Stat.Ino || public.Digest != temporary.Digest {
					t.Fatal("expected temporary alias of public file")
				}
			}
			// Snapshots compare content digests and full stat (except atime),
			// including public-file link count and ctime after refusal.
			for repeat := 0; repeat < 2; repeat++ {
				err = PreflightCopyRecovery(s.root, state.Store.DeviceID, a.CopyOperationDirectoryTail, intent)
				if positive && err != nil || !positive && err == nil {
					t.Fatalf("preflight positive=%v: %v", positive, err)
				}
				if !reflect.DeepEqual(before, copyDataSnapshot(t, path)) {
					t.Fatal("preflight mutated evidence")
				}
			}
			body := w.ReleaseDirRequest{Node: transaction.Node, Handle: handle}
			if !positive {
				f.expectFaults = true
				g, err := f.authority.Admit(s.principal, s.binding.Volume, true)
				must(t, err)
				f.sequence[s]++
				_, err = s.Dispatch(g, w.Request{Sequence: f.sequence[s], Auth: lifecycle, Body: body})
				g.Release()
				if !errors.Is(err, ErrVolumeFault) {
					t.Fatal("unsafe directory tail admitted", err)
				}
				if !reflect.DeepEqual(before, copyDataSnapshot(t, path)) {
					t.Fatal("rejected DATA mutated evidence")
				}
				return
			}
			f.call(s, lifecycle, body)
			if f.registry.faults[s.binding.Volume] != nil || s.handles[handle] != nil {
				t.Fatal("ReleaseDir latched a fault or retained its handle")
			}
			control(w.FinishCopy, intent.ID)
			if _, err := os.Lstat(tx); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cleanup retained private transaction", err)
			}
			fresh := control(w.BeginCopy, "").Intent
			if fresh.ID == intent.ID {
				t.Fatal("retry reused completed intent")
			}
			copyDataRetry(t, f, s, control, fresh)
			// copyDataOwner's cleanup requires real Retire/Barrier success and
			// verifies all session and registry resources have been drained.
		})
	}
}
