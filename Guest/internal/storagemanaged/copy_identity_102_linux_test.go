//go:build cengine_native_faulttest && linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// RTM-102 uses the existing native fixture's 128-MiB/4096-inode ext4.
// No mount, formatter, process, generation override, or skip is supplied here.
func identity102Root(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	var fs unix.Statfs_t
	copyHostMust(t, unix.Statfs(root, &fs))
	if os.Geteuid() != 0 || fs.Type != unix.EXT4_SUPER_MAGIC || uint64(fs.Blocks)*uint64(fs.Bsize) > 128<<20 || fs.Files > 4096 {
		t.Fatal("RTM-102 requires the existing bounded native ext4/root fixture")
	}
	return root
}

func identity102Open(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	copyHostMust(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// A pass requires the SAME inode and type, with a genuinely different kernel
// generation/full handle. A different inode, exhausted bound, or missing handle
// is a failure, never a substitute for observed reuse.
func identity102Reuse(t *testing.T, parent int, path string, before a.Ext4ObjectV1) a.Ext4ObjectV1 {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for attempt := 0; attempt < 4096 && time.Now().Before(deadline); attempt++ {
		copyHostMust(t, os.Remove(path))
		copyHostMust(t, unix.Syncfs(parent)) // release ext4's recently-deleted inode exclusion
		if before.FileType == unix.S_IFDIR {
			copyHostMust(t, os.Mkdir(path, 0700))
		} else {
			copyHostMust(t, os.WriteFile(path, []byte("replacement"), 0600))
		}
		got, err := copyIdentityAt(parent, filepath.Base(path))
		copyHostMust(t, err)
		if got.Inode == before.Inode {
			if got.FileType != before.FileType || got.Generation == before.Generation || got.Handle == before.Handle {
				t.Fatalf("reused inode lost generation: before=%+v after=%+v", before, got)
			}
			t.Logf("real reuse attempts=%d inode=%d generation=%d->%d handle=%x->%x", attempt+1, got.Inode, before.Generation, got.Generation, before.Handle, got.Handle)
			return got
		}
	}
	t.Fatal("real same-inode reuse not observed within 4096 attempts/15s")
	return a.Ext4ObjectV1{}
}

func TestNativePrepareIdentity102Reuse(t *testing.T) {
	for _, kind := range []string{"file", "root"} {
		t.Run(kind, func(t *testing.T) {
			root := identity102Root(t)
			parent := identity102Open(t, root)
			path := filepath.Join(root, "same-name")
			if kind == "root" {
				copyHostMust(t, os.Mkdir(path, 0700))
			} else {
				copyHostMust(t, os.WriteFile(path, []byte("old"), 0600))
			}
			before, err := copyIdentityAt(int(parent.Fd()), "same-name")
			copyHostMust(t, err)
			after := identity102Reuse(t, int(parent.Fd()), path, before)
			fresh, err := copyIdentityAt(int(parent.Fd()), "same-name")
			copyHostMust(t, err)
			if fresh != after || fresh == before {
				t.Fatal("fresh observation adopted the unlinked generation")
			}
		})
	}
}

func TestNativePrepareIdentity102CrossFilesystem(t *testing.T) {
	h := copyBootstrapSession(t, identity102Root(t))
	intent, err := h.guard.BeginCopy(h.root)
	copyHostMust(t, err)
	foreign := identity102Open(t, "/") // existing fixture's distinct read-only ext4, never mutated
	var fs unix.Statfs_t
	copyHostMust(t, unix.Fstatfs(int(foreign.Fd()), &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		t.Fatal("fixture root is not read-only ext4")
	}
	uuid, err := backingUUID(int(foreign.Fd()))
	copyHostMust(t, err)
	object, err := ext4Identity(int(foreign.Fd()))
	copyHostMust(t, err)
	if uuid == h.root.BackingUUID {
		t.Fatal("cross-filesystem control did not observe distinct UUIDs")
	}
	// Both are existing mounted filesystem roots, not fabricated inode numbers.
	// ext4 roots provide a deterministic numeric collision without another image.
	bounded := identity102Open(t, "/scratch")
	boundedUUID, err := backingUUID(int(bounded.Fd()))
	copyHostMust(t, err)
	boundedObject, err := ext4Identity(int(bounded.Fd()))
	copyHostMust(t, err)
	if boundedUUID != h.root.BackingUUID || boundedUUID == uuid || boundedObject.Inode != object.Inode || boundedObject.FileType != object.FileType {
		t.Fatal("required same numeric inode on distinct real ext4 UUIDs not observed")
	}
	t.Logf("cross-FS same inode=%d UUID=%x/%x full handles=%x/%x", object.Inode, boundedUUID, uuid, boundedObject.Handle, object.Handle)
	foreignSession := &Session{root: foreign, binding: h.session.binding}
	if _, err := foreignSession.copyRoot(h.guard); !errors.Is(err, unix.EXDEV) {
		t.Fatalf("foreign UUID accepted by copyRoot: %v", err)
	}
	observed := h.root
	observed.BackingUUID, observed.Root = uuid, object
	if _, err := h.guard.InspectCopy(intent.ID, observed); !errors.Is(err, a.ErrConflict) {
		t.Fatalf("foreign physical root adopted: %v", err)
	}
	// The existing /scratch bind is an actual ext4-to-ext4 mount crossing.
	if fd, err := copyPinAt(int(foreign.Fd()), "scratch", unix.O_PATH); !errors.Is(err, unix.EXDEV) {
		if err == nil {
			unix.Close(fd)
		}
		t.Fatalf("cross-mount identity traversal: %v", err)
	}
	sibling := identity102Open(t, identity102Root(t))
	sameFS := &Session{root: sibling, binding: h.session.binding}
	other, err := sameFS.copyRoot(h.guard)
	copyHostMust(t, err)
	if other.BackingUUID != h.root.BackingUUID || other.Root == h.root.Root {
		t.Fatal("same-filesystem different-root control is not distinct")
	}
	if _, err := h.guard.InspectCopy(intent.ID, other); !errors.Is(err, a.ErrConflict) {
		t.Fatalf("same-filesystem wrong root adopted: %v", err)
	}
	if _, err := h.guard.InspectCopy(intent.ID, h.root); err != nil {
		t.Fatal(err)
	}
	t.Logf("observed UUIDs bounded=%x readonly=%x roots=%+v/%+v", h.root.BackingUUID, uuid, h.root.Root, object)
}

func TestNativePrepareIdentity102ForgetRelookup(t *testing.T) {
	h := copyBootstrapSession(t, identity102Root(t))
	binding := h.session.binding
	root := filepath.Join(h.path, "volumes", "data")
	identities := map[string]a.Ext4ObjectV1{}
	for _, name := range []string{"a", "b", "c", "d"} {
		copyHostMust(t, os.WriteFile(filepath.Join(root, name), []byte(name), 0600))
		identity, err := copyIdentityAt(int(h.session.root.Fd()), name)
		copyHostMust(t, err)
		identities[name] = identity
	}
	sequence := uint64(0)
	call := func(auth w.Auth, body w.RequestBody) w.ReplyBody {
		sequence++
		result, err := h.session.Dispatch(h.guard, w.Request{Sequence: sequence, Auth: auth, Body: body})
		copyHostMust(t, err)
		if result.Reply.Errno != 0 {
			t.Fatal(result)
		}
		return result.Reply.Body
	}
	handle := call(caller(0, 0), w.OpenDirRequest{Node: 1}).(w.OpenDirReply).Opened.Handle
	intent := call(caller(0, 0), w.PrepareRequest{Node: 1, Handle: handle, Action: w.BeginCopy}).(w.PrepareReply).Intent
	previous := map[string]w.NodeID{}
	objects := map[string]w.ObjectID{}
	for _, order := range []string{"abcd", "dbac", "cadb"} {
		var forgotten []w.ForgetEntry
		for _, letter := range order {
			name := string(letter)
			entry := call(caller(0, 0), w.LookupRequest{Parent: 1, Name: []byte(name)}).(w.LookupReply).Entry
			if entry.Node == previous[name] {
				t.Fatal("FORGET retained old session-local node")
			}
			previous[name] = entry.Node
			if object, seen := objects[name]; seen && object != entry.Object {
				t.Fatal("same-A shuffled lookup lost retained registry object identity")
			}
			objects[name] = entry.Object
			got := call(caller(0, 0), w.PrepareRequest{Node: 1, Handle: handle, Action: w.IdentityAt, Intent: intent.ID, Path: []byte(name)}).(w.PrepareReply)
			if got.Identity != identities[name] || got.Root != h.root || h.session.binding != binding {
				t.Fatal("shuffled relookup changed durable identity or attachment")
			}
			forgotten = append(forgotten, w.ForgetEntry{Node: entry.Node, Count: 1})
		}
		call(lifecycle, w.ForgetRequest{Entries: forgotten})
		// FORGET collects session nodes; registry identity pins intentionally
		// survive until the last session drains, independent of lookup order.
		if len(h.session.nodes) != 1 || len(h.session.registry.objects) != 5 {
			t.Fatal("FORGET failed to collect nodes or discarded registry identity pins")
		}
	}
	call(caller(0, 0), w.PrepareRequest{Node: 1, Handle: handle, Action: w.FinishCopy, Intent: intent.ID})
	borrowed := identity102Open(t, root)
	copyHostMust(t, h.session.registry.Barrier(binding, borrowed))
	if !h.session.closed || len(h.session.nodes) != 0 || len(h.session.handles) != 0 || len(h.session.registry.objects) != 0 || len(h.session.registry.sessions) != 0 {
		t.Fatal("last-session barrier did not drain every registry/session pin")
	}
}

func identity102Control(t *testing.T, h *copyObligationHost) func(w.PrepareAction, a.ID) w.PrepareReply {
	t.Helper()
	sequence := uint64(1)
	opened := copyBootstrapDispatch(t, h, sequence, w.OpenDirRequest{Node: 1})
	if opened.Reply.Errno != 0 {
		t.Fatal(opened)
	}
	handle := opened.Reply.Body.(w.OpenDirReply).Opened.Handle
	return func(action w.PrepareAction, id a.ID) w.PrepareReply {
		t.Helper()
		sequence++
		result := copyBootstrapDispatch(t, h, sequence, w.PrepareRequest{Node: 1, Handle: handle, Action: action, Intent: id})
		if result.Reply.Errno != 0 {
			t.Fatalf("PREPARE %v: %+v", action, result)
		}
		return result.Reply.Body.(w.PrepareReply)
	}
}

func identity102Manifest(t *testing.T, h *copyObligationHost, large bool) (a.CopyIntent, []byte) {
	t.Helper()
	control := identity102Control(t, h)
	intent := control(w.BeginCopy, "").Intent
	intent = control(w.BindCopyTransaction, intent.ID).Intent
	tx := filepath.Join(h.path, "volumes", "data", copyTransactionPath)
	copyHostMust(t, os.Mkdir(filepath.Join(tx, "staging"), 0700))
	manifest := copyCleanupManifest{Version: 4, Intent: intent.ID, Physical: intent.Root}
	add := func(name string, directory bool) {
		path := filepath.Join(tx, "staging", name)
		if directory {
			copyHostMust(t, os.Mkdir(path, 0700))
		} else {
			copyHostMust(t, os.WriteFile(path, []byte("owned:"+name), 0600))
		}
		identity, err := copyIdentityAt(int(h.session.root.Fd()), copyTransactionPath+"/staging/"+name)
		copyHostMust(t, err)
		manifest.Entries = append(manifest.Entries, struct {
			Path     string         `json:"path"`
			Identity a.Ext4ObjectV1 `json:"identity"`
		}{name, identity})
	}
	if large {
		prefix := ""
		for i := 0; i < 4; i++ {
			prefix = filepath.Join(prefix, strings.Repeat("d", 200))
			add(prefix, true)
		}
		for i := 0; i < 1024; i++ {
			add(filepath.Join(prefix, fmt.Sprintf("%04d-%s", i, strings.Repeat("f", 210))), false)
		}
	} else {
		add("a", false)
		add("z", false)
	}
	// Include the initializer's complete v4 root record, not just the server's
	// identity-only projection. The fresh native root must have observed empty
	// supported xattrs; no invented unsupported/empty fallback is allowed.
	var st unix.Stat_t
	var fs unix.Statfs_t
	copyHostMust(t, unix.Fstat(int(h.session.root.Fd()), &st))
	copyHostMust(t, unix.Fstatfs(int(h.session.root.Fd()), &fs))
	xattrs, err := unix.Flistxattr(int(h.session.root.Fd()), nil)
	copyHostMust(t, err)
	if xattrs != 0 {
		t.Fatal("native manifest root unexpectedly has xattrs")
	}
	rootMetadata := identity102RootMetadata{Filesystem: fs.Fsid.Val, Device: st.Dev, Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777,
		Xattrs: identity102Xattrs{State: "supported", Entries: []struct{}{}}}
	raw, err := json.Marshal(struct {
		copyCleanupManifest
		Root identity102RootMetadata `json:"root"`
	}{manifest, rootMetadata})
	copyHostMust(t, err)
	// Validate actual JSON/identities, not arbitrary padded or zero-filled bytes.
	entries, err := copyExpectedEntries(bytes.NewReader(raw), intent)
	copyHostMust(t, err)
	if len(entries) != len(manifest.Entries) {
		t.Fatal("manifest entries lost")
	}
	copyHostMust(t, os.WriteFile(filepath.Join(tx, "manifest.json"), raw, 0600))
	copyHostMust(t, unix.Syncfs(int(h.session.root.Fd())))
	intent = control(w.SealManifest, intent.ID).Intent
	if intent.Phase != a.CopySealed || intent.ManifestSize != uint64(len(raw)) || intent.ManifestDigest != sha256.Sum256(raw) {
		t.Fatal("seal did not bind exact valid manifest")
	}
	return intent, raw
}

// Matches supervisor.confinedCopyRootMetadata's v4 JSON schema. Values come
// only from this test's real root; the supported-empty xattr prerequisite above
// is checked against the kernel, rather than silently discarding attributes.
type identity102RootMetadata struct {
	Filesystem [2]int32          `json:"filesystem"`
	Device     uint64            `json:"device"`
	Inode      uint64            `json:"inode"`
	UID        uint32            `json:"uid"`
	GID        uint32            `json:"gid"`
	Mode       uint32            `json:"mode"`
	Xattrs     identity102Xattrs `json:"xattrs"`
}
type identity102Xattrs struct {
	State   string     `json:"state"`
	Entries []struct{} `json:"entries"`
}

type identity102SnapshotEntry struct {
	Stat   unix.Stat_t
	Digest [32]byte
}

func identity102Snapshot(t *testing.T, root string) map[string]identity102SnapshotEntry {
	t.Helper()
	result := map[string]identity102SnapshotEntry{}
	copyHostMust(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var value identity102SnapshotEntry
		if err := unix.Lstat(path, &value.Stat); err != nil {
			return err
		}
		value.Stat.Atim = unix.Timespec{} // the observer's reads may update atime
		if entry.Type().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value.Digest = sha256.Sum256(raw)
		}
		result[path] = value
		return nil
	}))
	return result
}

func TestNativePrepareIdentity102ManifestAuthenticity(t *testing.T) {
	for _, change := range []string{"altered", "copied", "late-uncertain"} {
		t.Run(change, func(t *testing.T) {
			h := copyBootstrapSession(t, identity102Root(t))
			intent, raw := identity102Manifest(t, h, false)
			tx := filepath.Join(h.path, "volumes", "data", copyTransactionPath)
			switch change {
			case "altered":
				// Still a valid, semantically identical journal, but not the sealed bytes.
				raw = append(raw, '\n')
				copyHostMust(t, os.WriteFile(filepath.Join(tx, "manifest.json"), raw, 0600))
			case "copied":
				donor := copyBootstrapSession(t, identity102Root(t))
				_, raw = identity102Manifest(t, donor, false)
				copyHostMust(t, os.WriteFile(filepath.Join(tx, "manifest.json"), raw, 0600))
			case "late-uncertain":
				parent := identity102Open(t, filepath.Join(tx, "staging"))
				before, err := copyIdentityAt(int(parent.Fd()), "z")
				copyHostMust(t, err)
				identity102Reuse(t, int(parent.Fd()), filepath.Join(tx, "staging", "z"), before)
			}
			root := filepath.Join(h.path, "volumes", "data")
			before := identity102Snapshot(t, root)
			metadata, err := copyRootCleanup(int(h.session.root.Fd()))
			copyHostMust(t, err)
			for attempt := 0; attempt < 2; attempt++ {
				_, err := h.session.startCopyCleanup(h.guard, intent)
				want := a.ErrConflict
				if change == "late-uncertain" {
					want = unix.ESTALE
				}
				if !errors.Is(err, want) {
					t.Fatalf("%s cleanup: got %v want %v", change, err, want)
				}
				afterMetadata, err := copyRootCleanup(int(h.session.root.Fd()))
				copyHostMust(t, err)
				if metadata != afterMetadata || !reflect.DeepEqual(before, identity102Snapshot(t, root)) {
					t.Fatal("refused cleanup changed root/earlier child/journal/staging")
				}
				current, err := h.guard.InspectCopy(intent.ID, intent.Root)
				copyHostMust(t, err)
				if current != intent {
					t.Fatal("refused cleanup changed durable intent")
				}
			}
		})
	}
}

// These are storage-side authenticity/cleanup cases, not a claim that this
// direct session drives the supervisor's published-entry rollback algorithm.
// Publication is a real NOREPLACE rename, with both containing dirs synced.
func TestNativePrepareIdentity102PublicationAuthenticity(t *testing.T) {
	for published, phase := range []string{"private", "first-published", "all-published"} {
		t.Run(phase, func(t *testing.T) {
			for _, change := range []string{"valid", "root-metadata", "path", "handle", "digest", "late-uncertain"} {
				t.Run(change, func(t *testing.T) {
					h := copyBootstrapSession(t, identity102Root(t))
					intent, raw := identity102Manifest(t, h, false)
					root := filepath.Join(h.path, "volumes", "data")
					tx := filepath.Join(root, copyTransactionPath)
					staging := identity102Open(t, filepath.Join(tx, "staging"))
					for _, name := range []string{"a", "z"}[:published] {
						copyHostMust(t, unix.Renameat2(int(staging.Fd()), name, int(h.session.root.Fd()), name, unix.RENAME_NOREPLACE))
					}
					copyHostMust(t, unix.Fsync(int(staging.Fd())))
					copyHostMust(t, unix.Fsync(int(h.session.root.Fd())))
					if change == "root-metadata" || change == "path" || change == "handle" {
						var manifest struct {
							copyCleanupManifest
							Root identity102RootMetadata `json:"root"`
						}
						copyHostMust(t, json.Unmarshal(raw, &manifest))
						switch change {
						case "root-metadata":
							manifest.Root.Mode ^= 0001
						case "path":
							manifest.Entries[0].Path, manifest.Entries[1].Path = manifest.Entries[1].Path, manifest.Entries[0].Path
						case "handle":
							manifest.Entries[0].Identity = manifest.Entries[1].Identity // another actually observed full handle, never fake generation
						}
						var err error
						raw, err = json.Marshal(manifest)
						copyHostMust(t, err)
					} else if change == "digest" {
						raw = append(raw, '\n') // valid, semantically identical JSON; different sealed digest
					} else if change == "late-uncertain" {
						// The lexically last unowned real child must prevent deletion
						// of every earlier staged entry, even after partial publication.
						copyHostMust(t, os.WriteFile(filepath.Join(tx, "staging", "zz-unowned"), []byte("never-authorized"), 0600))
					}
					if change != "valid" && change != "late-uncertain" {
						if sha256.Sum256(raw) == intent.ManifestDigest {
							t.Fatal("adversary did not alter sealed bytes")
						}
						copyHostMust(t, os.WriteFile(filepath.Join(tx, "manifest.json"), raw, 0600))
					}
					copyHostMust(t, unix.Syncfs(int(h.session.root.Fd())))
					before := identity102Snapshot(t, h.path)
					metadata, err := copyRootCleanup(int(h.session.root.Fd()))
					copyHostMust(t, err)
					if change == "valid" {
						got, err := h.session.authenticateCopyManifest(h.guard, intent, false)
						copyHostMust(t, err)
						if got != intent {
							t.Fatal("auth changed valid intent")
						}
						cleaning, err := h.session.startCopyCleanup(h.guard, intent)
						copyHostMust(t, err)
						copyHostMust(t, h.session.finishCopyCleanup(h.guard, cleaning))
						if _, err := os.Lstat(tx); !errors.Is(err, os.ErrNotExist) {
							t.Fatal("valid cleanup retained transaction", err)
						}
						after, err := copyRootCleanup(int(h.session.root.Fd()))
						copyHostMust(t, err)
						if after != metadata {
							t.Fatal("valid cleanup lost exact root metadata")
						}
						for _, name := range []string{"a", "z"}[:published] {
							path := filepath.Join(root, name)
							if identity102Snapshot(t, path)[path] != before[path] {
								t.Fatal("server cleanup changed published entry")
							}
						}
						return
					}
					for attempt := 0; attempt < 2; attempt++ {
						_, err := h.session.startCopyCleanup(h.guard, intent)
						want := a.ErrConflict
						if change == "late-uncertain" {
							want = unix.ESTALE
						}
						if !errors.Is(err, want) {
							t.Fatalf("cleanup got %v want %v", err, want)
						}
						after, err := copyRootCleanup(int(h.session.root.Fd()))
						copyHostMust(t, err)
						if after != metadata || !reflect.DeepEqual(before, identity102Snapshot(t, h.path)) {
							t.Fatal("refusal changed root/published/staging/journal/authority")
						}
						got, err := h.guard.InspectCopy(intent.ID, intent.Root)
						copyHostMust(t, err)
						if got != intent {
							t.Fatal("refusal changed durable intent")
						}
					}
				})
			}
		})
	}
}

type identity102Reader struct {
	io.Reader
	maximum int
}

func (r *identity102Reader) Read(p []byte) (int, error) {
	if len(p) > r.maximum {
		r.maximum = len(p)
	}
	return r.Reader.Read(p)
}

func TestNativePrepareIdentity102LargeManifestRecovery(t *testing.T) {
	path := identity102Root(t)
	h := copyBootstrapSession(t, path)
	intent, raw := identity102Manifest(t, h, true)
	if len(raw) <= 1<<20 || len(raw) >= 64<<20 || a.MaxCopyManifestBytes != 64<<20 {
		t.Fatalf("valid manifest bound: %d", len(raw))
	}
	file := identity102Open(t, filepath.Join(path, "volumes", "data", copyTransactionPath, "manifest.json"))
	reader := &identity102Reader{Reader: file}
	digest, size, err := digestCopyManifest(reader)
	copyHostMust(t, err)
	if reader.maximum > 128<<10 || size != intent.ManifestSize || digest != intent.ManifestDigest {
		t.Fatal("valid manifest digest/buffer bound regressed")
	}
	// Close the real session/authority, then use the existing authenticated
	// retire/ReplacePrepare fixture to reopen the durable SEALED intent twice.
	for reopen := 0; reopen < 2; reopen++ {
		previous := h.session.binding
		borrowed := identity102Open(t, filepath.Join(path, "volumes", "data"))
		copyHostMust(t, h.session.registry.Barrier(previous, borrowed))
		h.guard.Release()
		copyHostMust(t, h.authority.Close())
		h = copyBootstrapSession(t, path)
		if h.session.binding.Prepare == previous.Prepare || h.session.binding.Attachment == previous.Attachment || h.authority.Epoch() == intent.Epoch {
			t.Fatal("reopen did not create fresh P/A/E")
		}
		control := identity102Control(t, h)
		got := control(w.BeginCopy, "").Intent
		if got.ID != intent.ID || got.Root != intent.Root || got.ManifestDigest != digest || got.Phase != a.CopySealed {
			t.Fatal("reopen lost sealed large manifest")
		}
		intent = control(w.AuthenticateManifest, intent.ID).Intent
		if reopen == 1 {
			intent = control(w.StartCleanup, intent.ID).Intent
			if intent.Phase != a.CopyCleaning {
				t.Fatal("cleanup not durably recorded")
			}
			control(w.FinishCopy, intent.ID)
			if _, err := os.Lstat(filepath.Join(path, "volumes", "data", copyTransactionPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("large valid manifest recovery retained transaction", err)
			}
			if _, err := h.guard.InspectCopy(intent.ID, intent.Root); !errors.Is(err, a.ErrUnauthorized) {
				t.Fatal("completed intent replay accepted", err)
			}
			fresh := control(w.BeginCopy, "").Intent
			if fresh.ID == intent.ID {
				t.Fatal("fresh Begin reused completed intent")
			}
			control(w.FinishCopy, fresh.ID)
		}
	}
	t.Logf("recovered valid manifest bytes=%d entries=%d max_digest_read=%d", len(raw), 1028, reader.maximum)
}
