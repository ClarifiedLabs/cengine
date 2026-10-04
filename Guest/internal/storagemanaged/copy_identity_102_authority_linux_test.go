//go:build cengine_native_faulttest && linux && (amd64 || arm64)

package storagemanaged

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageauthoritytest"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

const identity102AuthorityDirectory = ".cengine-storage-authority"

// Capture a real durable operation while its obligation is live, then discharge
// it normally. Later copying these exact bytes is the adversarial action, not a
// fake crash/abandoned-guard escape. The named subtest's cleanup closes ALL old
// registry/authority/test root pins before the caller can replace a root.
func identity102Capture(t *testing.T, name, path string) (a.Config, *storageauthoritytest.Fixture, a.CopyIntent, []byte) {
	t.Helper()
	var config a.Config
	var expected *storageauthoritytest.Fixture
	var intent a.CopyIntent
	var operation []byte
	if !t.Run(name, func(t *testing.T) {
		h := copyBootstrapSession(t, path)
		intent, _ = identity102Manifest(t, h, false)
		obligation, err := h.guard.BeginCopyOperation(100, a.CopyOperationCleanup, intent.ID)
		copyHostMust(t, err)
		operation, err = os.ReadFile(filepath.Join(path, identity102AuthorityDirectory, "copy-operation"))
		copyHostMust(t, err)
		if len(operation) == 0 || len(operation) > 16384 {
			t.Fatal("invalid captured operation bound")
		}
		copyHostMust(t, obligation.Complete(nil))
		copyHostMust(t, h.lifecycle.Capture(h.authority))
		captured := *h.lifecycle
		expected = &captured
		config = h.config
	}) {
		t.Fatal("capture failed; no adversary may run")
	}
	config.Root = identity102Open(t, path)
	return config, expected, intent, operation
}

func TestNativePrepareIdentity102RegisteredRootReuse(t *testing.T) {
	path := identity102Root(t)
	_, _, intent, _ := identity102Capture(t, "capture", path)
	root := filepath.Join(path, "volumes", "data")
	// Preserve the intact owned transaction (and its genuine inode identities)
	// outside the replaced root, then copy it back by rename, never rewriting it.
	escrow := filepath.Join(path, "held-transaction")
	copyHostMust(t, os.Rename(filepath.Join(root, copyTransactionPath), escrow))
	parent := identity102Open(t, filepath.Dir(root))
	reused := identity102Reuse(t, int(parent.Fd()), root, intent.Root.Root)
	copyHostMust(t, os.Rename(escrow, filepath.Join(root, copyTransactionPath)))
	copyHostMust(t, unix.Syncfs(int(parent.Fd())))
	h := copyBootstrapSession(t, path)
	if h.root.Root != reused || h.root.BackingUUID != intent.Root.BackingUUID || h.session.binding.Volume != intent.Owner.Volume || h.session.binding.Attachment == intent.Owner.Attachment || h.session.binding.Prepare == intent.Owner.Prepare || h.authority.Epoch() == intent.Epoch {
		t.Fatal("registered-root adversary did not retain V/UUID with real reuse and fresh P/A/E")
	}
	// Establish that the old intent really transferred to this current owner;
	// rejection below must be physical identity, not unrelated stale credentials.
	current, err := h.guard.InspectCopy(intent.ID, intent.Root)
	copyHostMust(t, err)
	if current.Owner != h.session.binding || current.Root != intent.Root || current.ManifestDigest != intent.ManifestDigest {
		t.Fatal("lost authenticated predecessor intent")
	}
	opened := copyBootstrapDispatch(t, h, 1, w.OpenDirRequest{Node: 1})
	if opened.Reply.Errno != 0 {
		t.Fatal(opened)
	}
	handle := opened.Reply.Body.(w.OpenDirReply).Opened.Handle
	before := identity102Snapshot(t, path)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := h.session.prepare(h.guard, w.PrepareRequest{Node: 1, Handle: handle, Action: w.IdentityAt, Intent: intent.ID, Path: []byte(".")}); !errors.Is(err, a.ErrConflict) {
			t.Fatal("server PREPARE adopted reused registered root", err)
		}
		if _, err := h.guard.InspectCopy(intent.ID, h.root); !errors.Is(err, a.ErrConflict) {
			t.Fatal("reused registered root adopted", err)
		}
		if _, err := h.guard.BeginCopy(h.root); !errors.Is(err, a.ErrConflict) {
			t.Fatal("fresh Begin adopted old root generation", err)
		}
		if !reflect.DeepEqual(before, identity102Snapshot(t, path)) {
			t.Fatal("root refusal changed journal/staging/replacement")
		}
	}
}

func TestNativePrepareIdentity102SameNameVolume(t *testing.T) {
	path := identity102Root(t)
	backing := identity102Open(t, path)
	uuid, err := backingUUID(int(backing.Fd()))
	copyHostMust(t, err)
	device := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	f := newFixtureAt(t, path, device)
	create := a.CreateVolumeRequest{Operation: newID(t), Store: f.storeID, Volume: newID(t), Name: "recreated"}
	created, err := f.authority.CreateVolume(f.control, create)
	copyHostMust(t, err)
	copyHostMust(t, f.volume.Close())
	f.volume = identity102Open(t, filepath.Join(path, "volumes", create.Name))
	f.volumeID = created.Volume.ID
	old, _ := f.session(a.ReadWrite)
	oldIdentity, err := ext4Identity(int(old.root.Fd()))
	copyHostMust(t, err)
	// Old issued TLS principal and real registry session are active before drain.
	f.call(old, caller(0, 0), w.GetAttrRequest{Node: 1})
	_, err = f.authority.Retire(context.Background(), f.control, a.RetireRequest{Operation: newID(t), Store: f.storeID, Volume: f.volumeID, Attachment: old.binding.Attachment, Launch: old.binding.Launch})
	copyHostMust(t, err)
	if !old.closed {
		t.Fatal("production registry barrier did not close old session")
	}
	remove := a.DeleteVolumeRequest{Operation: newID(t), Store: f.storeID, Volume: f.volumeID}
	deleted, err := f.authority.DeleteVolume(f.control, remove)
	copyHostMust(t, err)
	copyHostMust(t, f.volume.Close())
	freshCreate := a.CreateVolumeRequest{Operation: newID(t), Store: f.storeID, Volume: newID(t), Name: create.Name}
	fresh, err := f.authority.CreateVolume(f.control, freshCreate)
	copyHostMust(t, err)
	if fresh.Volume.ID == created.Volume.ID || fresh.Volume.Name != created.Volume.Name {
		t.Fatal("same-name creation did not issue distinct V")
	}
	f.volumeID = fresh.Volume.ID
	root := filepath.Join(path, "volumes", create.Name)
	f.volume = identity102Open(t, root)
	freshIdentity, err := ext4Identity(int(f.volume.Fd()))
	copyHostMust(t, err)
	if freshIdentity == oldIdentity {
		t.Fatal("new V adopted old physical root")
	}
	copyHostMust(t, os.WriteFile(filepath.Join(root, "keep"), []byte("fresh-volume"), 0640))
	before := identity102Snapshot(t, root)
	journal := identity102Snapshot(t, filepath.Join(path, identity102AuthorityDirectory))
	for attempt := 0; attempt < 2; attempt++ {
		if guard, err := f.authority.Admit(old.principal, fresh.Volume.ID, true); !errors.Is(err, a.ErrUnauthorized) {
			if guard != nil {
				guard.Release()
			}
			t.Fatal("old principal crossed V", err)
		}
		if guard, err := f.authority.Admit(old.principal, created.Volume.ID, true); !errors.Is(err, a.ErrBlocked) {
			if guard != nil {
				guard.Release()
			}
			t.Fatal("deleted V admitted old principal", err)
		}
		again, err := f.authority.DeleteVolume(f.control, remove)
		copyHostMust(t, err)
		if again != deleted {
			t.Fatal("replayed delete lost original receipt")
		}
		again, err = f.authority.CreateVolume(f.control, create)
		copyHostMust(t, err)
		if again != created {
			t.Fatal("replayed create adopted replacement")
		}
		if !reflect.DeepEqual(before, identity102Snapshot(t, root)) || !reflect.DeepEqual(journal, identity102Snapshot(t, filepath.Join(path, identity102AuthorityDirectory))) {
			t.Fatal("stale V authority mutated replacement/journal")
		}
	}
	owner, _ := f.session(a.ReadWrite)
	if owner.binding.Attachment == old.binding.Attachment || owner.binding.Key == old.binding.Key || owner.binding.Volume != fresh.Volume.ID {
		t.Fatal("replacement did not receive new issued owner")
	}
	f.call(owner, caller(0, 0), w.LookupRequest{Parent: 1, Name: []byte("keep")})
}

func TestNativePrepareIdentity102AuthorityJournal(t *testing.T) {
	for _, scenario := range []string{"exact-operation", "foreign-operation", "foreign-state", "stale-operation"} {
		t.Run(scenario, func(t *testing.T) {
			path := identity102Root(t)
			config, expected, _, operation := identity102Capture(t, "target", path)
			name := "copy-operation"
			payload := operation
			if scenario == "foreign-state" || scenario == "foreign-operation" {
				donor := identity102Root(t)
				_, foreign, _, foreignOperation := identity102Capture(t, "source", donor)
				if foreign.Expected.Store == expected.Expected.Store || foreign.Expected.Epoch == expected.Expected.Epoch {
					t.Fatal("donor is not independently issued authority")
				}
				payload = foreignOperation
				if scenario == "foreign-state" {
					name = "state.json"
					var err error
					payload, err = os.ReadFile(filepath.Join(donor, identity102AuthorityDirectory, name))
					copyHostMust(t, err)
				}
			}
			if scenario == "stale-operation" {
				if !t.Run("advance", func(t *testing.T) {
					h := copyBootstrapSession(t, path)
					metadata, err := h.authority.StartupMetadata()
					copyHostMust(t, err)
					if metadata.Epoch == expected.Expected.Epoch {
						t.Fatal("operation replay did not cross actual E")
					}
					copyHostMust(t, h.lifecycle.Capture(h.authority))
					captured := *h.lifecycle
					expected = &captured
				}) {
					t.Fatal("advance failed")
				}
			}
			copyHostMust(t, os.WriteFile(filepath.Join(path, identity102AuthorityDirectory, name), payload, 0600))
			copyHostMust(t, unix.Syncfs(int(config.Root.Fd())))
			before := identity102Snapshot(t, path)
			for attempt := 0; attempt < 2; attempt++ {
				predecessor := expected.Expected.ExpectedStartup
				reopened, err := expected.OpenExpected(config, predecessor)
				if scenario == "exact-operation" {
					copyHostMust(t, err)
					if reopened.Epoch() == predecessor.Epoch {
						t.Fatal("exact valid operation failed to recover")
					}
					copyHostMust(t, reopened.Close())
					// The direct successful open consumed the host fixture's old
					// anchor. Carry its live result into the next owner, never
					// recover an open revision from state.json.
					recoveryPath := filepath.Join(path, "host-copy-recovery.json")
					raw, err := os.ReadFile(recoveryPath)
					copyHostMust(t, err)
					var saved copyHostRecovery
					copyHostMust(t, json.Unmarshal(raw, &saved))
					saved.Lifecycle = expected
					raw, err = json.Marshal(saved)
					copyHostMust(t, err)
					copyHostMust(t, os.WriteFile(recoveryPath, raw, 0600))
					if _, err := os.Lstat(filepath.Join(path, identity102AuthorityDirectory, name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("production recovery did not discharge exact operation", err)
					}
					// Reopen again and install the actual fresh owner. Removing the
					// operation file is insufficient unless durable replay still
					// fences DATA until this exact cleanup has really succeeded.
					h := copyBootstrapSession(t, path)
					if !errors.Is(h.guard.CheckCopyReplay(), a.ErrBlocked) {
						t.Fatal("exact operation lost durable replay fence on second reopen")
					}
					opened := copyBootstrapDispatch(t, h, 1, w.OpenDirRequest{Node: 1})
					if opened.Reply.Errno != 0 {
						t.Fatal(opened)
					}
					handle := opened.Reply.Body.(w.OpenDirReply).Opened.Handle
					begun := copyBootstrapDispatch(t, h, 2, w.PrepareRequest{Node: 1, Handle: handle, Action: w.BeginCopy})
					if begun.Reply.Errno != 0 {
						t.Fatal(begun)
					}
					replay := begun.Reply.Body.(w.PrepareReply)
					if replay.Pending != w.StartCleanup || replay.Intent.Phase != a.CopySealed {
						t.Fatal("wrong reconstructed cleanup obligation", replay)
					}
					pending, err := h.guard.PendingCopyOperation(replay.Intent.ID)
					copyHostMust(t, err)
					if pending != a.CopyOperationCleanup {
						t.Fatal("pending action lost", pending)
					}
					blocked := copyBootstrapDispatch(t, h, 3, w.LookupRequest{Parent: 1, Name: []byte(copyTransactionPath)})
					if blocked.Reply.Errno != uint32(unix.EBUSY) {
						t.Fatal("reconstructed operation admitted ordinary DATA", blocked)
					}
					for index, action := range []w.PrepareAction{w.StartCleanup, w.FinishCopy} {
						result := copyBootstrapDispatch(t, h, uint64(index+4), w.PrepareRequest{Node: 1, Handle: handle, Action: action, Intent: replay.Intent.ID})
						if result.Reply.Errno != 0 {
							t.Fatal("exact cleanup replay failed", result)
						}
					}
					copyHostMust(t, h.guard.CheckCopyReplay())
					if _, err := os.Lstat(filepath.Join(path, "volumes", "data", copyTransactionPath)); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("exact replay retained transaction", err)
					}
					allowed := copyBootstrapDispatch(t, h, 6, w.ReadDirRequest{Node: 1, Handle: handle, MaxBytes: 4096})
					if allowed.Reply.Errno != 0 {
						t.Fatal("successful exact replay did not release DATA", allowed)
					}
					break
				}
				want := a.ErrRepairRequired
				if scenario == "foreign-state" {
					want = a.ErrConflict
				}
				if reopened != nil {
					reopened.Close()
					t.Fatal("foreign/stale journal returned authority")
				}
				if !errors.Is(err, want) {
					t.Fatalf("%s returned %v, want %v", scenario, err, want)
				}
				if !reflect.DeepEqual(before, identity102Snapshot(t, path)) {
					t.Fatal("refused journal changed namespace/bytes/metadata")
				}
			}
		})
	}
}
