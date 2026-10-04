//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func dispatchRaw(f *fixture, s *Session, auth w.Auth, body w.RequestBody) (Result, error) {
	f.t.Helper()
	f.sequence[s]++
	r := w.Request{Sequence: f.sequence[s], Auth: auth, Body: body}
	g, err := f.authority.Admit(s.principal, s.binding.Volume, r.Mutates())
	if err != nil {
		return Result{}, err
	}
	defer g.Release()
	return s.Dispatch(g, r)
}
func TestEverySyncFailureIsStickyAcrossVolumePeersAndReceipts(t *testing.T) {
	for _, kind := range []string{"fsync", "fdatasync", "syncfs", "flush", "release", "fsyncdir"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			s, root := f.session(a.ReadWrite)
			peer, peerRoot := f.session(a.ReadWrite)
			c := f.call(s, caller(1001, 1001), w.CreateRequest{Parent: root.Node, Name: []byte("file"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
			var body w.RequestBody
			auth := grantAuth
			ops := platformSyncOperations()
			f.registry.syncOps = ops
			fired := false
			failOnce := func(real func(int) error) func(int) error {
				return func(fd int) error {
					if !fired {
						fired = true
						return unix.EIO
					}
					return real(fd)
				}
			}
			switch kind {
			case "fsync":
				f.registry.syncOps.fsync = failOnce(ops.fsync)
				body = w.FsyncRequest{Node: c.Entry.Node, Handle: c.Opened.Handle}
			case "fdatasync":
				f.registry.syncOps.fdatasync = failOnce(ops.fdatasync)
				body = w.FsyncRequest{Node: c.Entry.Node, Handle: c.Opened.Handle, DataOnly: true}
			case "syncfs":
				f.registry.syncOps.syncfs = failOnce(ops.syncfs)
				body = w.WriteRequest{Node: c.Entry.Node, Handle: c.Opened.Handle, Data: []byte("persist")}
			case "flush":
				f.registry.syncOps.fsync = failOnce(ops.fsync)
				body = w.FlushRequest{Node: c.Entry.Node, Handle: c.Opened.Handle}
			case "release":
				f.registry.syncOps.fsync = failOnce(ops.fsync)
				auth = lifecycle
				body = w.ReleaseRequest{Node: c.Entry.Node, Handle: c.Opened.Handle}
			case "fsyncdir":
				h := f.call(s, caller(1001, 1001), w.OpenDirRequest{Node: root.Node}).(w.OpenDirReply).Opened.Handle
				f.registry.syncOps.fsync = failOnce(ops.fsync)
				body = w.FsyncDirRequest{Node: root.Node, Handle: h}
			}
			f.expectFaults = true
			result, err := dispatchRaw(f, s, auth, body)
			if !fired || !errors.Is(err, ErrVolumeFault) || !errors.Is(err, unix.EIO) || result.Reply.Errno != uint32(unix.EIO) {
				t.Fatalf("failure not returned/latching: %+v %v", result, err)
			}
			f.registry.syncOps = ops // later successful flushes must NOT erase the evidence
			for _, pair := range []struct {
				s    *Session
				root w.NodeID
			}{{s, root.Node}, {peer, peerRoot.Node}} {
				_, err = dispatchRaw(f, pair.s, metadata, w.GetAttrRequest{Node: pair.root})
				if !errors.Is(err, ErrVolumeFault) {
					t.Fatal("volume peer continued", err)
				}
			}
			_, err = f.authority.Admit(s.principal, s.binding.Volume, false)
			if !errors.Is(err, a.ErrBlocked) {
				t.Fatal("faulted authority admitted work", err)
			}
			receipt, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch})
			if err == nil || receipt.Revision != 0 {
				t.Fatal("durability failure minted a receipt", receipt, err)
			}
			// Global authority quarantine rejects Retire; local cleanup is not proof.
			_ = f.registry.Barrier(s.binding, f.volume)
			if !s.closed || len(s.handles) != 0 || len(s.nodes) != 0 {
				t.Fatal("faulted barrier skipped cleanup")
			}
			if err = f.registry.Barrier(s.binding, f.volume); !errors.Is(err, ErrVolumeFault) {
				t.Fatal("second barrier erased fault", err)
			}
		})
	}
}
func TestFinalBarrierClosesOrphanOwnersBeforeSyncfs(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("orphan"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	f.call(s, grantAuth, w.WriteRequest{Node: c.Entry.Node, Handle: c.Opened.Handle, Data: []byte("orphan data")})
	f.call(s, auth, w.UnlinkRequest{Parent: root.Node, Name: []byte("orphan")})
	descriptors := []int{int(s.root.Fd()), int(s.metadataFD.Fd()), s.handles[c.Opened.Handle].fd}
	for _, obj := range f.registry.objects {
		descriptors = append(descriptors, obj.fd)
	}
	for _, n := range s.nodes {
		descriptors = append(descriptors, n.fd)
	}
	called := false
	f.registry.syncOps.syncfs = func(fd int) error {
		called = true
		for _, closed := range descriptors {
			if _, err := stat(closed); !errors.Is(err, unix.EBADF) {
				t.Errorf("syncfs preceded last close of fd %d: %v", closed, err)
			}
		}
		if len(f.registry.objects) != 0 || len(s.nodes) != 0 || len(s.handles) != 0 {
			t.Error("syncfs preceded ownership cleanup")
		}
		if _, err := stat(fd); err != nil {
			t.Errorf("authority borrowed root closed: %v", err)
		}
		return unix.Syncfs(fd)
	}
	_, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch})
	must(t, err)
	if !called {
		t.Fatal("missing final syncfs")
	}
}
func TestPostNamespaceFailureTerminatesAllPeersWithoutFabricatedEvents(t *testing.T) {
	for _, kind := range []string{"create", "mkdir", "mknod", "symlink", "link", "rename", "unlink", "rmdir"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			s, root := f.session(a.ReadWrite)
			peer, peerRoot := f.session(a.ReadWrite)
			auth := caller(1001, 1001)
			c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("source"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
			f.call(s, auth, w.MkdirRequest{Parent: root.Node, Name: []byte("dir"), Mode: 0700})
			var body w.RequestBody
			changed := "new"
			switch kind {
			case "create":
				body = w.CreateRequest{Parent: root.Node, Name: []byte(changed), Flags: w.OpenReadWrite, Mode: 0600}
			case "mkdir":
				body = w.MkdirRequest{Parent: root.Node, Name: []byte(changed), Mode: 0700}
			case "mknod":
				body = w.MknodRequest{Parent: root.Node, Name: []byte(changed), Mode: unix.S_IFREG | 0600}
			case "symlink":
				body = w.SymlinkRequest{Parent: root.Node, Name: []byte(changed), Target: []byte("source")}
			case "link":
				body = w.LinkRequest{Source: c.Entry.Node, Parent: root.Node, Name: []byte(changed)}
			case "rename":
				body = w.RenameRequest{OldParent: root.Node, OldName: []byte("source"), NewParent: root.Node, NewName: []byte(changed)}
			case "unlink":
				changed = "source"
				body = w.UnlinkRequest{Parent: root.Node, Name: []byte(changed)}
			case "rmdir":
				changed = "dir"
				body = w.RmdirRequest{Parent: root.Node, Name: []byte(changed)}
			}
			f.registry.postNamespace = func() error { return unix.EMFILE }
			f.expectFaults = true
			result, err := dispatchRaw(f, s, auth, body)
			if !errors.Is(err, ErrVolumeFault) || !errors.Is(err, unix.EMFILE) {
				t.Fatal("uncertain mutation did not fence volume", err)
			}
			_, diskErr := os.Lstat(filepath.Join(f.path, "volumes", "data", changed))
			if kind == "unlink" || kind == "rmdir" {
				if !errors.Is(diskErr, os.ErrNotExist) {
					t.Fatal("syscall did not run", diskErr)
				}
			} else {
				must(t, diskErr)
			}
			if len(result.Events) != 1 || result.Events[0].Kind != w.InvalidateAttr || result.Events[0].Object != root.Object {
				t.Fatalf("lost truthful parent event or fabricated child identity: %+v", result.Events)
			}
			_, err = dispatchRaw(f, peer, metadata, w.GetAttrRequest{Node: peerRoot.Node})
			if !errors.Is(err, ErrVolumeFault) {
				t.Fatal("peer continued", err)
			}
		})
	}
}
