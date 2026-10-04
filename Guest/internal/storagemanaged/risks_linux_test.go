//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestAppendGrantIsOffsetAddressedAndHandlesNeverUpgrade(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("append"), Flags: w.OpenReadWrite | w.OpenAppend, Mode: 0600}).(w.CreateReply)
	n, h := c.Entry.Node, c.Opened.Handle
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, WriteFlags: w.WriteCache, Data: []byte("abc")})
	f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: h, WriteFlags: w.WriteCache, Offset: 1, Data: []byte("Z")})
	got := f.call(s, grantAuth, w.ReadRequest{Node: n, Handle: h, Size: 8}).(w.ReadReply)
	if string(got.Data) != "aZc" {
		t.Fatal("pwrite incorrectly appended", string(got.Data))
	}
	read := f.call(s, auth, w.OpenRequest{Node: n}).(w.OpenReply).Opened.Handle
	f.wantError(s, grantAuth, w.WriteRequest{Node: n, Handle: read, IOFlags: w.OpenReadWrite, Data: []byte("bad")}, unix.EBADF)
	f.wantError(s, grantAuth, w.ReadRequest{Node: root.Node, Handle: h, Size: 1}, unix.EBADF)
	f.wantError(s, grantAuth, w.FsyncDirRequest{Node: n, Handle: h}, unix.EBADF)
	f.wantError(s, grantAuth, w.WriteRequest{Node: n, Handle: h, IOFlags: w.OpenReadWrite | w.OpenDirect, Data: []byte("bad")}, unix.EINVAL)
	f.call(s, lifecycle, w.ForgetRequest{Entries: []w.ForgetEntry{{Node: n, Count: 1}}})
	if s.nodes[n] == nil {
		t.Fatal("forgotten open node prematurely collected")
	}
	f.call(s, lifecycle, w.ReleaseRequest{Node: n, Handle: read})
	f.call(s, lifecycle, w.ReleaseRequest{Node: n, Handle: h})
	if s.nodes[n] != nil {
		t.Fatal("node ownership leaked after last close")
	}
}
func TestForgetUnderflowIsAtomicAndTerminal(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	e := f.call(s, caller(1001, 1001), w.MkdirRequest{Parent: root.Node, Name: []byte("d"), Mode: 0700}).(w.MkdirReply).Entry
	f.wantError(s, lifecycle, w.ForgetRequest{Entries: []w.ForgetEntry{{Node: root.Node, Count: 1}, {Node: e.Node, Count: 2}}}, unix.EINVAL)
	if s.nodes[root.Node].lookups != 1 || s.nodes[e.Node].lookups != 1 || !s.failed {
		t.Fatal("partially applied corrupt forget")
	}
}
func TestRenameExchangeAndExactPinsAcrossSessions(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	other, otherRoot := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	first := f.call(s, auth, w.SymlinkRequest{Parent: root.Node, Name: []byte("one"), Target: []byte("one-target")}).(w.SymlinkReply).Entry
	second := f.call(s, auth, w.SymlinkRequest{Parent: root.Node, Name: []byte("two"), Target: []byte("two-target")}).(w.SymlinkReply).Entry
	remote := f.call(other, auth, w.LookupRequest{Parent: otherRoot.Node, Name: []byte("one")}).(w.LookupReply).Entry
	f.call(s, auth, w.RenameRequest{OldParent: root.Node, OldName: []byte("one"), NewParent: root.Node, NewName: []byte("two"), Flags: w.RenameExchange})
	linked := f.call(other, auth, w.LinkRequest{Source: remote.Node, Parent: otherRoot.Node, Name: []byte("alias")}).(w.LinkReply).Entry
	if linked.Object != first.Object {
		t.Fatal("exact pin selected replacement inode")
	}
	got := f.call(s, auth, w.LookupRequest{Parent: root.Node, Name: []byte("one")}).(w.LookupReply).Entry
	if got.Object != second.Object {
		t.Fatal("exchange failed")
	}
	// Sticky-directory ownership and protected_hardlinks are kernel checks.
	must(t, os.Chmod(filepath.Join(f.path, "volumes", "data"), os.ModeSticky|0777))
	f.wantError(other, caller(1002, 1002), w.UnlinkRequest{Parent: otherRoot.Node, Name: []byte("alias")}, unix.EPERM)
}
func TestRetirementJoinsQueuedAdmittedWork(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	g, err := f.authority.Admit(s.principal, s.binding.Volume, false)
	must(t, err)
	f.gate.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := s.Dispatch(g, w.Request{Sequence: 1, Auth: metadata, Body: w.GetAttrRequest{Node: root.Node}})
		g.Release()
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	req := a.RetireRequest{Operation: newID(t), Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch}
	_, err = f.authority.Retire(ctx, f.control, req)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		f.gate.Unlock()
		t.Fatal(err)
	}
	if s.closed {
		f.gate.Unlock()
		t.Fatal("barrier overtook queued guard")
	}
	f.gate.Unlock()
	must(t, <-done)
	_, err = f.authority.Retire(context.Background(), f.control, req)
	must(t, err)
	if !s.closed {
		t.Fatal("barrier did not close session")
	}
}
func TestSemanticTruncateAndRejectedLegacySignals(t *testing.T) {
	f := newFixture(t)
	s, root := f.session(a.ReadWrite)
	auth := caller(1001, 1001)
	c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("suid"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	n := c.Entry.Node
	f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 06777})
	f.call(s, auth, w.SetAttrRequest{Node: n, Valid: w.SetSize, Semantics: w.MetadataValid | w.MetadataCTime | w.MetadataOpen | w.MetadataForce | w.MetadataKillSUID | w.MetadataKillSGID})
	st := f.call(s, metadata, w.GetAttrRequest{Node: n}).(w.GetAttrReply).Attr
	if st.Mode&06000 != 0 {
		t.Fatal("open truncate retained set-ID", st)
	}
	for _, tc := range legacyMetadataRequests() {
		t.Run(tc.name, func(t *testing.T) {
			// A malformed request is a terminal protocol error, not a recoverable
			// syscall errno. Never reuse that session, even to inspect metadata.
			f := newFixture(t)
			s, root := f.session(a.ReadWrite)
			c := f.call(s, auth, w.CreateRequest{Parent: root.Node, Name: []byte("unchanged"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
			n := c.Entry.Node
			f.call(s, grantAuth, w.WriteRequest{Node: n, Handle: c.Opened.Handle, Data: []byte("retain data")})
			f.call(s, auth, w.SetAttrRequest{Node: n, Semantics: w.MetadataValid | w.MetadataCTime, Valid: w.SetMode, Mode: 06777})
			fd := s.nodes[n].fd
			before, err := stat(fd)
			must(t, err)
			handles, events := len(s.handles), f.registry.eventSequence
			request := w.Request{Sequence: f.sequence[s] + 1, Auth: auth, Body: tc.request(n)}
			g, err := f.authority.Admit(s.principal, s.binding.Volume, request.Mutates())
			must(t, err)
			result, err := s.Dispatch(g, request)
			g.Release()
			if !errors.Is(err, w.ErrInvalid) || result.Reply != (w.Reply{}) || len(result.Events) != 0 {
				t.Fatal("standalone kill must fail at the wire boundary without a reply", result, err)
			}
			after, err := stat(fd)
			must(t, err)
			if attributes(after) != attributes(before) || len(s.handles) != handles || f.registry.eventSequence != events {
				t.Fatal("standalone kill applied metadata or opened a handle before rejection", before, after)
			}
		})
	}
}
