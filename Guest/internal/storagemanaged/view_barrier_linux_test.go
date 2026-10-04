//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestReadOnlyFinalBarrierClosesDetachedOrphanPinsBeforeSync(t *testing.T) {
	f := newFixture(t)
	fd, err := unix.Openat(int(f.volume.Fd()), "orphan", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0644)
	must(t, err)
	_, err = unix.Write(fd, []byte("orphan"))
	must(t, err)
	must(t, unix.Close(fd))
	s, root := f.session(a.ReadOnly)
	n := f.call(s, caller(1002, 1002), w.LookupRequest{Parent: root.Node, Name: []byte("orphan")}).(w.LookupReply).Entry.Node
	h := f.call(s, caller(1002, 1002), w.OpenRequest{Node: n}).(w.OpenReply).Opened.Handle
	must(t, unix.Unlinkat(int(f.volume.Fd()), "orphan", 0))
	descriptors := []int{int(s.root.Fd()), int(s.metadataFD.Fd()), s.handles[h].fd}
	for _, n := range s.nodes {
		descriptors = append(descriptors, n.fd)
	}
	for _, obj := range f.registry.objects {
		descriptors = append(descriptors, obj.fd)
	}
	called := false
	f.registry.syncOps.syncfs = func(fd int) error {
		called = true
		for _, closed := range descriptors {
			if _, err := stat(closed); !errors.Is(err, unix.EBADF) {
				t.Errorf("view owner survived final sync: fd=%d err=%v", closed, err)
			}
		}
		if len(f.registry.objects) != 0 || len(s.nodes) != 0 || len(s.handles) != 0 {
			t.Error("view ownership survived final barrier")
		}
		return unix.Syncfs(fd)
	}
	_, err = f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch})
	must(t, err)
	if !called {
		t.Fatal("missing final sync")
	}
}

func TestReadOnlyPeerCannotEscapeStickyRWVolumeFault(t *testing.T) {
	f := newFixture(t)
	rw, rwRoot := f.session(a.ReadWrite)
	ro, roRoot := f.session(a.ReadOnly)
	// Retain a legitimate admission from before quarantine: queued RO setup must
	// not escape the later fault either. New admission is now fenced globally.
	g, err := f.authority.Admit(ro.principal, ro.binding.Volume, false)
	must(t, err)
	defer g.Release()
	fresh := ro.binding
	fresh.Attachment, fresh.Key = newID(t), fingerprint(t, key(t))
	register := a.RegisterRequest{Operation: newID(t), Binding: fresh}
	f.expectFaults = true
	f.registry.syncOps.syncfs = func(int) error { return unix.EIO }
	_, err = dispatchRaw(f, rw, caller(1001, 1001), w.MkdirRequest{Parent: rwRoot.Node, Name: []byte("partial"), Mode: 0700})
	if !errors.Is(err, ErrVolumeFault) {
		t.Fatal("RW failure not sticky", err)
	}
	f.registry.syncOps = platformSyncOperations()
	_, err = dispatchRaw(f, ro, metadata, w.GetAttrRequest{Node: roRoot.Node})
	if !errors.Is(err, ErrVolumeFault) {
		t.Fatal("RO peer escaped volume fence", err)
	}
	if err = f.authority.RegisterAttachment(f.control, register); !errors.Is(err, a.ErrBlocked) {
		t.Fatal("fresh RO registration escaped authority quarantine", err)
	}
	if _, err = f.authority.Admit(ro.principal, ro.binding.Volume, false); !errors.Is(err, a.ErrBlocked) {
		t.Fatal("fresh RO admission escaped authority quarantine", err)
	}
	_, _, err = New(g, ro.principal, ro.binding, f.gate, f.worker, f.registry)
	g.Release()
	if !errors.Is(err, ErrVolumeFault) {
		t.Fatal("RO setup cleared sticky fault", err)
	}
	receipt, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: ro.binding.Store, Volume: ro.binding.Volume, Attachment: ro.binding.Attachment, Launch: ro.binding.Launch})
	if !errors.Is(err, a.ErrBlocked) || receipt.Revision != 0 {
		t.Fatal("RO quarantine minted a receipt", receipt, err)
	}
	// Quarantine rejects Retire before its callback. Joined test-owned cleanup
	// releases pins but is not successful drain proof and must retain the fault.
	if err = f.registry.Barrier(ro.binding, f.volume); !errors.Is(err, ErrVolumeFault) || !ro.closed || len(ro.nodes) != 0 {
		t.Fatal("RO faulted cleanup cleared evidence or leaked pins", err)
	}
}
