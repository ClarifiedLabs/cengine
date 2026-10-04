package storagefuse

import (
	"os"
	"sync"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// prepareProcess is a kernel-local process lifetime, never caller authority.
// matches accepts live threads of the pinned TGID, not recycled numeric IDs.
// The only production implementation is descriptor-rooted Linux procfs + pidfd.
type prepareProcess interface {
	matches(uint32) bool
	close()
}

type prepareProcessGate struct {
	mu       sync.Mutex     // includes transport admission and teardown
	owner    prepareProcess // installed at trusted mount creation, never by a request
	readOnly bool
	begun    bool
	closed   bool
	// Guarded by mu; construction is unpublished. Never used to admit requests.
	lastOwned   bool
	lastFailure processMatchFailure
}

// newMountPrepareProcess seals the expected initializer before mounting/serving.
// nativeFactory.Mount and supervisorWorkload.Prepare execute in the same PID1
// process; only StartManaged later execs the workload. No PID from Config, the
// workload, or a FUSE header may select this owner. The private pin seam is for
// host tests; native construction always supplies pinPrepareProcess.
func newMountPrepareProcess(role a.Role, readOnly bool, pin func(uint32) (prepareProcess, error)) (*prepareProcessGate, error) {
	if role == a.RuntimeRole {
		return nil, nil
	}
	if role != a.PrepareRole || pin == nil {
		return nil, ErrProfile
	}
	expected := uint32(os.Getpid())
	owner, err := pin(expected)
	if err != nil || owner == nil {
		if owner != nil {
			owner.close()
		}
		return nil, ErrProfile // no unpinned, numeric-PID-only, or runtime fallback
	}
	if !owner.matches(expected) {
		owner.close()
		return nil, ErrProfile
	}
	return &prepareProcessGate{owner: owner, readOnly: readOnly}, nil
}

func (g *prepareProcessGate) owns(tid uint32) bool {
	g.lastOwned = false
	g.lastFailure = processMatchFailure{}
	switch {
	case g.closed:
		g.lastFailure.stage = matchClosed
	case tid == 0:
		g.lastFailure.stage = matchZeroTID
	case g.owner == nil:
		g.lastFailure.stage = matchNoOwner
	default:
		g.lastOwned = g.owner.matches(tid)
		if !g.lastOwned {
			g.lastFailure.stage = matchUnavailable
			if diagnostic, ok := g.owner.(interface{ lastMatchFailure() processMatchFailure }); ok {
				g.lastFailure = diagnostic.lastMatchFailure()
			}
		}
	}
	return g.lastOwned
}

func (g *prepareProcessGate) check(tid uint32, state uint8) bool {
	return state == present && g.owns(tid)
}

// Linux 6.18 fuse_flush sets args.force: ABI3 captures NONE, but
// fuse_force_creds still supplies the closing TID in the mount's PID namespace.
// This is only a local process restriction. NONE remains OpenGrantAuth, and the
// client/server must still validate the exact live file handle and drain guard.
func (g *prepareProcessGate) forcedFlush(tid uint32, state uint8, auth w.AuthKind, opcode uint32) bool {
	const fuseFlush = 25
	return state == none && auth == w.OpenGrantAuth && opcode == fuseFlush &&
		!g.readOnly && g.begun && g.owns(tid)
}

// Called with mu held, after exact-Unique capture and request construction.
func (g *prepareProcessGate) admit(tid uint32, node uint64, body w.RequestBody) fuse.Status {
	if !g.check(tid, present) {
		return fuse.EACCES
	}
	if b, ok := body.(w.PrepareRequest); ok {
		// All PREPARE actions, including identity queries and StartCleanup,
		// require the authenticated RW prepare attachment.
		if g.readOnly {
			return fuse.EROFS
		}
		if g.begun {
			return fuse.OK
		}
		if b.Action != w.BeginCopy {
			return fuse.EACCES
		}
		g.begun = true // failed/rejected Begin never replaces the expected owner
		return fuse.OK
	}
	if g.begun {
		return fuse.OK
	}
	// Only the already-pinned initializer may obtain root bootstrap grants.
	if node == 1 {
		switch body.(type) {
		case w.GetAttrRequest, w.OpenDirRequest, w.StatFSRequest, w.AccessRequest:
			if !(w.Request{Body: body}).Mutates() {
				return fuse.OK
			}
		}
	}
	return fuse.EACCES
}

func (g *prepareProcessGate) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	g.closed = true
	if g.owner != nil {
		g.owner.close()
		// Retain the non-adoptable state even after resource closure.
	}
}
