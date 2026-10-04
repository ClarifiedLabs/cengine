package storagemanaged

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// Write-ahead fencing is separate from the wire RO policy: a legal RO flush or
// resource close can still report deferred IO errors. Reads never allocate an
// obligation. Final retirement is already covered by authority's barrier marker.
func needsDurability(r w.Request) bool {
	if p, ok := r.Body.(w.PrepareRequest); ok {
		return p.Action != w.IdentityAt && p.Action != w.AuthenticateManifest
	}
	if r.Mutates() {
		return true
	}
	switch r.Body.(type) {
	case w.FlushRequest, w.FsyncRequest, w.FsyncDirRequest, w.ReleaseRequest, w.ReleaseDirRequest:
		return true
	}
	return false
}

// Authority deliberately has no dependency on wire action numbering.
type requestObligation interface{ Complete(error) error }

func (s *Session) beginRequestObligation(g *a.Guard, r w.Request) (requestObligation, error) {
	if p, ok := r.Body.(w.PrepareRequest); ok {
		action := map[w.PrepareAction]string{w.BeginCopy: a.CopyOperationBegin, w.BindCopyTransaction: a.CopyOperationProvision, w.SealManifest: a.CopyOperationSeal, w.StartCleanup: a.CopyOperationCleanup, w.FinishCopy: a.CopyOperationFinish, w.RollbackCopy: a.CopyOperationRollback, w.ResumeCopyDirectory: a.CopyOperationDirectoryTail}[p.Action]
		return g.BeginCopyOperation(r.Sequence, action, p.Intent)
	}
	action, intent, err := s.copyDataRecovery(g, r)
	if err != nil {
		return nil, err
	}
	if action != "" {
		return g.BeginCopyDataOperation(r.Sequence, action, intent.ID)
	}
	return g.BeginDurability(r.Sequence)
}

// Only bare admission errors are nonpoisoning. A wrapped ErrBlocked from
// authority.poison, including IO/unknown markers, must remain terminal.
func rejectedObligation(err error) bool {
	switch err {
	case a.ErrUnauthorized, a.ErrInvalid, a.ErrConflict, a.ErrBlocked, a.ErrBusy, a.ErrLimit, a.ErrClosed:
		return true
	}
	return false
}

// A successor needs fresh root attributes for FUSE default_permissions before
// opening its root directory handle. Both operations use already-pinned root
// descriptors without enumeration or atime changes. No path traversal, handle
// substitution, or readdir on the resulting handle is exempt.
func replayRootBootstrap(r w.Request) bool {
	switch p := r.Body.(type) {
	case w.GetAttrRequest:
		return p.Node == 1 && p.Handle == nil
	case w.OpenDirRequest:
		// Linux O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_LARGEFILE|O_NONBLOCK only;
		// access mode remains O_RDONLY; creation/truncation are excluded.
		const harmless = uint32(0x10000 | 0x20000 | 0x80000 | 0x8000 | 0x800)
		return p.Node == 1 && p.Flags & ^harmless == 0
	}
	return false
}
