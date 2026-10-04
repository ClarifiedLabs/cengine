package storageauthority

import "os"

// DupVolumeRoot returns a caller-owned, close-on-exec duplicate of the authority's
// retained exact volume-root descriptor. No volume name or path is reopened. It
// requires this particular Guard to be live in its original service incarnation;
// another live request for the same attachment cannot revive a released Guard.
//
// Duplication serializes with Release and Authority.Close. A successful duplicate
// stays valid independently of the original FD: Release does not close it. The
// caller must finish its users and close it BEFORE Release, or transfer it (and
// any derived nodes/handles) to an attachment-owned registry covered by Barrier
// BEFORE Release. Concurrent callers must coordinate that ownership/transfer;
// this method does not make early Release or post-drain FD use safe.
//
// This is resource acquisition for an already-admitted request, not new admission.
// It remains allowed during RETIRING so accepted work can finish. It fails for a
// nil/zero Guard (ErrUnauthorized), a released Guard or closed owner (ErrClosed),
// stale/mismatched authority (ErrUnauthorized), or blocked service/attachment.
// Descriptor errors are returned without granting a root or consuming the Guard.
func (g *Guard) DupVolumeRoot() (*os.File, error) {
	if g == nil || g.token == nil || g.token.owner == nil {
		return nil, ErrUnauthorized
	}
	t := g.token
	a := t.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if t.released {
		return nil, ErrClosed
	}
	if err := a.available(); err != nil {
		return nil, err
	}
	if t.epoch != a.s.Epoch || t.binding.Store != a.s.Store.ID {
		return nil, ErrUnauthorized
	}
	rec, ok := a.s.Attachments[t.binding.Attachment]
	rt := a.runtime[t.binding.Attachment]
	if !ok || rec.Binding != t.binding || rt == nil || rt.count <= 0 {
		return nil, ErrUnauthorized
	}
	if rec.Phase != Active && rec.Phase != Retiring {
		return nil, ErrBlocked
	}
	volume, ok := a.s.Volumes[t.binding.Volume]
	root := a.roots[t.binding.Volume]
	if !ok || root == nil {
		return nil, ErrUnknown
	}
	duplicate, err := dupDirectory(root)
	if err != nil {
		return nil, err
	}
	got, err := identity(duplicate)
	if err != nil {
		duplicate.Close()
		return nil, err
	}
	if got != volume.Root {
		duplicate.Close()
		return nil, ErrConflict
	}
	return duplicate, nil
}
