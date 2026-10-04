package storageauthority

// ValidateFor checks that this particular live admission belongs to the exact
// authenticated session and service incarnation. A same-volume guard from another
// attachment is not interchangeable. Accepted work remains valid in RETIRING.
//
// The caller still owns the guard: do not Release concurrently with, or before,
// the work being authorized. This check neither admits nor prolongs a request.
func (g *Guard) ValidateFor(p *DataPrincipal) error {
	if g == nil || g.token == nil || g.token.owner == nil || p == nil || p.owner == nil {
		return ErrUnauthorized
	}
	t := g.token
	a := t.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.owner != a || p.epoch != t.epoch || p.binding != t.binding {
		return ErrUnauthorized
	}
	if t.released {
		return ErrClosed
	}
	if err := a.available(); err != nil {
		return err
	}
	if t.epoch != a.s.Epoch || t.binding.Store != a.s.Store.ID {
		return ErrUnauthorized
	}
	rec, ok := a.s.Attachments[t.binding.Attachment]
	rt := a.runtime[t.binding.Attachment]
	if !ok || rec.Binding != t.binding || rt == nil || rt.count <= 0 {
		return ErrUnauthorized
	}
	if rec.Phase != Active && rec.Phase != Retiring {
		return ErrBlocked
	}
	return nil
}
