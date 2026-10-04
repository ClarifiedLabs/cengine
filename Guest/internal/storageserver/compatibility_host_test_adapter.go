//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageserver

import (
	"sync/atomic"

	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
)

// CompatibilityHostTestExecutor is ONLY a host-test filesystem stand-in, behind
// a separate non-release build tag. TLS authentication, real authority admission,
// guard ownership, durable receipt and transport joins are not replaced. The
// Service adapter separately substitutes host root.Sync for the Linux barrier.
// It does not claim Linux inode/handle/worker execution coverage.
type CompatibilityHostTestExecutor struct{ prepare, getattr atomic.Uint32 }

func (e *CompatibilityHostTestExecutor) GetAttrCalls() uint32 { return e.getattr.Load() }

func (e *CompatibilityHostTestExecutor) PrepareCalls() uint32 { return e.prepare.Load() }

func (s *Server) InstallCompatibilityHostTestExecutor() (*CompatibilityHostTestExecutor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections) != 0 {
		return nil, ErrConfiguration
	}
	e := &CompatibilityHostTestExecutor{}
	entry := w.Entry{Node: 1, Generation: 1, Object: w.ObjectID{1}, Attr: w.Attr{Ino: 1, Mode: 0040755, Nlink: 1, BlockSize: 4096}}
	s.factory = func(g *a.Guard, p *a.DataPrincipal, _ a.Binding) (executor, w.Entry, error) {
		if err := g.ValidateFor(p); err != nil {
			return nil, w.Entry{}, err
		}
		return compatibilityHostDispatch{principal: p, owner: e, entry: entry}, entry, nil
	}
	return e, nil
}

type compatibilityHostDispatch struct {
	principal *a.DataPrincipal
	owner     *CompatibilityHostTestExecutor
	entry     w.Entry
}

func (e compatibilityHostDispatch) Dispatch(g *a.Guard, req w.Request) (m.Result, error) {
	if err := g.ValidateFor(e.principal); err != nil {
		return m.Result{}, err
	}
	reply := w.Reply{Sequence: req.Sequence, Op: req.Body.Operation()}
	switch req.Body.(type) {
	case w.PrepareRequest:
		e.owner.prepare.Add(1)
		reply.Errno = 16 // host stand-in refuses actual copy filesystem work
	case w.GetAttrRequest:
		e.owner.getattr.Add(1)
		reply.Body = w.GetAttrReply{Attr: e.entry.Attr}
	default:
		return m.Result{}, ErrConfiguration
	}
	return m.Result{Reply: reply}, nil
}
