package storageserver

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// Private observations of real admission and a nonnil fence, not bypasses for
// authentication or dispatch. Tests install these before starting any Serve.
type copyFenceHooks struct {
	admitted func(a.Binding, *a.Guard, w.Request)
	waiting  func(*a.Guard)
}

func (p *peer) receivePool() chan struct{} {
	if p.prepareReceive != nil {
		return p.prepareReceive
	}
	return p.server.receive
}

// Always returns with dispatch held, including failure, so the caller preserves
// the existing terminal-publication/guard-release order. A wakeup is not access.
func (s *Server) lockCopyDispatch(g *a.Guard) error {
	for {
		s.dispatch.Lock()
		wait, err := g.CopyFence()
		if err != nil || wait == nil {
			return err
		}
		s.dispatch.Unlock()
		if hooks := s.copyHooks; hooks != nil && hooks.waiting != nil {
			hooks.waiting(g)
		}
		<-wait
	}
}
