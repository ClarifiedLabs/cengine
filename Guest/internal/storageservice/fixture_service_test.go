package storageservice

// fixtureService retains private resource access for shared DATA/PREPARE tests,
// but construction, control, credentials and reopen use real lifecycle APIs.
import (
	"context"
	"net"

	a "dev.cengine/guest/internal/storageauthority"
)

type fixtureService struct {
	*commonService
	lifecycle    *LifecycleService
	current      a.SignedLifecycleGrant
	openRevision uint64
}

func fixtureOwner(s *LifecycleService, current a.SignedLifecycleGrant) (*fixtureService, error) {
	meta, err := s.Scope()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return &fixtureService{commonService: s.owner, lifecycle: s, current: current, openRevision: meta.OpenRevision}, nil
}
func (s *fixtureService) Close() error { return s.lifecycle.Close() }
func (s *fixtureService) ServeAttachmentCSR(ctx context.Context, raw net.Conn) error {
	return s.lifecycle.ServeAttachmentCSR(ctx, raw)
}
func (f *fixture) open(cfg Config, expected a.Controller) (*fixtureService, error) {
	if expected != lifecycleController(f.s.current.Grant) {
		return nil, a.ErrConflict
	}
	owner, err := OpenLifecycle(cfg, f.s.current.Grant.Identity, f.s.current)
	if err != nil {
		return nil, err
	}
	return fixtureOwner(owner, f.s.current)
}
func (f *fixture) reopen(cfg Config, expected a.ExpectedLifecycleStartup) (*fixtureService, error) {
	return f.s.reopen(cfg, expected)
}
func (s *fixtureService) reopen(cfg Config, expected a.ExpectedLifecycleStartup) (*fixtureService, error) {
	owner, err := ReopenLifecycle(cfg, s.current.Grant.Identity, s.current, expected)
	if err != nil {
		return nil, err
	}
	return fixtureOwner(owner, s.current)
}
