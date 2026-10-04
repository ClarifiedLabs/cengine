package storageservice

import (
	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	"errors"
	"os"
)

func (s *fixtureService) ProbeIsolation(kind string, root *os.File) (*IsolationProof, error) {
	if preparecompat.CurrentProfile() != preparecompat.FullProfile || (kind != "legacy-connection" && kind != "second-service-exclusivity" && kind != "isolation-state") {
		return nil, a.ErrUnauthorized
	}
	before, err := s.Ready()
	if err != nil {
		return nil, err
	}
	digest, err := s.authority.CompatibilityStateDigest()
	if err != nil {
		return nil, err
	}
	result := ""
	if kind == "second-service-exclusivity" {
		if root == nil {
			return nil, a.ErrInvalid
		}
		cfg := s.config
		cfg.Root = root
		// Real constructor opens a distinct journal lock description. Never duplicate
		// the first lock FD, initialize over its registry, or weaken the live owner.
		second, e := s.reopen(cfg, a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: before.Store.ID, Epoch: before.ServiceEpoch, Controller: before.Controller}, OpenRevision: s.openRevision})
		if second != nil {
			closeErr := second.Close()
			return nil, errors.Join(a.ErrConflict, closeErr)
		}
		if !errors.Is(e, a.ErrLocked) {
			return nil, errors.Join(a.ErrConflict, e)
		}
		result = "second-owner-locked"
	} else if kind == "isolation-state" {
		result = "registry-state"
	} else {
		if err = s.rejectLegacyConnection(); err != nil {
			return nil, err
		}
		result = "legacy-tls-header-rejected"
	}
	after, err := s.Ready()
	if err != nil {
		return nil, err
	}
	final, err := s.authority.CompatibilityStateDigest()
	if err != nil {
		return nil, err
	}
	if digest != final || before.Store != after.Store || before.ServiceEpoch != after.ServiceEpoch || before.Revision != after.Revision || before.Controller != after.Controller {
		return nil, a.ErrConflict
	}
	return &IsolationProof{CaseName: kind, Store: string(before.Store.ID), ServiceEpoch: string(before.ServiceEpoch), Revision: before.Revision, RegistrySHA256: digest, Result: result}, nil
}
