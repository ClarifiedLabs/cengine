package storageservice

import a "dev.cengine/guest/internal/storageauthority"

// FenceLifecycleHandoff is private ROOT-signed recovery, not an ordinary query.
// Fence the abandoned takeover under the authority lock before repairing cached
// endpoints. A busy CONTROL drain may require an exact retry after the durable
// fence; neither that retry nor endpoint repair replaces DATA or resource owners.
func (s *LifecycleService) FenceLifecycleHandoff(signed a.SignedLifecycleHandoff, nonce []byte) (a.LifecycleHandoffResult, error) {
	if !s.valid() {
		return a.LifecycleHandoffResult{}, ErrConfiguration
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return a.LifecycleHandoffResult{}, a.ErrClosed
	}
	if s.retirement != (a.LifecycleGrant{}) || (s.pending != (a.LifecycleGrant{}) && s.pending != signed.Request.Pending) {
		return a.LifecycleHandoffResult{}, a.ErrConflict
	}
	result, err := o.authority.FenceLifecycleHandoff(signed, nonce)
	if err != nil {
		return a.LifecycleHandoffResult{}, err
	}
	meta, err := o.authority.LifecycleMetadata()
	if err != nil {
		return a.LifecycleHandoffResult{}, err
	}
	if meta.CurrentGrant != result.AppliedGrant || meta.Epoch != result.Request.ServiceEpoch || meta.OpenRevision != result.Request.OpenRevision || meta.RetirementGrant != (a.LifecycleGrant{}) {
		return a.LifecycleHandoffResult{}, a.ErrConflict
	}
	if o.controlActive != 0 {
		return a.LifecycleHandoffResult{}, a.ErrBusy
	}
	control, err := s.newWorkloadControl(meta)
	if err != nil {
		return a.LifecycleHandoffResult{}, err
	}
	endpoint, err := s.newEndpoint(meta, a.LifecycleGrant{}, a.LifecycleGrant{})
	if err != nil {
		return a.LifecycleHandoffResult{}, err
	}
	o.control, o.generation = control, meta.Controller
	s.endpoint, s.pending = endpoint, a.LifecycleGrant{}
	return result, nil
}
