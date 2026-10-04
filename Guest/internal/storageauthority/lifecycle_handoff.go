package storageauthority

// lifecycleHandoffFence retains only the latest abandoned grant high water and
// its immutable fence outcome. It survives subsequent takeovers/opens; ordinary
// controller serial checks alone cannot reject an unapplied abandoned grant.
type lifecycleHandoffFence struct {
	Request       LifecycleHandoffRequest `json:"request"`
	Applied       lifecycleApplied        `json:"applied"`
	FenceRevision uint64                  `json:"fence_revision"`
}

func (f lifecycleHandoffFence) result(nonce []byte) LifecycleHandoffResult {
	return LifecycleHandoffResult{f.Request, append([]byte(nil), nonce...), f.Applied.Grant,
		f.Applied.ServiceEpoch, f.Applied.Revision, f.FenceRevision}
}

func (a *Authority) validateHandoffFence() error {
	f := a.s.Lifecycle.HandoffFence
	if f == nil {
		return nil
	}
	l := a.s.Lifecycle
	if f.result(make([]byte, 32)).Validate() != nil || f.Request.Predecessor.Identity != l.Identity ||
		f.Request.Pending.NewKey == a.s.Bootstrap || f.FenceRevision > a.s.Revision {
		return ErrInvalid
	}
	if l.Latest.Grant == f.Applied.Grant {
		if l.Latest != f.Applied {
			return ErrInvalid
		}
	} else if l.Latest.Grant.Serial <= f.Request.Pending.Serial || l.Latest.Revision <= f.FenceRevision {
		return ErrInvalid
	}
	return nil
}

// FenceLifecycleHandoff is a private ROOT-signed, same-live-open operation. Under
// the SAME mutex as TakeoverLifecycle it durably fences the abandoned grant before
// reporting either original immutable applied receipt. Previously authenticated
// successor connections cannot apply that grant after this method returns.
//
// This does not trust HOST death assertions: ROOT must independently prove the
// displaced native owners dead before signing, and independently authenticate the
// live Guest result. No current-controller principal or new child is needed here.
// Busy DATA is transient; poison, uncertain journals and retirement stay fenced.
func (a *Authority) FenceLifecycleHandoff(signed SignedLifecycleHandoff, nonce []byte) (LifecycleHandoffResult, error) {
	if a == nil || len(nonce) != 32 {
		return LifecycleHandoffResult{}, ErrInvalid
	}
	signed.Signature = append([]byte(nil), signed.Signature...)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return LifecycleHandoffResult{}, err
	}
	if err := VerifyLifecycleHandoff(a.bootstrap, signed); err != nil {
		return LifecycleHandoffResult{}, err
	}
	r, l := signed.Request, a.s.Lifecycle
	if l == nil || r.Predecessor.Identity != l.Identity || r.ServiceEpoch != a.s.Epoch ||
		r.OpenRevision != l.OpenRevision || r.Pending.NewKey == a.s.Bootstrap ||
		(l.Latest.Grant != r.Predecessor && l.Latest.Grant != r.Pending) {
		return LifecycleHandoffResult{}, ErrConflict
	}
	if f := l.HandoffFence; f != nil {
		if f.Request == r && f.Applied == l.Latest {
			return f.result(nonce), nil
		}
		if r.Pending.Serial <= f.Request.Pending.Serial || r.OperationID == f.Request.OperationID {
			return LifecycleHandoffResult{}, ErrConflict
		}
	}
	if a.dataIO != nil || a.copyIO != nil {
		return LifecycleHandoffResult{}, ErrBusy
	}
	if err := a.j.lifecycleNamespaceClean(); err != nil {
		return LifecycleHandoffResult{}, err
	}
	if a.s.Revision == ^uint64(0) {
		return LifecycleHandoffResult{}, ErrLimit
	}
	f := lifecycleHandoffFence{r, l.Latest, a.s.Revision + 1}
	if err := f.result(nonce).Validate(); err != nil {
		return LifecycleHandoffResult{}, err
	}
	next := a.clone()
	next.Lifecycle.HandoffFence = &f
	if err := a.commit(next); err != nil {
		return LifecycleHandoffResult{}, err
	}
	return f.result(nonce), nil
}
