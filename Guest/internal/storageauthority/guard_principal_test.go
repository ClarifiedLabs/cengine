package storageauthority

import (
	"context"
	"testing"
)

func TestGuardValidatesExactSessionAndIncarnation(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("shared")
	b, p := f.runtime(v, ReadWrite)
	_, other := f.runtime(v, ReadWrite)
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	defer g.Release()
	must(t, g.ValidateFor(p))
	wantErr(t, g.ValidateFor(other), ErrUnauthorized)
	wantErr(t, g.ValidateFor(nil), ErrUnauthorized)
	wantErr(t, (*Guard)(nil).ValidateFor(p), ErrUnauthorized)
	wantErr(t, (&Guard{}).ValidateFor(p), ErrUnauthorized)
	stale := *p
	stale.epoch = mustID(t)
	wantErr(t, g.ValidateFor(&stale), ErrUnauthorized)
	separate := newLifecycleWorkloadFixture(t, nil)
	stale = *p
	stale.owner = separate.a
	wantErr(t, g.ValidateFor(&stale), ErrUnauthorized)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	retirement := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	_, err = f.a.Retire(ctx, f.control, retirement)
	wantErr(t, err, context.Canceled)
	must(t, g.ValidateFor(p)) // Fence does not cancel accepted work.
	copyGuard := *g
	g.Release()
	wantErr(t, copyGuard.ValidateFor(p), ErrClosed)
	// The canceled waiter did not cancel retirement. Join its barrier before
	// fixture cleanup closes the service, including on a slower ext4 filesystem.
	_, err = f.a.Retire(context.Background(), f.control, retirement)
	must(t, err)
}
