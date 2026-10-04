package storageauthority

import (
	"errors"
	"testing"
)

func TestLifecycleMetadataDetachedAndFreshOnly(t *testing.T) {
	var zero Authority
	if _, err := zero.LifecycleMetadata(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	var absent *Authority
	if _, err := absent.LifecycleMetadata(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	f, initial := newLifecycleFixture(t)
	meta, err := f.a.LifecycleMetadata()
	must(t, err)
	if meta.Identity != initial.Grant.Identity || meta.CurrentGrant != initial.Grant || meta.Controller != f.a.s.Controller || meta.RetirementGrant != (LifecycleGrant{}) || meta.Sealed {
		t.Fatal("wrong initial metadata")
	}
	meta.Identity.Generation++
	meta.CurrentGrant.ID = mustID(t)
	again, err := f.a.LifecycleMetadata()
	must(t, err)
	if again.Identity != initial.Grant.Identity || again.CurrentGrant != initial.Grant {
		t.Fatal("metadata aliases authority")
	}
	retire := lifecycleRetirement(t, f)
	must(t, f.a.RetireLifecycle(f.control, retire))
	terminal, err := f.a.LifecycleMetadata()
	must(t, err)
	if !terminal.Sealed || terminal.CurrentGrant != initial.Grant || terminal.RetirementGrant != retire.Grant {
		t.Fatal("wrong terminal metadata")
	}
	if _, err = f.a.StartupMetadata(); !errors.Is(err, ErrBlocked) {
		t.Fatal("terminal ordinary metadata", err)
	}
	must(t, f.a.Close())
	if _, err = f.a.LifecycleMetadata(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed metadata", err)
	}
}
