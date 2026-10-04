package storageauthority

import (
	"errors"
	"testing"
)

func TestStartupMetadataDetachedAndClosed(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	meta, err := f.a.StartupMetadata()
	must(t, err)
	if meta.Store != f.a.s.Store || meta.Epoch != f.a.Epoch() || meta.Controller != f.a.s.Controller || meta.Revision != f.a.s.Revision || meta.Bootstrap != f.a.s.Bootstrap {
		t.Fatal("wrong startup metadata")
	}
	meta.Controller.Epoch++
	meta.Store.ID = mustID(t)
	next, err := f.a.StartupMetadata()
	must(t, err)
	if next == meta {
		t.Fatal("metadata changed authority")
	}
	must(t, f.a.Close())
	if _, err = f.a.StartupMetadata(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
