package storageauthority

import (
	"path/filepath"
	"testing"
)

func TestLifecycleOpenExpectedAnchorGuard(t *testing.T) {
	f, current := newLifecycleFixture(t)
	old := expectedLifecycleStartup(f)
	must(t, f.a.Close())
	var err error
	f.a, err = OpenLifecycleExpected(f.c, current, old)
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	f.volume("anchor-not-query-revision")
	expected := expectedLifecycleStartup(f)
	revision := f.a.s.Revision
	if expected.OpenRevision <= old.OpenRevision || expected.OpenRevision >= revision {
		t.Fatal("fixture must distinguish stale, live-open and mutable revisions")
	}
	path := filepath.Join(f.path, registryName)
	before := journalContents(t, path)
	wrong := expected
	wrong.OpenRevision = old.OpenRevision
	// The durable comparison cannot precede acquiring the journal flock. While
	// its current owner is live, even this otherwise valid signed candidate locks.
	_, err = OpenLifecycleExpected(f.c, current, wrong)
	wantErr(t, err, ErrLocked)
	assertJournalContents(t, path, before)
	must(t, f.a.Close())

	for name, anchor := range map[string]uint64{
		"zero":           0,
		"stale":          old.OpenRevision,
		"future":         expected.OpenRevision + 1,
		"query-revision": revision,
		"maximum":        ^uint64(0),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := expected
			candidate.OpenRevision = anchor
			got, err := OpenLifecycleExpected(f.c, current, candidate)
			if anchor == 0 {
				wantErr(t, err, ErrInvalid)
			} else {
				wantErr(t, err, ErrConflict)
			}
			if got != nil {
				got.Close()
				t.Fatal("mismatched anchor returned authority")
			}
			assertJournalContents(t, path, before)
		})
	}
	_, err = OpenLifecycleExpected(f.c, current, ExpectedLifecycleStartup{ExpectedStartup: expected.ExpectedStartup})
	wantErr(t, err, ErrInvalid)
	assertJournalContents(t, path, before)

	// All rejected candidates carried the real signed current grant. None may
	// consume E or the open anchor; the exact predecessor must still open once.
	f.a, err = OpenLifecycleExpected(f.c, current, expected)
	must(t, err)
	if f.a.Epoch() == expected.Epoch || f.a.s.Revision != revision+1 ||
		f.a.s.Lifecycle.OpenRevision != revision+1 || f.a.s.Controller != expected.Controller ||
		f.a.s.Lifecycle.Latest.Grant != current.Grant {
		t.Fatal("failed candidate consumed predecessor or correct open changed ownership")
	}
	must(t, f.a.Close())
	before = journalContents(t, path)
	_, err = OpenLifecycleExpected(f.c, current, expected)
	wantErr(t, err, ErrConflict)
	assertJournalContents(t, path, before)
}
