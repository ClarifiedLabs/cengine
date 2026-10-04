package storageauthority

import "testing"

func TestCopyInspectAuthenticatesIdentityQueriesWithoutMutation(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("inspect")
	_, g := copyPrepare(t, f, v, ReadWrite)
	root := copyRoot(f, v)
	before := f.a.s.Revision
	_, err := g.InspectCopy(mustID(t), root)
	wantErr(t, err, ErrUnauthorized)
	if f.a.s.Revision != before {
		t.Fatal("inspect created authority")
	}
	intent, err := g.BeginCopy(root)
	must(t, err)
	before = f.a.s.Revision
	got, err := g.InspectCopy(intent.ID, root)
	must(t, err)
	if got != intent || f.a.s.Revision != before {
		t.Fatal("inspect changed intent")
	}
	wrong := root
	wrong.BackingUUID[0]++
	_, err = g.InspectCopy(intent.ID, wrong)
	wantErr(t, err, ErrConflict)
	wrong = root
	wrong.Root.Generation++
	_, err = g.InspectCopy(intent.ID, wrong)
	wantErr(t, err, ErrConflict)
	_, err = g.InspectCopy(mustID(t), root)
	wantErr(t, err, ErrUnauthorized)
	must(t, g.FinishCopy(intent.ID))
	_, err = g.InspectCopy(intent.ID, root)
	wantErr(t, err, ErrUnauthorized)
}
