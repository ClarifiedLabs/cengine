package storageauthority

import (
	"encoding/json"
	"testing"
)

func TestPrepareReserveRejectsUnfundedCompletionBeforeIO(t *testing.T) {
	for _, budget := range []string{"operation", "bytes", "revision"} {
		t.Run(budget, func(t *testing.T) {
			f := newFixture(t, nil)
			r := plannedPrepare(t, f, f.volume("reserve"))
			projected := f.a.clone()
			must(t, f.a.plan(projected, r, ""))
			projected.Operations[r.Operation] = digest("reserve", r)
			projected.Revision += 2 // Open and reserve.
			limits := exactCapacity(t, projected)
			switch budget {
			case "operation":
				limits.Operations--
			case "bytes":
				limits.JournalBytes--
			case "revision":
				f.a.s.Revision = ^uint64(0) - 4 // One short of Open/reserve/retire/complete.
				must(t, f.a.j.persist(f.a.s))
			}
			reopenWithCapacity(t, f, limits)
			before := f.a.s.Revision
			steps := 0
			f.a.j.fault = func(string) error { steps++; return nil }
			wantErr(t, f.a.ReservePrepare(f.control, r), ErrLimit)
			if steps != 0 || f.a.s.Revision != before || len(f.a.s.Prepares) != 0 || len(f.a.s.Attachments) != 0 || f.a.fault != nil {
				t.Fatal("unfunded reservation changed authority or performed journal IO")
			}
		})
	}
}

func TestPrepareReplacementReservesSuccessorCompletion(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("successor")
	r := plannedPrepare(t, f, v)
	must(t, f.a.ReservePrepare(f.control, r))
	c := drainedPrepare(t, f, r)
	replace := ReplaceRequest{mustID(t), r.Prepare, c.Receipts, plannedPrepare(t, f, v)}
	projected := f.a.clone()
	must(t, f.a.plan(projected, replace.Successor, r.Prepare))
	prep := projected.Prepares[r.Prepare]
	prep.Phase, prep.Successor = Replaced, replace.Successor.Prepare
	projected.Prepares[r.Prepare] = prep
	projected.Operations[replace.Operation] = digest("replace", replace)
	projected.Operations[replace.Successor.Operation] = digest("reserve", replace.Successor)
	projected.Revision += 2
	limits := exactCapacity(t, projected)
	reopenWithCapacity(t, f, limits)
	must(t, f.a.ReplacePrepare(f.control, replace))
	must(t, f.a.ReplacePrepare(f.control, replace))
	changed := replace
	changed.Successor.Operation = mustID(t)
	wantErr(t, f.a.ReplacePrepare(f.control, changed), ErrConflict)
	wantErr(t, f.a.AddVolume(f.control, VolumeRequest{mustID(t), v}), ErrLimit)
	finish := drainedPrepare(t, f, replace.Successor)
	must(t, f.a.CompletePrepare(f.control, finish))
	if len(f.a.s.Operations) != limits.Operations {
		t.Fatal("successor did not use final reserved slot")
	}
	must(t, f.a.validate())
}

func TestPrepareAndVolumeLifecycleReservationsCoexist(t *testing.T) {
	for _, kind := range []string{"create", "delete"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			r := plannedPrepare(t, f, f.volume("prepared"))
			must(t, f.a.ReservePrepare(f.control, r))
			create := createRequest(t, f, "new")
			var del DeleteVolumeRequest
			if kind == "delete" {
				del = DeleteVolumeRequest{mustID(t), f.a.s.Store.ID, f.volume("deleted").ID}
			}
			projected := f.a.clone()
			projected.Revision += 2 // Open then lifecycle intent.
			if kind == "create" {
				projected.Volumes[create.Volume] = Volume{ID: create.Volume, Name: create.Name}
				projected.VolumeLifecycles[create.Volume] = VolumeLifecycle{Phase: VolumeCreating, Create: create.Operation}
				projected.Operations[create.Operation] = digest("create-volume", create)
			} else {
				life := projected.VolumeLifecycles[del.Volume]
				life.Phase, life.Delete = VolumeDeleting, del.Operation
				projected.VolumeLifecycles[del.Volume] = life
				projected.Operations[del.Operation] = digest("delete-volume", del)
			}
			reopenWithCapacity(t, f, exactCapacity(t, projected))
			if kind == "create" {
				_, err := f.a.CreateVolume(f.control, create)
				must(t, err)
			} else {
				_, err := f.a.DeleteVolume(f.control, del)
				must(t, err)
			}
			c := drainedPrepare(t, f, r)
			must(t, f.a.CompletePrepare(f.control, c))
			must(t, f.a.validate())
		})
	}
}

func TestPrepareCompletionProjectionAtRevisionBoundaries(t *testing.T) {
	f := newFixture(t, nil)
	r := plannedPrepare(t, f, f.volume("digits"))
	must(t, f.a.ReservePrepare(f.control, r))
	c := drainedPrepare(t, f, r)
	for _, revision := range []uint64{8, 9, 98, 99, 998, 999, ^uint64(0) - 3} {
		s := f.a.clone()
		s.Revision = revision
		probe := &Authority{limits: exactCapacity(t, s)}
		prep := s.Prepares[r.Prepare]
		prep.Phase, prep.Attestation = Completed, &c.Attestation
		s.Prepares[r.Prepare] = prep
		s.Operations[c.Operation] = digest("complete", c)
		s.Revision++
		data, err := json.Marshal(s)
		must(t, err)
		must(t, probe.capacity(s, int64(len(data))))
	}
}
