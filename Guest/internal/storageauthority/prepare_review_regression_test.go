package storageauthority

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareReplacementCapacityRefusalAndStaleController(t *testing.T) {
	for _, budget := range []string{"bytes", "revision"} {
		t.Run(budget, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("replacement-refusal")
			r := plannedPrepare(t, f, v)
			must(t, f.a.ReservePrepare(f.control, r))
			complete := drainedPrepare(t, f, r)
			replace := ReplaceRequest{mustID(t), r.Prepare, complete.Receipts, plannedPrepare(t, f, v)}
			limits := DefaultLimits()
			if budget == "bytes" {
				projected := f.a.clone()
				projected.Revision++
				limits.JournalBytes = exactCapacity(t, projected).JournalBytes
			} else {
				// Open and predecessor completion fit; the fresh successor's
				// retirement and completion revisions do not. Two revisions remain
				// reserved for the lifecycle terminal intent and result.
				f.a.s.Revision = ^uint64(0) - 4
				must(t, f.a.j.persist(f.a.s))
			}
			stale := f.control
			reopenWithCapacity(t, f, limits)
			before, err := json.Marshal(f.a.s)
			must(t, err)
			path := filepath.Join(f.path, registryName, stateName)
			durable, err := os.ReadFile(path)
			must(t, err)
			steps := 0
			f.a.j.fault = func(string) error { steps++; return nil }
			wantErr(t, f.a.CompletePrepare(stale, complete), ErrUnauthorized)
			wantErr(t, f.a.ReplacePrepare(stale, replace), ErrUnauthorized)
			wantErr(t, f.a.ReplacePrepare(f.control, replace), ErrLimit)
			after, err := json.Marshal(f.a.s)
			must(t, err)
			afterDurable, err := os.ReadFile(path)
			must(t, err)
			if string(before) != string(after) || string(durable) != string(afterDurable) || steps != 0 || f.a.fault != nil {
				t.Fatal("refused replacement or stale controller changed pending authority")
			}
			must(t, f.a.CompletePrepare(f.control, complete))
			revision := f.a.s.Revision
			must(t, f.a.CompletePrepare(f.control, complete))
			wantErr(t, f.a.CompletePrepare(stale, complete), ErrUnauthorized)
			if f.a.s.Revision != revision || f.a.s.Prepares[r.Prepare].Phase != Completed {
				t.Fatal("exact completion did not consume only its reserved transition")
			}
			must(t, f.a.validate())
		})
	}
}
