package storageauthority

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func plannedPrepare(t *testing.T, f *fixture, volumes ...Volume) ReserveRequest {
	t.Helper()
	r := ReserveRequest{Operation: mustID(t), Prepare: mustID(t)}
	for _, v := range volumes {
		b, _ := f.binding(v, PrepareRole, ReadWrite, r.Prepare)
		r.Attachments = append(r.Attachments, b)
	}
	return canonicalReserve(r)
}

func drainedPrepare(t *testing.T, f *fixture, r ReserveRequest) CompleteRequest {
	t.Helper()
	c := CompleteRequest{Operation: mustID(t), Prepare: r.Prepare, Attestation: Attestation{r.Prepare, true, true}}
	for _, b := range r.Attachments {
		c.Receipts = append(c.Receipts, f.retire(b))
	}
	return c
}

func reopenWithCapacity(t *testing.T, f *fixture, limits Limits) {
	t.Helper()
	must(t, f.a.Close())
	f.c.Limits = limits
	a, err := f.openCurrent()
	must(t, err)
	f.a = a
	f.control = f.authControl(f.controllerKey, 1)
}

func TestPrepareAdmittedWithReservedCompletionCapacity(t *testing.T) {
	for _, budget := range []string{"operations", "bytes", "both"} {
		t.Run(budget, func(t *testing.T) {
			f := newFixture(t, nil)
			first := plannedPrepare(t, f, f.volume("one"), f.volume("two"))
			second := plannedPrepare(t, f, f.volume("three"))
			spare := f.volume("spare")
			projected := f.a.clone()
			for _, r := range []ReserveRequest{first, second} {
				must(t, f.a.plan(projected, r, ""))
				projected.Operations[r.Operation] = digest("reserve", r)
			}
			projected.Revision += 3 // Open and the two reservations.
			limits := exactCapacity(t, projected)
			if budget == "operations" {
				limits.JournalBytes = DefaultLimits().JournalBytes
			}
			if budget == "bytes" {
				limits.Operations = DefaultLimits().Operations
			}
			reopenWithCapacity(t, f, limits)
			for _, r := range []ReserveRequest{first, second} {
				must(t, f.a.ReservePrepare(f.control, r))
				must(t, f.a.ReservePrepare(f.control, r))
				changed := r
				changed.Prepare = mustID(t)
				wantErr(t, f.a.ReservePrepare(f.control, changed), ErrConflict)
			}
			before := f.a.s.Revision
			wantErr(t, f.a.AddVolume(f.control, VolumeRequest{mustID(t), spare}), ErrLimit)
			_, err := f.a.CreateVolume(f.control, createRequest(t, f, "extra"))
			wantErr(t, err, ErrLimit)
			_, err = f.a.DeleteVolume(f.control, DeleteVolumeRequest{mustID(t), f.a.s.Store.ID, spare.ID})
			wantErr(t, err, ErrLimit)
			if f.a.s.Revision != before || f.a.fault != nil {
				t.Fatal("unrelated rejected growth changed state")
			}
			for _, r := range []ReserveRequest{second, first} {
				c := drainedPrepare(t, f, r)
				bad := c
				bad.Receipts = append([]Receipt(nil), c.Receipts...)
				bad.Receipts[0].Revision++
				wantErr(t, f.a.CompletePrepare(f.control, bad), ErrBlocked)
				bad = c
				bad.Attestation.CleanCopyUp = false
				wantErr(t, f.a.CompletePrepare(f.control, bad), ErrInvalid)
				if f.a.s.Prepares[r.Prepare].Phase != Pending {
					t.Fatal("invalid completion released reservation")
				}
				must(t, f.a.CompletePrepare(f.control, c))
				revision := f.a.s.Revision
				must(t, f.a.CompletePrepare(f.control, c))
				wantErr(t, f.a.CompletePrepare(f.control, bad), ErrConflict)
				if f.a.s.Revision != revision {
					t.Fatal("replay consumed reserved capacity")
				}
			}
			if budget != "bytes" && len(f.a.s.Operations) != limits.Operations {
				t.Fatal("operation budget was not exhausted exactly")
			}
			must(t, f.a.validate())
		})
	}
}

func TestPrepareRevisionReservationThroughLastRevision(t *testing.T) {
	f := newFixture(t, nil)
	r := plannedPrepare(t, f, f.volume("last"))
	// Establish a durable near-exhausted revision before Open; configured limits
	// remain immutable throughout the actual reserve/drain/complete calls.
	f.a.s.Revision = ^uint64(0) - 7 // Open, reserve, intent, receipt, complete; two lifecycle revisions.
	must(t, f.a.j.persist(f.a.s))
	reopenWithCapacity(t, f, DefaultLimits())
	must(t, f.a.ReservePrepare(f.control, r))
	wantErr(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), r.Prepare, r.Attachments}), ErrLimit)
	c := drainedPrepare(t, f, r)
	must(t, f.a.CompletePrepare(f.control, c))
	must(t, f.a.CompletePrepare(f.control, c))
	if f.a.s.Revision != ^uint64(0)-2 {
		t.Fatal("did not reach final reserved revision")
	}
}

func TestPrepareReplacementMustFundSuccessorWithoutSpendingPendingReservation(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("replace")
	r := plannedPrepare(t, f, v)
	must(t, f.a.ReservePrepare(f.control, r))
	c := drainedPrepare(t, f, r)
	projected := f.a.clone()
	projected.Revision++
	reopenWithCapacity(t, f, exactCapacity(t, projected))
	replace := ReplaceRequest{mustID(t), r.Prepare, c.Receipts, plannedPrepare(t, f, v)}
	before := f.a.clone()
	wantErr(t, f.a.ReplacePrepare(f.control, replace), ErrLimit)
	after, err := json.Marshal(f.a.s)
	must(t, err)
	original, err := json.Marshal(before)
	must(t, err)
	if string(after) != string(original) || f.a.fault != nil {
		t.Fatal("failed replacement spent predecessor reservation")
	}
	must(t, f.a.CompletePrepare(f.control, c))
}

func TestPrepareTimeoutAndFailedDrainRetainReservation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newFixture(t, func(Binding, *os.File) error { close(entered); <-release; return unix.EIO })
	r := plannedPrepare(t, f, f.volume("blocked"))
	must(t, f.a.ReservePrepare(f.control, r))
	b := r.Attachments[0]
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	await(t, entered)
	c := CompleteRequest{mustID(t), r.Prepare, nil, Attestation{r.Prepare, true, true}}
	wantErr(t, f.a.CompletePrepare(f.control, c), ErrBlocked)
	if f.a.s.Prepares[r.Prepare].Phase != Pending {
		t.Fatal("timeout released prepare")
	}
	close(release)
	_, err = f.a.Retire(context.Background(), f.control, req)
	wantErr(t, err, ErrBlocked)
	wantErr(t, f.a.CompletePrepare(f.control, c), ErrBlocked)
	if f.a.s.Prepares[r.Prepare].Phase != Pending {
		t.Fatal("failed drain released prepare")
	}
	must(t, f.a.Close())
	_, err = f.openCurrent()
	wantErr(t, err, ErrRepairRequired)
}

func TestPrepareCompletionPersistenceFailureRetainsPending(t *testing.T) {
	for _, failure := range []error{unix.EIO, unix.ENOSPC, io.ErrShortWrite} {
		for _, boundary := range persistBoundaries {
			t.Run(failure.Error()+"/"+boundary, func(t *testing.T) {
				f := newFixture(t, nil)
				r := plannedPrepare(t, f, f.volume("failure"))
				must(t, f.a.ReservePrepare(f.control, r))
				c := drainedPrepare(t, f, r)
				fired := false
				f.a.j.fault = func(stage string) error {
					if stage == boundary && !fired {
						fired = true
						return failure
					}
					return nil
				}
				err := f.a.CompletePrepare(f.control, c)
				wantErr(t, err, failure)
				wantErr(t, err, ErrBlocked)
				if !fired || f.a.s.Prepares[r.Prepare].Phase != Pending {
					t.Fatal("failed publication released pending reservation")
				}
				wantErr(t, f.a.CompletePrepare(f.control, c), ErrBlocked)
				f.a.j.fault = nil
				must(t, f.a.Close())
				_, err = f.openCurrent()
				wantErr(t, err, ErrRepairRequired)
				if _, statErr := os.Stat(filepath.Join(f.path, registryName, quarantineName)); statErr != nil {
					t.Fatalf("known IO failure left no permanent quarantine marker: %v", statErr)
				}
			})
		}
	}
}

func TestPrepareBrokenCompletionCapacityFailsClosed(t *testing.T) {
	f := newFixture(t, nil)
	r := plannedPrepare(t, f, f.volume("invariant"))
	must(t, f.a.ReservePrepare(f.control, r))
	c := drainedPrepare(t, f, r)
	f.a.limits.JournalBytes = 1 // Impossible via public API; simulate a software bug.
	err := f.a.CompletePrepare(f.control, c)
	if !errors.Is(err, ErrCapacityInvariant) || !errors.Is(err, ErrBlocked) || f.a.s.Prepares[r.Prepare].Phase != Pending {
		t.Fatalf("capacity invariant did not retain fence: %v", err)
	}
	must(t, f.a.Close())
	_, err = f.openCurrent()
	wantErr(t, err, ErrRepairRequired)
}
