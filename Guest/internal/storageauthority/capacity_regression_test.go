package storageauthority

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func exactCapacity(t *testing.T, s *diskState) Limits {
	t.Helper()
	limits := DefaultLimits()
	limits.Operations = len(s.Operations)
	for _, rec := range s.Attachments {
		if rec.Phase != Drained && rec.Retirement == "" {
			limits.Operations++
		}
	}
	for _, prep := range s.Prepares {
		if prep.Phase == Pending {
			limits.Operations++
		}
	}
	data, err := json.Marshal(s)
	must(t, err)
	probe := &Authority{limits: limits}
	low, high := int64(len(data)), limits.JournalBytes
	for low < high {
		mid := low + (high-low)/2
		probe.limits.JournalBytes = mid
		if probe.capacity(s, int64(len(data))) == nil {
			high = mid
		} else {
			low = mid + 1
		}
	}
	limits.JournalBytes = low
	return limits
}

func recoveredProjection(s *diskState) {
	s.Revision++
	for id, rec := range s.Attachments {
		if rec.Phase == Active || rec.Phase == Reserved {
			rec.Phase = Retiring
			s.Attachments[id] = rec
		}
	}
}

func TestConfiguredCapacityPreservesEveryFirstRetirement(t *testing.T) {
	f := newFixture(t, nil)
	v1, v2 := f.volume("one"), f.volume("two")
	runtime1, _ := f.runtime(v1, ReadOnly)
	runtime2, _ := f.runtime(v2, ReadWrite)
	p := mustID(t)
	prepare1, _ := f.binding(v1, PrepareRole, ReadWrite, p)
	prepare2, _ := f.binding(v2, PrepareRole, ReadOnly, p)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p, []Binding{prepare1, prepare2}}))
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), prepare1}))
	projected := f.a.clone()
	recoveredProjection(projected)
	limits := exactCapacity(t, projected)
	must(t, f.a.Close())
	f.c.Limits = limits
	entered, release := make(chan struct{}), make(chan struct{})
	f.c.Barrier = func(b Binding, _ *os.File) error {
		if b.Attachment == runtime1.Attachment {
			close(entered)
			<-release
		}
		return nil
	}
	var err error
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	if f.a.limits != limits {
		t.Fatal("limits not applied by Open")
	}
	// No runtime mutation of limits below: Open has accepted an exact budget.
	req := RetireRequest{mustID(t), runtime1.Store, runtime1.Volume, runtime1.Attachment, runtime1.Launch}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	await(t, entered)
	// An unnecessary new retirement operation ID has no reserved slot. It may
	// fail pre-IO, but cannot poison the already durable RETIRING intent/barrier.
	extra := req
	extra.Operation = mustID(t)
	_, err = f.a.Retire(context.Background(), f.control, extra)
	wantErr(t, err, ErrLimit)
	if errors.Is(err, ErrBlocked) || errors.Is(err, ErrCapacityInvariant) {
		t.Fatalf("clean rejection quarantined existing intent: %v", err)
	}
	snapshot, err := f.a.Query(f.control)
	must(t, err)
	if snapshot.Attachments[runtime1.Attachment].Phase != Retiring {
		t.Fatal("capacity rejection undid fencing")
	}
	if _, err = os.Stat(filepath.Join(f.path, registryName, pendingName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-IO rejection wrote uncertainty marker: %v", err)
	}
	close(release)
	_, err = f.a.Retire(context.Background(), f.control, req)
	must(t, err)
	f.retire(runtime2)
	receipts := []Receipt{f.retire(prepare1), f.retire(prepare2)}
	must(t, f.a.CompletePrepare(f.control, CompleteRequest{mustID(t), p, receipts, Attestation{p, true, true}}))
	if len(f.a.s.Operations) != limits.Operations {
		t.Fatal("did not exercise exact operation limit")
	}
	if f.a.limits != limits || f.a.fault != nil {
		t.Fatal("reserved capacity changed or quarantined")
	}
	must(t, f.a.validate())
}

func TestDrainedNewOperationPreIORejectionDoesNotPoisonReceipt(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("done")
	b, _ := f.runtime(v, ReadWrite)
	receipt := f.retire(b)
	projected := f.a.clone()
	recoveredProjection(projected)
	limits := exactCapacity(t, projected)
	limits.Operations++ // Isolate byte capacity.
	original := f.a.s.Attachments[b.Attachment].Retirement
	must(t, f.a.Close())
	f.c.Limits = limits
	var err error
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	before, err := os.ReadFile(filepath.Join(f.path, registryName, stateName))
	must(t, err)
	steps := 0
	f.a.j.fault = func(string) error { steps++; return nil }
	_, err = f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
	wantErr(t, err, ErrLimit)
	if steps != 0 || f.a.fault != nil || errors.Is(err, ErrCapacityInvariant) {
		t.Fatalf("clean capacity rejection claimed IO ambiguity: steps=%d err=%v", steps, err)
	}
	after, err := os.ReadFile(filepath.Join(f.path, registryName, stateName))
	must(t, err)
	if string(before) != string(after) {
		t.Fatal("rejected command changed durable state")
	}
	got, err := f.a.Retire(context.Background(), f.control, RetireRequest{original, b.Store, b.Volume, b.Attachment, b.Launch})
	must(t, err)
	if got != receipt {
		t.Fatal("capacity rejection changed immutable receipt")
	}
	_, err = f.a.Query(f.control)
	must(t, err)
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
}

func TestRetirementBudgetProjectionAtRevisionBoundaries(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("projection")
	first, _ := f.runtime(v, ReadWrite)
	second, _ := f.runtime(v, ReadOnly)
	for _, revision := range []uint64{8, 9, 98, 99, 998, 999, ^uint64(0) - 6} {
		s := f.a.clone()
		s.Revision = revision
		probe := &Authority{limits: exactCapacity(t, s)}
		check := func() { data, err := json.Marshal(s); must(t, err); must(t, probe.capacity(s, int64(len(data)))) }
		check()
		for _, b := range []Binding{first, second} {
			req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
			rec := s.Attachments[b.Attachment]
			rec.Phase = Retiring
			rec.Retirement = req.Operation
			s.Attachments[b.Attachment] = rec
			s.Operations[req.Operation] = digest("retire", req)
			s.Revision++
			check()
			s.Revision++
			rec.Phase = Drained
			rec.Receipt = &Receipt{SchemaVersion, b.Store, b.Volume, b.Attachment, b.Launch, b.Prepare, s.Revision}
			s.Attachments[b.Attachment] = rec
			check()
		}
	}
	s := f.a.clone()
	s.Revision = ^uint64(0) - 5
	data, err := json.Marshal(s)
	must(t, err)
	wantErr(t, f.a.capacity(s, int64(len(data))), ErrLimit) // Four workload plus two lifecycle revisions needed.
}

func TestBrokenLogicalCapacityInvariantRemainsQuarantined(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("broken-budget")
	b, p := f.runtime(v, ReadWrite)
	// Deliberately violate immutable Config after admission, which the public API
	// cannot do. A software invariant breach must retain fencing and be distinct
	// from an actual storage EIO/ENOSPC while still requiring conservative repair.
	f.a.limits.JournalBytes = 1
	_, err := f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
	wantErr(t, err, ErrLimit)
	wantErr(t, err, ErrCapacityInvariant)
	wantErr(t, err, ErrBlocked)
	_, err = f.a.Admit(p, v.ID, true)
	wantErr(t, err, ErrBlocked)
	if f.a.s.Attachments[b.Attachment].Phase != Retiring {
		t.Fatal("logical failure lost memory fence")
	}
	must(t, f.a.Close())
	_, err = f.openCurrent()
	wantErr(t, err, ErrRepairRequired)
}
