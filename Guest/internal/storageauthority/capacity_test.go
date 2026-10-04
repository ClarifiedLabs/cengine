package storageauthority

import (
	"context"
	"encoding/json"
	"testing"
)

func TestGrowthReservesOperationSlotForRetirement(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("budget")
	b, _ := f.runtime(v, ReadWrite)
	f.a.limits.Operations = len(f.a.s.Operations) + 1
	// An ordinary new command cannot consume the one slot promised to A.
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}), ErrLimit)
	receipt := f.retire(b)
	if f.a.s.Attachments[b.Attachment].Receipt == nil || receipt.Attachment != b.Attachment {
		t.Fatal("retirement lost reserved budget")
	}
	if len(f.a.s.Operations) != f.a.limits.Operations {
		t.Fatal("unexpected ledger count")
	}
	// No additional operation is needed when a lost reply is retried exactly.
	op := f.a.s.Attachments[b.Attachment].Retirement
	got, err := f.a.Retire(context.Background(), f.control, RetireRequest{op, b.Store, b.Volume, b.Attachment, b.Launch})
	must(t, err)
	if got != receipt {
		t.Fatal("capacity invalidated durable retry")
	}
	must(t, f.a.validate())
}

func TestGrowthReservesReceiptBytes(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("budget")
	b, _ := f.runtime(v, ReadWrite)
	encoded, err := json.Marshal(f.a.s)
	must(t, err)
	// Find the exact logical lower bound without doing IO or assuming JSON size.
	low, high := int64(len(encoded)), f.a.limits.JournalBytes
	for low < high {
		mid := low + (high-low)/2
		f.a.limits.JournalBytes = mid
		if f.a.capacity(f.a.s, int64(len(encoded))) == nil {
			high = mid
		} else {
			low = mid + 1
		}
	}
	f.a.limits.JournalBytes = low
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}), ErrLimit)
	f.retire(b)
	must(t, f.a.validate())
}
