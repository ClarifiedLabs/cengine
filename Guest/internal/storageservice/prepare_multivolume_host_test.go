//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"context"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	"testing"
	"time"
)

// The existing explicit host adapter substitutes only filesystem execution and
// the Linux barrier. Authority journal commits and the crash-only reply hook
// remain real. This is host ordering coverage, not physical VM death evidence.
// Drive the actual control Retire reply hook used by the existing crash-only
// hold. Target-first must return both replies, never publish held, and remain
// ineligible even when the exact target retirement is replayed after its peer.
func TestTwoVolumeServiceRealReverseRetirementOrderNeverHeld(t *testing.T) {
	f := newFixture(t)
	_, err := f.s.InstallCompatibilityHostTestExecutor()
	must(t, err)
	arm, bindings := twoVolumeServicePrepare(t, f, -1)
	_, err = f.s.ArmPrepareCompatibility(arm)
	must(t, err)
	query, err := pc.StorageQueryForArm(arm)
	must(t, err)
	client, wait := f.connect(t)
	defer func() { client.Close(); wait() }()
	requests := make([]a.RetireRequest, 2)
	for i, b := range bindings {
		requests[i] = a.RetireRequest{Operation: id(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}
	}
	var receipts [2]a.Receipt
	for _, i := range []int{1, 0, 1} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		response, err := client.Call(ctx, c.Request{Retire: &requests[i]})
		cancel()
		must(t, err)
		if response.Receipt == nil {
			t.Fatal("real Retire returned no receipt")
		}
		if receipts[i] != (a.Receipt{}) && receipts[i] != *response.Receipt {
			t.Fatal("replay changed original receipt")
		}
		receipts[i] = *response.Receipt
		status, err := f.s.ObservePrepareCompatibility(query)
		must(t, err)
		must(t, pc.ValidateStorageStatusForArm(status, arm))
		if status.State != "armed" || status.Observation != nil || !status.RetirementStarted || status.AcceptedInFlight != 0 || status.ReceiptReplayCount != 0 {
			t.Fatal("reverse retirement manufactured held proof", status)
		}
	}
	if receipts[1].Revision >= receipts[0].Revision {
		t.Fatal("test did not retire target before preceding volume")
	}
	snapshot := call(t, client, c.Request{Query: &c.Empty{}}).Snapshot
	if snapshot == nil {
		t.Fatal("missing durable authority snapshot")
	}
	for i, b := range bindings {
		record := snapshot.Attachments[b.Attachment]
		if record.Binding != b || record.Phase != a.Drained || record.Retirement != requests[i].Operation || record.Receipt == nil || *record.Receipt != receipts[i] {
			t.Fatal("real retirement not durable", i)
		}
	}
	if snapshot.Prepares[bindings[0].Prepare].Phase != a.Pending || len(snapshot.Attachments) != 2 {
		t.Fatal("reverse retirement completed prepare or issued runtime attachments")
	}
}
