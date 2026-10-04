//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"context"
	"crypto/tls"
	"reflect"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	a "dev.cengine/guest/internal/storageauthority"
	client "dev.cengine/guest/internal/storageclient"
	control "dev.cengine/guest/internal/storagecontrol"
	w "dev.cengine/guest/internal/storagewire"
)

// Host prerequisite, NOT native mounted acceptance: real issued client, FIFO
// serializer, successful GETATTR, retained control Retire and persisted receipt,
// then the same client's actual request with independently correlated Admit.
func TestSameEOriginalClientActualRequestAfterPersistedReceipt(t *testing.T) {
	f := newFixture(t)
	executor, err := f.s.InstallCompatibilityHostTestExecutor()
	must(t, err)
	h, identity := consumerIdentity(t, f)
	raw, wait := serve(t, f.s.ServeData)
	cfg := consumerTLS(t, f, identity)
	transport := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	must(t, transport.HandshakeContext(ctx))
	data, err := client.New(client.Config{Conn: transport, TLSConfig: cfg, ServerPin: a.Fingerprint(f.ready.ServerKey.String()), Authority: h, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: 0x1ffffffffff, Limits: client.DefaultLimits(), Timeout: time.Second, Invalidate: func(context.Context, client.Notification) error { return nil }})
	must(t, err)
	defer data.Close()
	positive, err := data.OriginalConsumerRootAttempt(ctx, h)
	must(t, err)
	_, root := data.Root()
	if positive.Node != root.Node || positive.RequestSequence == 0 || executor.GetAttrCalls() != 1 {
		t.Fatal("missing actual positive", positive)
	}
	q := consumerArm(t, f, h, identity, cc.SameE)
	q.Version = cc.SameERootVersion
	_, err = f.s.ArmConsumerObservation(q)
	must(t, err)
	// Keep this exact authenticated controller connection across retirement/query.
	ctl, join := f.connect(t)
	defer func() { ctl.Close(); join() }()
	retire := a.RetireRequest{Operation: a.ID(q.OperationUUID), Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch}
	response := call(t, ctl, control.Request{Retire: &retire})
	if response.Receipt == nil {
		t.Fatal("no actual receipt")
	}
	receipt := *response.Receipt
	if receipt.Schema != a.SchemaVersion || receipt.Store != h.Binding.Store || receipt.Volume != h.Binding.Volume || receipt.Attachment != h.Binding.Attachment || receipt.Launch != h.Binding.Launch || receipt.Prepare != "" || receipt.Revision == 0 {
		t.Fatal("foreign receipt", receipt)
	}
	before := call(t, ctl, control.Request{Query: &control.Empty{}}).Snapshot
	if before == nil {
		t.Fatal("no independently queried registry")
	}
	record := before.Attachments[h.Binding.Attachment]
	if record.Phase != a.Drained || record.Binding != h.Binding || record.Retirement != retire.Operation || record.Receipt == nil || *record.Receipt != receipt {
		t.Fatal("not exact persisted retirement", record)
	}
	select {
	case <-data.Terminal():
		t.Fatal("retirement preclosed original client")
	default:
	}
	negative, err := data.OriginalConsumerRootAttempt(ctx, h)
	if err == nil || ctx.Err() != nil || negative.Node != positive.Node || negative.RequestSequence <= positive.RequestSequence {
		t.Fatal("no authentic post-receipt original request", negative, err)
	}
	if got := wait(); got != a.ErrBlocked {
		t.Fatal("not actual Authority.Admit denial", got)
	}
	status, err := f.s.QueryConsumerObservation(q)
	must(t, err)
	must(t, cc.ValidateStatus(status))
	if status.State != "observed" || status.Evidence == nil || status.Evidence.Admission == nil || status.Evidence.Admission.Original != cc.OriginalFor(h) || status.Evidence.Admission.RequestSequence != negative.RequestSequence || status.Evidence.Admission.Operation != w.OpGetAttr || status.Evidence.Admission.Node != negative.Node || status.Evidence.Admission.AuthKind != w.NodeMetadataAuth || !status.Evidence.Admission.NoHandle {
		t.Fatal("local transport error substituted for matching server denial", status)
	}
	finalized, err := f.s.FinalizeConsumerObservation(q)
	must(t, err)
	must(t, cc.ValidateStatus(finalized))
	if finalized.State != "finalized" || !reflect.DeepEqual(finalized.Evidence, status.Evidence) {
		t.Fatal(finalized)
	}
	after := call(t, ctl, control.Request{Query: &control.Empty{}}).Snapshot
	if !reflect.DeepEqual(before, after) || executor.GetAttrCalls() != 1 || f.ready.ServiceEpoch != h.Epoch {
		t.Fatal("denied operation changed registry, dispatched, or changed E")
	}
	if request, err := data.OriginalConsumerRootAttempt(ctx, h); err != client.ErrProtocol || request != (client.OriginalConsumerRootRequest{}) {
		t.Fatal("already-closed client generated another observation", request, err)
	}
}
