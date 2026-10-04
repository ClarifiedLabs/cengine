package storageboot

import (
	"bytes"
	"testing"

	cc "dev.cengine/guest/internal/consumercompat"
	w "dev.cengine/guest/internal/storagewire"
)

func TestConsumerRootEvidenceClosedScalarWire(t *testing.T) {
	q := consumerVector(t)
	q.Version = cc.SameERootVersion
	f := lifecycleFrame("reply", bindingFixture())
	one := uint64(1)
	f.Sequence = &one
	f.ServiceEpoch, f.WorkerUUID = q.WorkerScope.ServiceEpoch, q.WorkerScope.WorkerUUID
	f.ConsumerObservationStatus = &cc.Status{Query: q, State: "observed", SelectedCount: 1, Evidence: &cc.Evidence{
		Stage: "request-admit", ErrorClass: "blocked", StoreUUID: q.WorkerScope.StoreUUID,
		ServiceEpoch: q.WorkerScope.ServiceEpoch, RejectedLeafSHA256: q.OriginalLeafSHA256,
		Admission: &cc.Admission{Original: q.Original, RequestSequence: 19, Operation: w.OpGetAttr, Node: 1, AuthKind: w.NodeMetadataAuth, NoHandle: true},
	}}
	for _, state := range []string{"observed", "finalized"} {
		f.ConsumerObservationStatus.State = state
		must(t, cc.ValidateStatus(*f.ConsumerObservationStatus))
		var buf bytes.Buffer
		must(t, WriteLifecycleFrame(&buf, &f))
		got, err := ReadLifecycleFrame(&buf)
		must(t, err)
		if got.ConsumerObservationStatus.Evidence.Admission.AuthKind != w.NodeMetadataAuth || !got.ConsumerObservationStatus.Evidence.Admission.NoHandle {
			t.Fatal("lost typed evidence")
		}
		raw, err := lifecycleCanonical(f)
		must(t, err)
		for _, change := range [][2]string{
			{`"authKind":3`, `"authKind":256`},
			{`"authKind":3`, `"authKind":1`},
			{`"authKind":3`, `"authKind":"3"`},
			{`"authKind":3`, `"authKind":3.0`},
			{`"authKind":3`, `"authKind":null`},
			{`"noHandle":true`, `"noHandle":false`},
			{`"noHandle":true`, `"noHandle":true,"writeOneAtZero":false`},
			{`"noHandle":true`, `"noHandle":1`},
			{`"noHandle":true`, `"noHandle":"true"`},
			{`"noHandle":true`, `"noHandle":null`},
			{`"noHandle":true`, `"noHandle":true,"extra":true`},
			{`"noHandle":true`, `"noHandle":true,"noHandle":true`},
		} {
			bad := bytes.Replace(raw, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(raw, bad) {
				t.Fatal("mutation not applied", change)
			}
			if _, err := DecodeLifecycleFrame(bad); err == nil {
				t.Fatal("accepted malformed scalar", change)
			}
		}
	}
}

func TestConsumerFileEvidenceRejectsExtraneousFalseNoHandle(t *testing.T) {
	q := consumerVector(t)
	q.Version = cc.SameEFileVersion
	q.CaseName = cc.SameEFile
	q.Original.Binding.Mode = "read-write"
	f := lifecycleFrame("reply", bindingFixture())
	one := uint64(1)
	f.Sequence = &one
	f.ServiceEpoch, f.WorkerUUID = q.WorkerScope.ServiceEpoch, q.WorkerScope.WorkerUUID
	f.ConsumerObservationStatus = &cc.Status{Query: q, State: "observed", SelectedCount: 1, Evidence: &cc.Evidence{
		Stage: "request-admit", ErrorClass: "blocked", StoreUUID: q.WorkerScope.StoreUUID,
		ServiceEpoch: q.WorkerScope.ServiceEpoch, RejectedLeafSHA256: q.OriginalLeafSHA256,
		Admission: &cc.Admission{Original: q.Original, RequestSequence: 19, Operation: w.OpWrite, Node: 2, AuthKind: w.CallerAuth, Handle: 3, WriteOneAtZero: true},
	}}
	for _, state := range []string{"observed", "finalized"} {
		f.ConsumerObservationStatus.State = state
		must(t, cc.ValidateStatus(*f.ConsumerObservationStatus))
		var buf bytes.Buffer
		must(t, WriteLifecycleFrame(&buf, &f))
		_, err := ReadLifecycleFrame(&buf)
		must(t, err)
		raw, err := lifecycleCanonical(f)
		must(t, err)
		bad := bytes.Replace(raw, []byte(`"writeOneAtZero":true`), []byte(`"writeOneAtZero":true,"noHandle":false`), 1)
		if bytes.Equal(raw, bad) {
			t.Fatal("mutation not applied")
		}
		if _, err := DecodeLifecycleFrame(bad); err == nil {
			t.Fatal("accepted extraneous noHandle:false in file admission")
		}
	}
}
