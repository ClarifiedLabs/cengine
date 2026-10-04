package storageboot

import (
	"bytes"
	cc "dev.cengine/guest/internal/consumercompat"
	w "dev.cengine/guest/internal/storagewire"
	"testing"
)

func TestConsumerCapabilityClosedWire(t *testing.T) {
	q := consumerVector(t)
	q.Version = cc.SameEFileXattrVersion
	q.CaseName = cc.SameEFile
	f := lifecycleFrame("reply", bindingFixture())
	one := uint64(1)
	f.Sequence = &one
	f.ServiceEpoch, f.WorkerUUID = q.WorkerScope.ServiceEpoch, q.WorkerScope.WorkerUUID
	f.ConsumerObservationStatus = &cc.Status{Query: q, State: "observed", SelectedCount: 1, Evidence: &cc.Evidence{Stage: "request-admit", ErrorClass: "blocked", StoreUUID: q.WorkerScope.StoreUUID, ServiceEpoch: q.WorkerScope.ServiceEpoch, RejectedLeafSHA256: q.OriginalLeafSHA256, Admission: &cc.Admission{Original: q.Original, RequestSequence: 19, Operation: w.OpGetXAttr, Node: 2, AuthKind: w.CallerAuth, NoHandle: true, CapabilityName: cc.SameEFileCapability}}}
	for _, state := range []string{"observed", "finalized"} {
		f.ConsumerObservationStatus.State = state
		var buf bytes.Buffer
		must(t, WriteLifecycleFrame(&buf, &f))
		got, err := ReadLifecycleFrame(&buf)
		must(t, err)
		if got.ConsumerObservationStatus.Evidence.Admission.CapabilityName != cc.SameEFileCapability {
			t.Fatal("lost capability")
		}
		raw, err := lifecycleCanonical(f)
		must(t, err)
		for _, pair := range [][2]string{
			{`"authKind":1`, `"authKind":256`}, {`"authKind":1`, `"authKind":3`}, {`"authKind":1`, `"authKind":1.0`},
			{`"noHandle":true`, `"noHandle":true,"handle":0`}, {`"noHandle":true`, `"noHandle":true,"writeOneAtZero":false`},
			{`"capabilityName":"security.capability"`, `"capabilityName":null`}, {`"capabilityName":"security.capability"`, `"capabilityName":"other"`},
			{`"capabilityName":"security.capability"`, `"capabilityName":"security.capability","capabilityName":"security.capability"`},
		} {
			bad := bytes.Replace(raw, []byte(pair[0]), []byte(pair[1]), 1)
			if bytes.Equal(bad, raw) {
				t.Fatal("no mutation")
			}
			if _, err := DecodeLifecycleFrame(bad); err == nil {
				t.Fatal("loose wire", pair)
			}
		}
	}
}
