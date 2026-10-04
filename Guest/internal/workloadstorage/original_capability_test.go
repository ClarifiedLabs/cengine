package workloadstorage

import (
	c "dev.cengine/guest/internal/storageclient"
	"testing"
)

func TestOriginalCapabilityVersionAndContinuity(t *testing.T) {
	arm := originalTestArm()
	arm.Version = 7
	for _, name := range []string{"same-e-retained-fd", "cross-e-retained-fd", "cross-mount-root-grant", "same-e-existing-data", "cross-e-old-leaf-reconnect"} {
		arm.CaseName = name
		if arm.valid() != (name == "same-e-retained-fd") {
			t.Fatal("version widened", name)
		}
	}
	positive := c.OriginalConsumerFileTrace{Write: &c.OriginalConsumerFileRequest{Node: 2, Handle: 3, RequestSequence: 4}, Sync: &c.OriginalConsumerFileRequest{Node: 2, Handle: 3, RequestSequence: 5}, WriteOK: true, SyncOK: true}
	for _, fault := range []string{"exact", "missing", "node", "sequence", "write", "sync", "write-ok", "sync-ok", "positive-capability"} {
		t.Run(fault, func(t *testing.T) {
			v := c.OriginalConsumerFileTrace{Capability: &c.OriginalConsumerCapabilityRequest{Node: 2, RequestSequence: 6}}
			prior := positive
			switch fault {
			case "missing":
				v.Capability = nil
			case "node":
				v.Capability.Node++
			case "sequence":
				v.Capability.RequestSequence = 5
			case "write":
				v.Write = positive.Write
			case "sync":
				v.Sync = positive.Sync
			case "write-ok":
				v.WriteOK = true
			case "sync-ok":
				v.SyncOK = true
			case "positive-capability":
				prior.Capability = v.Capability
			}
			if validNegativeCapabilityFileTrace(v, prior) != (fault == "exact") {
				t.Fatal("invalid correlation", fault)
			}
			if validNegativeFileTrace(v, prior) {
				t.Fatal("legacy borrowed capability")
			}
		})
	}
}
