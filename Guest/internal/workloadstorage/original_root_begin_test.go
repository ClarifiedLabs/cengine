package workloadstorage

import (
	"testing"

	c "dev.cengine/guest/internal/storageclient"
)

// Pure lifecycle gate fixture only: these empty opaque pointers are NOT wire
// grants and are never passed to Arm, Witness, Probe or a success projection.
func TestOriginalRootBeginRequiresBothLiveOwnedMounts(t *testing.T) {
	for _, name := range []string{"live", "nil-pair", "source-dead", "target-dead", "target-terminal", "missing-owner", "missing-grant", "worker-failed", "worker-busy", "worker-joined"} {
		t.Run(name, func(t *testing.T) {
			pair := &originalRootPair{}
			for i := range pair.attachments {
				pair.attachments[i] = &sessionAttachmentFake{done: make(chan struct{})}
				pair.owners[i] = &retainedFDOwner{done: make(chan struct{})}
				pair.grants[i] = &c.OriginalConsumerReadGrant{}
			}
			switch name {
			case "nil-pair":
				pair = nil
			case "source-dead":
				close(pair.attachments[0].(*sessionAttachmentFake).done)
			case "target-dead":
				close(pair.attachments[1].(*sessionAttachmentFake).done)
			case "target-terminal":
				pair.attachments[1] = nil
			case "missing-owner":
				pair.owners[1] = nil
			case "missing-grant":
				pair.grants[1] = nil
			case "worker-failed":
				pair.owners[1].failed = true
			case "worker-busy":
				pair.owners[1].released = true
			case "worker-joined":
				close(pair.owners[1].done)
			}
			if pair.live() != (name == "live") {
				t.Fatal("live pair gate", name)
			}
		})
	}
}
