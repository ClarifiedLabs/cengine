package storageservice

import (
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	"strings"
	"testing"
)

func TestIOStatusProjectionNeedsActualFiredCut(t *testing.T) {
	id := "00000001-0000-4000-8000-000000000001"
	c := servicePrepareCompatibility{query: pc.StorageQuery{Version: 3, Profile: pc.FullProfile, RequestID: id, ArmDigest: strings.Repeat("a", 64), WorkerUUID: id}, target: id, stage: "io-eio-seal-persist"}
	snap := a.PrepareCompatibilitySnapshot{State: "armed", IO: &a.PrepareCompatibilityIO{Point: "seal-persist", Errno: "EIO"}}
	if c.statusFromSnapshot(snap).Observation != nil {
		t.Fatal("unfired evidence")
	}
	snap.State = "observed"
	snap.IO.Fired = true
	snap.IO.Occurrence = 1
	snap.IO.Sequence = 42
	got := c.statusFromSnapshot(snap)
	if pc.ValidateStorageStatus(got) != nil || got.Observation.IO.RequestSequence != 42 || got.Observation.Drain != nil {
		t.Fatal("lost IO snapshot")
	}
}
