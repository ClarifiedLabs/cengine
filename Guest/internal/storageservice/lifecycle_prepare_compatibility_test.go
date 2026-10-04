package storageservice

import (
	"errors"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
)

func TestLifecyclePrepareCompatibilityZeroOwner(t *testing.T) {
	for _, service := range []*LifecycleService{nil, {}} {
		if err := service.BindPrepareCompatibilityWorker(string(id(t))); !errors.Is(err, ErrConfiguration) {
			t.Fatal("zero bind", err)
		}
		if _, err := service.ArmPrepareCompatibility(pc.StorageArm{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("zero arm", err)
		}
		if _, err := service.ObservePrepareCompatibility(pc.StorageQuery{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("zero observe", err)
		}
		if _, err := service.ReleasePrepareCompatibility(pc.StorageRelease{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("zero release", err)
		}
		if _, err := service.ClaimPrepareCompatibilityWorkerExit(pc.StorageRelease{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("zero worker exit", err)
		}
		if _, err := service.ClaimPrepareCompatibilityCheckpointExit(pc.WorkerCheckpointExit{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("zero checkpoint exit", err)
		}
	}
}
