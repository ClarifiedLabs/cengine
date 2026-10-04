//go:build !cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat

package storageauthority

import "testing"

func TestWorkerExitDefaultAndOldProfilesInert(t *testing.T) {
	for _, stage := range []string{"admitted-queued", "full-frame-before-admit"} {
		if _, err := (&PrepareCompatibilityWitness{}).ClaimWorkerExit(stage, ""); err == nil {
			t.Fatal("inert claim", stage)
		}
	}
}
