//go:build !cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat

package storageauthority

import "testing"

func TestPrepareIOPhase2ProfilesInert(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	for _, point := range []string{"provision-rename", "provision-parent-sync", "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs"} {
		for _, errnoName := range []string{"eio", "enospc"} {
			if _, err := f.a.InstallPrepareCompatibility(PrepareCompatibilityPlan{Stage: "io-" + errnoName + "-" + point}); err != ErrUnauthorized {
				t.Fatal("enabled", point, err)
			}
		}
		if err := (*Guard)(nil).PrepareCompatibilityCleanupIO("", point); err != nil {
			t.Fatal("inert hook", err)
		}
	}
}
