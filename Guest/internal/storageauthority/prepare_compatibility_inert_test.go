//go:build !cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat

package storageauthority

import "testing"

func TestStorageCompatibilityOrdinaryAndConflictingTagsInert(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	var g *Guard
	if err := g.PrepareCompatibilityTransactionRemoved("", func() error {
		t.Fatal("ordinary profile invoked witness-only replay fsync")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"", "io-eio-copy-operation-write", "io-enospc-seal-persist", "io-eio-retire-barrier-clear-persist"} {
		if _, err := f.a.InstallPrepareCompatibility(PrepareCompatibilityPlan{Stage: stage}); err != ErrUnauthorized {
			t.Fatal("enabled", stage, err)
		}
	}
}
