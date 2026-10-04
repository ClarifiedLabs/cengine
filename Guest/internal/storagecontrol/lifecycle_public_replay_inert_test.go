//go:build !cengine_prepare_full_compat

package storagecontrol

import (
	a "dev.cengine/guest/internal/storageauthority"
	"testing"
)

func TestLifecyclePublicReplayOrdinaryBuildInert(t *testing.T) {
	if ReplaySignedLifecycleTakeover(t.Context(), nil, a.SignedLifecycleGrant{}, a.SignedLifecycleGrant{}) == nil {
		t.Fatal("ordinary replay")
	}
}
