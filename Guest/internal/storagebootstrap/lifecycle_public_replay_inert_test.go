//go:build !cengine_prepare_full_compat

package storagebootstrap

import "testing"

func TestLifecyclePublicReplayOrdinaryBuildInert(t *testing.T) {
	f := newLifecycleSessionFixture(t, true)
	f.connect(t)
	if raw, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("public-takeover-replay", []byte(`{}`)), nil); err == nil || len(raw) != 0 {
		t.Fatal("ordinary build admitted replay")
	}
	if f.s.publicTakeoverReplayUsed {
		t.Fatal("ordinary build consumed probe")
	}
	check(t, f.s.takeover(t.Context()))
}
