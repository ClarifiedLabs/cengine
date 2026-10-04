package workloadstorage

import "testing"

func TestImmutableBootModeDefaultsLegacyAndRejectsAmbiguity(t *testing.T) {
	for _, line := range []string{"", "quiet", "cengine.workload_storage_mode=legacy"} {
		got, err := bootMode(line)
		if err != nil || got {
			t.Fatal("legacy mode rejected")
		}
	}
	got, err := bootMode("quiet cengine.workload_storage_mode=managed")
	if err != nil || !got {
		t.Fatal("managed mode rejected")
	}
	for _, line := range []string{"cengine.workload_storage_mode", "cengine.workload_storage_mode=", "cengine.workload_storage_mode=other", "cengine.workload_storage_mode=managed cengine.workload_storage_mode=legacy", "cengine.workload_storage_mode=managed cengine.workload_storage_mode=managed"} {
		if _, err := bootMode(line); err == nil {
			t.Fatal("ambiguous mode accepted")
		}
	}
}
