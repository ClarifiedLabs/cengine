package storageauthority

import "testing"

func TestStorageSchemaVersions(t *testing.T) {
	if SchemaVersion != 3 || LifecycleSchemaVersion != 4 {
		t.Fatal("workload receipt and registry versions changed")
	}
}
