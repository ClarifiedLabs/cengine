package protocol

import (
	"encoding/json"
	"testing"
)

func TestWorkloadSpecDecodesRuntimeAnnotations(t *testing.T) {
	if Version != 6 {
		t.Fatalf("Version = %d, want 6", Version)
	}
	var spec WorkloadSpec
	if err := json.Unmarshal([]byte(`{
		"id":"container-1",
		"annotations":{"io.example.owner":"runtime"}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	if got := spec.Annotations["io.example.owner"]; got != "runtime" {
		t.Fatalf("Annotations[io.example.owner] = %q, want runtime", got)
	}
}
