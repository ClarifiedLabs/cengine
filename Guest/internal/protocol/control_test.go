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

func TestEndpointSysctlsUseProtocolVersionSix(t *testing.T) {
	if Version != 6 {
		t.Fatalf("endpoint sysctls require guest protocol version 6, got %d", Version)
	}
	endpoint := NetworkEndpoint{Sysctls: []string{"net.ipv4.conf.IFNAME.forwarding=1"}}
	if len(endpoint.Sysctls) != 1 || endpoint.Sysctls[0] != "net.ipv4.conf.IFNAME.forwarding=1" {
		t.Fatalf("endpoint sysctls did not round-trip through protocol model: %#v", endpoint.Sysctls)
	}
}
