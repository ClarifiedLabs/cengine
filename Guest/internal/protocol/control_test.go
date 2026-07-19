package protocol

import (
	"encoding/json"
	"testing"
)

func TestWorkloadSpecDecodesRuntimeAnnotationsAndRlimits(t *testing.T) {
	if Version != 7 {
		t.Fatalf("Version = %d, want 7", Version)
	}
	var spec WorkloadSpec
	if err := json.Unmarshal([]byte(`{
		"id":"container-1",
		"annotations":{"io.example.owner":"runtime"},
		"rlimits":[{"type":"nofile","soft":1024,"hard":18446744073709551615}]
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	if got := spec.Annotations["io.example.owner"]; got != "runtime" {
		t.Fatalf("Annotations[io.example.owner] = %q, want runtime", got)
	}
	if len(spec.Rlimits) != 1 || spec.Rlimits[0].Type != "nofile" ||
		spec.Rlimits[0].Soft != 1024 || spec.Rlimits[0].Hard != ^uint64(0) {
		t.Fatalf("Rlimits did not decode: %#v", spec.Rlimits)
	}
}

func TestEndpointSysctlsRemainAvailableInProtocolVersionSeven(t *testing.T) {
	if Version != 7 {
		t.Fatalf("endpoint sysctls require guest protocol version 7, got %d", Version)
	}
	endpoint := NetworkEndpoint{Sysctls: []string{"net.ipv4.conf.IFNAME.forwarding=1"}}
	if len(endpoint.Sysctls) != 1 || endpoint.Sysctls[0] != "net.ipv4.conf.IFNAME.forwarding=1" {
		t.Fatalf("endpoint sysctls did not round-trip through protocol model: %#v", endpoint.Sysctls)
	}
}
