package protocol

import (
	"encoding/json"
	"testing"
)

func TestWorkloadSpecDecodesRuntimeAnnotationsRlimitsAndPathPolicies(t *testing.T) {
	if Version != 11 {
		t.Fatalf("Version = %d, want 11", Version)
	}
	var spec WorkloadSpec
	if err := json.Unmarshal([]byte(`{
		"id":"container-1",
		"ioClaim":"container-claim",
		"annotations":{"io.example.owner":"runtime"},
		"ipcMode":"none",
		"maskedPaths":["/proc/kcore"],
		"readonlyPaths":["/proc/sys"],
		"rlimits":[{"type":"nofile","soft":1024,"hard":18446744073709551615}]
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	if got := spec.Annotations["io.example.owner"]; got != "runtime" {
		t.Fatalf("Annotations[io.example.owner] = %q, want runtime", got)
	}
	if spec.IOClaim != "container-claim" {
		t.Fatalf("IOClaim = %q, want container-claim", spec.IOClaim)
	}
	if spec.IPCMode != "none" {
		t.Fatalf("IPCMode = %q, want none", spec.IPCMode)
	}
	if len(spec.MaskedPaths) != 1 || spec.MaskedPaths[0] != "/proc/kcore" {
		t.Fatalf("MaskedPaths did not decode: %#v", spec.MaskedPaths)
	}
	if len(spec.ReadonlyPaths) != 1 || spec.ReadonlyPaths[0] != "/proc/sys" {
		t.Fatalf("ReadonlyPaths did not decode: %#v", spec.ReadonlyPaths)
	}
	if len(spec.Rlimits) != 1 || spec.Rlimits[0].Type != "nofile" ||
		spec.Rlimits[0].Soft != 1024 || spec.Rlimits[0].Hard != ^uint64(0) {
		t.Fatalf("Rlimits did not decode: %#v", spec.Rlimits)
	}
}

func TestExecSpecDecodesIOClaim(t *testing.T) {
	var spec ExecSpec
	if err := json.Unmarshal([]byte(`{"id":"exec-1","ioClaim":"exec-claim"}`), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.IOClaim != "exec-claim" {
		t.Fatalf("IOClaim = %q, want exec-claim", spec.IOClaim)
	}
}

func TestEndpointSysctlsRemainAvailableInCurrentProtocol(t *testing.T) {
	if Version != 11 {
		t.Fatalf("endpoint sysctls require guest protocol version 11, got %d", Version)
	}
	endpoint := NetworkEndpoint{Sysctls: []string{"net.ipv4.conf.IFNAME.forwarding=1"}}
	if len(endpoint.Sysctls) != 1 || endpoint.Sysctls[0] != "net.ipv4.conf.IFNAME.forwarding=1" {
		t.Fatalf("endpoint sysctls did not round-trip through protocol model: %#v", endpoint.Sysctls)
	}
}

func TestBlockIOThrottlesDecodeInCurrentProtocol(t *testing.T) {
	var resources Resources
	if err := json.Unmarshal([]byte(`{
		"memoryBytes":67108864,"cpuQuota":100000,"cpuPeriod":100000,"pids":32,
		"blockIOReadBps":[{"path":"/dev/vda","rate":9223372036854775808}],
		"blockIOWriteBps":[{"path":"/dev/vda","rate":18446744073709551615}],
		"blockIOReadIOps":[],"blockIOWriteIOps":[]
	}`), &resources); err != nil {
		t.Fatal(err)
	}
	if len(resources.BlockIOReadBps) != 1 || resources.BlockIOReadBps[0].Path != "/dev/vda" ||
		resources.BlockIOReadBps[0].Rate != uint64(1)<<63 ||
		len(resources.BlockIOWriteBps) != 1 || resources.BlockIOWriteBps[0].Rate != ^uint64(0) {
		t.Fatalf("block I/O throttles did not decode: %#v", resources.BlockIOReadBps)
	}
}

func TestResourceUpdateDecodesCompatibilityFailureBoundary(t *testing.T) {
	var update ResourceUpdate
	if err := json.Unmarshal([]byte(`{
		"resources":{"blockIOReadBps":[],"blockIOWriteBps":[],"blockIOReadIOps":[],"blockIOWriteIOps":[]},
		"compatibilityFailureAfterWrites":4
	}`), &update); err != nil {
		t.Fatal(err)
	}
	if update.CompatibilityFailureAfterWrites != 4 {
		t.Fatalf("CompatibilityFailureAfterWrites = %d, want 4", update.CompatibilityFailureAfterWrites)
	}
}
