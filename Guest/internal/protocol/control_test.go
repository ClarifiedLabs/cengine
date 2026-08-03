package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkloadSpecDecodesRuntimeAnnotationsRlimitsAndPathPolicies(t *testing.T) {
	if Version != 18 {
		t.Fatalf("Version = %d, want 18", Version)
	}
	var spec WorkloadSpec
	if err := json.Unmarshal([]byte(`{
		"id":"container-1",
		"ioClaim":"container-claim",
		"annotations":{"io.example.owner":"runtime"},
		"noNewPrivileges":true,
		"seccompDefault":true,
		"ipcMode":"none",
		"shmSize":33554432,
		"sysctls":{"net.ipv4.ip_forward":"1"},
		"maskedPaths":["/proc/kcore"],
		"readonlyPaths":["/proc/sys"],
		"mounts":[{"kind":"bind","nonRecursive":true,"readOnlyNonRecursive":true}],
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
	if !spec.NoNewPrivileges {
		t.Fatal("NoNewPrivileges did not decode")
	}
	if !spec.SeccompDefault {
		t.Fatal("SeccompDefault did not decode")
	}
	if spec.IPCMode != "none" {
		t.Fatalf("IPCMode = %q, want none", spec.IPCMode)
	}
	if spec.ShmSize != 33554432 || spec.Sysctls["net.ipv4.ip_forward"] != "1" {
		t.Fatalf("ShmSize/Sysctls did not decode: %#v", spec)
	}
	if len(spec.MaskedPaths) != 1 || spec.MaskedPaths[0] != "/proc/kcore" {
		t.Fatalf("MaskedPaths did not decode: %#v", spec.MaskedPaths)
	}
	if len(spec.ReadonlyPaths) != 1 || spec.ReadonlyPaths[0] != "/proc/sys" {
		t.Fatalf("ReadonlyPaths did not decode: %#v", spec.ReadonlyPaths)
	}
	if len(spec.Mounts) != 1 || !spec.Mounts[0].NonRecursive ||
		!spec.Mounts[0].ReadOnlyNonRecursive || spec.Mounts[0].ReadOnlyForceRecursive {
		t.Fatalf("bind recursion modes did not decode: %#v", spec.Mounts)
	}
	if len(spec.Rlimits) != 1 || spec.Rlimits[0].Type != "nofile" ||
		spec.Rlimits[0].Soft != 1024 || spec.Rlimits[0].Hard != ^uint64(0) {
		t.Fatalf("Rlimits did not decode: %#v", spec.Rlimits)
	}
}

func TestEnvelopeVersionCompatibility(t *testing.T) {
	frame := func(version uint32) *bytes.Buffer {
		t.Helper()
		data, err := json.Marshal(Envelope{Version: version, ID: "request-1", Operation: "ping"})
		if err != nil {
			t.Fatal(err)
		}
		var buffer bytes.Buffer
		if err := binary.Write(&buffer, binary.BigEndian, uint32(len(data))); err != nil {
			t.Fatal(err)
		}
		buffer.Write(data)
		return &buffer
	}
	for _, version := range []uint32{PreviousVersion, Version} {
		envelope, err := ReadEnvelope(frame(version))
		if err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		if envelope.Version != version {
			t.Fatalf("version = %d, want %d", envelope.Version, version)
		}
		response := ResponseEnvelope(envelope)
		if response.Version != version || response.ID != envelope.ID || response.Operation != envelope.Operation {
			t.Fatalf("response did not echo version %d: %#v", version, response)
		}
	}
	for _, version := range []uint32{0, PreviousVersion - 1, Version + 1} {
		_, err := ReadEnvelope(frame(version))
		if err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
			t.Fatalf("version %d error = %v", version, err)
		}
	}
}

func TestPreviousVersionWorkloadDefaultsSharedMemory(t *testing.T) {
	var previous WorkloadSpec
	if err := json.Unmarshal([]byte(`{"id":"container-1","ipcMode":"private"}`), &previous); err != nil {
		t.Fatal(err)
	}
	previous.ApplyCompatibilityDefaults(PreviousVersion)
	if previous.ShmSize != DefaultSharedMemorySize || len(previous.Sysctls) != 0 {
		t.Fatalf("previous-version defaults = %#v", previous)
	}

	var current WorkloadSpec
	current.ApplyCompatibilityDefaults(Version)
	if current.ShmSize != 0 {
		t.Fatalf("current-version missing shared memory size defaulted to %d", current.ShmSize)
	}
}

func TestExecSpecDecodesIOClaim(t *testing.T) {
	var spec ExecSpec
	if err := json.Unmarshal([]byte(`{"id":"exec-1","ioClaim":"exec-claim","seccompDefault":true}`), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.IOClaim != "exec-claim" {
		t.Fatalf("IOClaim = %q, want exec-claim", spec.IOClaim)
	}
	if !spec.SeccompDefault {
		t.Fatal("SeccompDefault did not decode")
	}
}

func TestEndpointSysctlsRemainAvailableInCurrentProtocol(t *testing.T) {
	if Version != 18 {
		t.Fatalf("endpoint sysctls require current guest protocol version 18, got %d", Version)
	}
	endpoint := NetworkEndpoint{Sysctls: []string{"net.ipv4.conf.IFNAME.forwarding=1"}}
	if len(endpoint.Sysctls) != 1 || endpoint.Sysctls[0] != "net.ipv4.conf.IFNAME.forwarding=1" {
		t.Fatalf("endpoint sysctls did not round-trip through protocol model: %#v", endpoint.Sysctls)
	}
}

func TestWallClockTimeRequiresBothFields(t *testing.T) {
	var value WallClockTime
	if err := json.Unmarshal(
		[]byte(`{"seconds":1784920000,"microseconds":123456}`), &value,
	); err != nil {
		t.Fatal(err)
	}
	if value.Seconds != 1_784_920_000 || value.Microseconds != 123_456 {
		t.Fatalf("WallClockTime = %#v", value)
	}
	for _, payload := range []string{
		`{"seconds":1784920000}`,
		`{"microseconds":123456}`,
		`{"seconds":"invalid","microseconds":123456}`,
	} {
		if err := json.Unmarshal([]byte(payload), &value); err == nil {
			t.Fatalf("WallClockTime accepted %s", payload)
		}
	}
}

func TestBlockIOThrottlesDecodeInCurrentProtocol(t *testing.T) {
	var resources Resources
	if err := json.Unmarshal([]byte(`{
		"memoryBytes":67108864,"cpuQuota":100000,"cpuPeriod":100000,"pids":32,
		"blockIOReadBps":[{"path":"/dev/vda","rate":9223372036854775808}],
		"blockIOWriteBps":[{"path":"/dev/vda","rate":18446744073709551615}],
		"blockIOReadIOps":[],"blockIOWriteIOps":[{"path":"/dev/vdb","rate":200}],
		"devices":[{"pathOnHost":"/dev/vdb","pathInContainer":"/dev/data","cgroupPermissions":"rw"}],
		"deviceCgroupRules":[{"deviceType":"c","major":10,"minor":null,"access":"rwm"}]
	}`), &resources); err != nil {
		t.Fatal(err)
	}
	if len(resources.BlockIOReadBps) != 1 || resources.BlockIOReadBps[0].Path != "/dev/vda" ||
		resources.BlockIOReadBps[0].Rate != uint64(1)<<63 ||
		len(resources.BlockIOWriteBps) != 1 || resources.BlockIOWriteBps[0].Rate != ^uint64(0) {
		t.Fatalf("block I/O throttles did not decode: %#v", resources.BlockIOReadBps)
	}
	if len(resources.Devices) != 1 || resources.Devices[0].PathOnHost != "/dev/vdb" ||
		resources.Devices[0].PathInContainer != "/dev/data" ||
		resources.Devices[0].CgroupPermissions != "rw" {
		t.Fatalf("configured devices did not decode: %#v", resources.Devices)
	}
	if len(resources.DeviceCgroupRules) != 1 || resources.DeviceCgroupRules[0].DeviceType != "c" ||
		resources.DeviceCgroupRules[0].Major == nil || *resources.DeviceCgroupRules[0].Major != 10 ||
		resources.DeviceCgroupRules[0].Minor != nil || resources.DeviceCgroupRules[0].Access != "rwm" {
		t.Fatalf("device cgroup rules did not decode: %#v", resources.DeviceCgroupRules)
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
