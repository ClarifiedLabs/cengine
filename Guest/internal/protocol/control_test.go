package protocol

import "testing"

func TestEndpointSysctlsUseProtocolVersionSix(t *testing.T) {
	if Version != 6 {
		t.Fatalf("endpoint sysctls require guest protocol version 6, got %d", Version)
	}
	endpoint := NetworkEndpoint{Sysctls: []string{"net.ipv4.conf.IFNAME.forwarding=1"}}
	if len(endpoint.Sysctls) != 1 || endpoint.Sysctls[0] != "net.ipv4.conf.IFNAME.forwarding=1" {
		t.Fatalf("endpoint sysctls did not round-trip through protocol model: %#v", endpoint.Sysctls)
	}
}
