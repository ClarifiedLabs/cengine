//go:build linux

package network

import "testing"

func TestManagementConfigurationRequiresIPv4CIDRAndValidVLAN(t *testing.T) {
	address, err := managementConfiguration("100.64.0.2/10", 4094)
	if err != nil || address.String() != "100.64.0.2/10" {
		t.Fatalf("unexpected management configuration %v, %v", address, err)
	}
	for _, test := range []struct {
		address string
		vlan    uint16
	}{{"100.64.0.2", 4094}, {"fd00::2/64", 4094}, {"100.64.0.2/10", 0}} {
		if _, err := managementConfiguration(test.address, test.vlan); err == nil {
			t.Fatalf("expected address %q VLAN %d to fail", test.address, test.vlan)
		}
	}
}

func TestManagementLinkDoesNotCollideWithDockerInterfaces(t *testing.T) {
	if managementLinkName == trunkName || len(managementLinkName) > 15 {
		t.Fatalf("invalid management interface name %q", managementLinkName)
	}
}
