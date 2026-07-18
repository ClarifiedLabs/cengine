//go:build linux

package network

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestContainerNetworkHandlesOnlyRequestRouteNetlink(t *testing.T) {
	families := routeNetlinkFamilies()
	if len(families) != 1 || families[0] != unix.NETLINK_ROUTE {
		t.Fatalf("unexpected netlink families %v", families)
	}
}

func TestTemporaryLinkNameCannotCollideWithDockerInterface(t *testing.T) {
	name := temporaryLinkName(4_194_304, 4094)
	if name == trunkName || len(name) > 15 {
		t.Fatalf("invalid temporary interface name %q", name)
	}
}

func TestEndpointSysctlPathReplacesInterfacePlaceholderWithoutTraversal(t *testing.T) {
	path, value, err := endpointSysctlPath("eth0", "net.ipv4.conf.IFNAME.forwarding=1")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/proc/sys/net/ipv4/conf/eth0/forwarding" || value != "1" {
		t.Fatalf("unexpected sysctl path/value: %q %q", path, value)
	}
	for _, assignment := range []string{
		"net.ipv4.conf.eth0.forwarding=1",
		"net.ipv4...IFNAME=1",
		"net.ipv4.conf.IFNAME...=1",
		"kernel.ipv4.conf.IFNAME.forwarding=1",
		"net.ipv4.conf.IFNAME.forwarding=1\n2",
	} {
		if _, _, err := endpointSysctlPath("eth0", assignment); err == nil {
			t.Fatalf("expected %q to be rejected", assignment)
		}
	}
}
