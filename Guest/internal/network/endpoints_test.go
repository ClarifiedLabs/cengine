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
