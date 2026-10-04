//go:build linux

package network

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

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

func TestManagementLoopbackSetup(t *testing.T) {
	failure := errors.New("netlink failed")
	for _, mode := range []string{"success", "lookup", "up"} {
		t.Run(mode, func(t *testing.T) {
			loopback := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lo"}}
			calls := 0
			err := configureManagementLoopback(func(name string) (netlink.Link, error) {
				if name != "lo" {
					t.Fatal("not loopback")
				}
				if mode == "lookup" {
					return nil, failure
				}
				return loopback, nil
			}, func(link netlink.Link) error {
				calls++
				if link != loopback {
					t.Fatal("wrong link")
				}
				if mode == "up" {
					return failure
				}
				return nil
			})
			if mode == "success" && err != nil || mode != "success" && err != failure {
				t.Fatalf("error: %v", err)
			}
			if mode == "lookup" && calls != 0 || mode != "lookup" && calls != 1 {
				t.Fatal("unexpected link setup")
			}
		})
	}
}

func TestManagementLinkDoesNotCollideWithDockerInterfaces(t *testing.T) {
	if managementLinkName == trunkName || len(managementLinkName) > 15 {
		t.Fatalf("invalid management interface name %q", managementLinkName)
	}
}
