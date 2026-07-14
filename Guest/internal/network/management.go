//go:build linux

package network

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

const managementLinkName = "cestorage0"

func ConfigureManagement(address string, vlan uint16) error {
	parsed, err := managementConfiguration(address, vlan)
	if err != nil {
		return err
	}
	trunk, err := netlink.LinkByName(trunkName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(trunk); err != nil {
		return err
	}
	link, err := netlink.LinkByName(managementLinkName)
	if err != nil {
		attributes := netlink.NewLinkAttrs()
		attributes.Name = managementLinkName
		attributes.ParentIndex = trunk.Attrs().Index
		link = &netlink.Vlan{LinkAttrs: attributes, VlanId: int(vlan)}
		if err := netlink.LinkAdd(link); err != nil {
			return err
		}
		link, err = netlink.LinkByName(managementLinkName)
		if err != nil {
			return err
		}
	}
	if err := netlink.AddrReplace(link, parsed); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func managementConfiguration(address string, vlan uint16) (*netlink.Addr, error) {
	if vlan < 1 || vlan > 4094 {
		return nil, fmt.Errorf("invalid management VLAN %d", vlan)
	}
	ip, network, err := net.ParseCIDR(address)
	if err != nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid management address %q", address)
	}
	network.IP = ip
	return &netlink.Addr{IPNet: network}, nil
}
