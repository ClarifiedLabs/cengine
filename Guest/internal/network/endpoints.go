//go:build linux

package network

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"dev.cengine/guest/internal/protocol"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const trunkName = "eth0"

func Attach(pid int, endpoints []protocol.NetworkEndpoint) error {
	for _, endpoint := range endpoints {
		if err := AttachOne(pid, endpoint); err != nil { return fmt.Errorf("attach network %s: %w", endpoint.NetworkID, err) }
	}
	return setupLoopback(pid)
}

func AttachOne(pid int, endpoint protocol.NetworkEndpoint) error {
	if endpoint.VLAN < 1 || endpoint.VLAN > 4094 { return fmt.Errorf("invalid VLAN %d", endpoint.VLAN) }
	if endpoint.Name == "" { return errors.New("endpoint requires an interface name") }
	target, err := netns.GetFromPid(pid); if err != nil { return err }; defer target.Close()
	targetHandle, err := netlink.NewHandleAt(target, routeNetlinkFamilies()...); if err != nil { return err }; defer targetHandle.Close()
	if existing, err := targetHandle.LinkByName(endpoint.Name); err == nil { return configure(targetHandle, existing, endpoint) }
	trunk, err := netlink.LinkByName(trunkName); if err != nil { return err }
	if err := netlink.LinkSetUp(trunk); err != nil { return err }
	temporaryName := temporaryLinkName(pid, endpoint.VLAN)
	attributes := netlink.NewLinkAttrs(); attributes.Name = temporaryName; attributes.ParentIndex = trunk.Attrs().Index
	if endpoint.MACAddress != "" { address, err := net.ParseMAC(endpoint.MACAddress); if err != nil { return err }; attributes.HardwareAddr = address }
	link := &netlink.Vlan{LinkAttrs: attributes, VlanId: int(endpoint.VLAN)}
	if err := netlink.LinkAdd(link); err != nil { return err }
	if err := netlink.LinkSetNsFd(link, int(target)); err != nil { _ = netlink.LinkDel(link); return err }
	moved, err := targetHandle.LinkByName(temporaryName); if err != nil { return err }
	if err := targetHandle.LinkSetName(moved, endpoint.Name); err != nil { _ = targetHandle.LinkDel(moved); return err }
	moved, err = targetHandle.LinkByName(endpoint.Name); if err != nil { return err }
	if err := configure(targetHandle, moved, endpoint); err != nil { _ = targetHandle.LinkDel(moved); return err }
	return setupLoopbackWithHandle(targetHandle)
}

func Remove(pid int, name string) error {
	if name == "" { return unix.EINVAL }
	target, err := netns.GetFromPid(pid); if err != nil { return err }; defer target.Close()
	handle, err := netlink.NewHandleAt(target, routeNetlinkFamilies()...); if err != nil { return err }; defer handle.Close()
	link, err := handle.LinkByName(name)
	if err != nil { if _, ok := err.(netlink.LinkNotFoundError); ok { return nil }; return err }
	return handle.LinkDel(link)
}

func configure(handle *netlink.Handle, link netlink.Link, endpoint protocol.NetworkEndpoint) error {
	for _, value := range endpoint.Addresses { address, err := netlink.ParseAddr(value); if err != nil { return err }; if err := handle.AddrReplace(link, address); err != nil { return err } }
	if err := handle.LinkSetUp(link); err != nil { return err }
	for _, value := range endpoint.Gateways {
		gateway := net.ParseIP(value); if gateway == nil { return fmt.Errorf("invalid gateway %s", value) }
		family := netlink.FAMILY_V4; if strings.Contains(value, ":") { family = netlink.FAMILY_V6 }
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: gateway, Priority: 100, Protocol: unix.RTPROT_STATIC}
		if family == netlink.FAMILY_V6 { route.Dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)} }
		if err := handle.RouteReplace(route); err != nil { return err }
	}
	return nil
}

func setupLoopback(pid int) error {
	target, err := netns.GetFromPid(pid); if err != nil { return err }; defer target.Close()
	handle, err := netlink.NewHandleAt(target, routeNetlinkFamilies()...); if err != nil { return err }; defer handle.Close()
	return setupLoopbackWithHandle(handle)
}

func setupLoopbackWithHandle(handle *netlink.Handle) error { loopback, err := handle.LinkByName("lo"); if err != nil { return err }; return handle.LinkSetUp(loopback) }

func temporaryLinkName(pid int, vlan uint16) string { return fmt.Sprintf("ce%08x%03x", uint32(pid), vlan) }

func routeNetlinkFamilies() []int { return []int{unix.NETLINK_ROUTE} }
