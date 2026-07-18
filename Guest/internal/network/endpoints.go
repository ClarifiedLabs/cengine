//go:build linux

package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"dev.cengine/guest/internal/protocol"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const trunkName = "eth0"

func Attach(pid int, endpoints []protocol.NetworkEndpoint) error {
	for _, endpoint := range endpoints {
		if err := AttachOne(pid, endpoint); err != nil {
			return fmt.Errorf("attach network %s: %w", endpoint.NetworkID, err)
		}
	}
	return setupLoopback(pid)
}

func AttachOne(pid int, endpoint protocol.NetworkEndpoint) error {
	if endpoint.VLAN < 1 || endpoint.VLAN > 4094 {
		return fmt.Errorf("invalid VLAN %d", endpoint.VLAN)
	}
	if endpoint.Name == "" {
		return errors.New("endpoint requires an interface name")
	}
	target, err := netns.GetFromPid(pid)
	if err != nil {
		return err
	}
	defer target.Close()
	targetHandle, err := netlink.NewHandleAt(target, routeNetlinkFamilies()...)
	if err != nil {
		return err
	}
	defer targetHandle.Close()
	if existing, err := targetHandle.LinkByName(endpoint.Name); err == nil {
		if err := configure(targetHandle, existing, endpoint); err != nil {
			return err
		}
		return setSysctls(target, endpoint.Name, endpoint.Sysctls)
	}
	trunk, err := netlink.LinkByName(trunkName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(trunk); err != nil {
		return err
	}
	temporaryName := temporaryLinkName(pid, endpoint.VLAN)
	attributes := netlink.NewLinkAttrs()
	attributes.Name = temporaryName
	attributes.ParentIndex = trunk.Attrs().Index
	if endpoint.MACAddress != "" {
		address, err := net.ParseMAC(endpoint.MACAddress)
		if err != nil {
			return err
		}
		attributes.HardwareAddr = address
	}
	link := &netlink.Vlan{LinkAttrs: attributes, VlanId: int(endpoint.VLAN)}
	if err := netlink.LinkAdd(link); err != nil {
		return err
	}
	if err := netlink.LinkSetNsFd(link, int(target)); err != nil {
		_ = netlink.LinkDel(link)
		return err
	}
	moved, err := targetHandle.LinkByName(temporaryName)
	if err != nil {
		return err
	}
	if err := targetHandle.LinkSetName(moved, endpoint.Name); err != nil {
		_ = targetHandle.LinkDel(moved)
		return err
	}
	moved, err = targetHandle.LinkByName(endpoint.Name)
	if err != nil {
		return err
	}
	if err := configure(targetHandle, moved, endpoint); err != nil {
		_ = targetHandle.LinkDel(moved)
		return err
	}
	if err := setSysctls(target, endpoint.Name, endpoint.Sysctls); err != nil {
		_ = targetHandle.LinkDel(moved)
		return err
	}
	return setupLoopbackWithHandle(targetHandle)
}

func Remove(pid int, name string) error {
	if name == "" {
		return unix.EINVAL
	}
	target, err := netns.GetFromPid(pid)
	if err != nil {
		return err
	}
	defer target.Close()
	handle, err := netlink.NewHandleAt(target, routeNetlinkFamilies()...)
	if err != nil {
		return err
	}
	defer handle.Close()
	link, err := handle.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return err
	}
	return handle.LinkDel(link)
}

func configure(handle *netlink.Handle, link netlink.Link, endpoint protocol.NetworkEndpoint) error {
	for _, value := range endpoint.Addresses {
		address, err := netlink.ParseAddr(value)
		if err != nil {
			return err
		}
		if err := handle.AddrReplace(link, address); err != nil {
			return err
		}
	}
	if err := handle.LinkSetUp(link); err != nil {
		return err
	}
	for _, value := range endpoint.Gateways {
		gateway := net.ParseIP(value)
		if gateway == nil {
			return fmt.Errorf("invalid gateway %s", value)
		}
		family := netlink.FAMILY_V4
		if strings.Contains(value, ":") {
			family = netlink.FAMILY_V6
		}
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: gateway, Priority: 100, Protocol: unix.RTPROT_STATIC}
		if family == netlink.FAMILY_V6 {
			route.Dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		}
		if err := handle.RouteReplace(route); err != nil {
			return err
		}
	}
	return nil
}

func setupLoopback(pid int) error {
	target, err := netns.GetFromPid(pid)
	if err != nil {
		return err
	}
	defer target.Close()
	handle, err := netlink.NewHandleAt(target, routeNetlinkFamilies()...)
	if err != nil {
		return err
	}
	defer handle.Close()
	return setupLoopbackWithHandle(handle)
}

func setupLoopbackWithHandle(handle *netlink.Handle) error {
	loopback, err := handle.LinkByName("lo")
	if err != nil {
		return err
	}
	return handle.LinkSetUp(loopback)
}

func setSysctls(target netns.NsHandle, ifName string, assignments []string) error {
	if len(assignments) == 0 {
		return nil
	}
	runtime.LockOSThread()
	restored := false
	defer func() {
		// A goroutine that exits while still locked causes Go to retire the OS
		// thread. Do not return a thread in the workload namespace to the pool if
		// restoring the init namespace fails.
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	original, err := netns.Get()
	if err != nil {
		return fmt.Errorf("open init network namespace: %w", err)
	}
	defer original.Close()
	if err := netns.Set(target); err != nil {
		return fmt.Errorf("enter workload network namespace: %w", err)
	}
	applyError := applySysctls(ifName, assignments)
	restoreError := netns.Set(original)
	if restoreError != nil {
		return fmt.Errorf("restore init network namespace: %w", restoreError)
	}
	restored = true
	return applyError
}

func applySysctls(ifName string, assignments []string) error {
	for _, assignment := range assignments {
		path, value, err := endpointSysctlPath(ifName, assignment)
		if err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a sysctl file", path)
		}
		current, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read endpoint sysctl %s: %w", path, err)
		}
		if strings.TrimSpace(string(current)) == value {
			continue
		}
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			return fmt.Errorf("write endpoint sysctl %s: %w", path, err)
		}
	}
	return nil
}

func endpointSysctlPath(ifName, assignment string) (string, string, error) {
	if !validSysctlComponent(ifName) {
		return "", "", fmt.Errorf("invalid endpoint interface name %q", ifName)
	}
	name, value, found := strings.Cut(assignment, "=")
	parts := strings.Split(name, ".")
	if !found || len(parts) != 5 || parts[0] != "net" ||
		(parts[1] != "ipv4" && parts[1] != "ipv6" && parts[1] != "mpls") ||
		!strings.EqualFold(parts[3], "IFNAME") {
		return "", "", fmt.Errorf("invalid endpoint sysctl %q", assignment)
	}
	for _, part := range parts {
		if !validSysctlComponent(part) {
			return "", "", fmt.Errorf("invalid endpoint sysctl %q", assignment)
		}
	}
	if strings.ContainsAny(value, "\x00\n") {
		return "", "", fmt.Errorf("invalid endpoint sysctl value for %s", name)
	}
	parts[3] = ifName
	return filepath.Join(append([]string{"/proc/sys"}, parts...)...), value, nil
}

func validSysctlComponent(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func temporaryLinkName(pid int, vlan uint16) string {
	return fmt.Sprintf("ce%08x%03x", uint32(pid), vlan)
}

func routeNetlinkFamilies() []int { return []int{unix.NETLINK_ROUTE} }
