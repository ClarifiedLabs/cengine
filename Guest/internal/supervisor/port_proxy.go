//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"

	"dev.cengine/guest/internal/protocol"
	"github.com/vishvananda/netns"
)

// DialPublishedPort opens a connection from the workload's network namespace.
// The returned descriptor remains attached to that namespace after this thread
// restores the init process's namespace.
func (s *Supervisor) DialPublishedPort(transport string, port uint16, ipv6 bool) (net.Conn, error) {
	if transport != "tcp" && transport != "udp" {
		return nil, fmt.Errorf("unsupported port transport %q", transport)
	}
	if port == 0 {
		return nil, errors.New("published port must be nonzero")
	}

	s.mu.Lock()
	if s.command == nil || s.command.Process == nil || s.spec == nil || s.status.Status != "running" {
		s.mu.Unlock()
		return nil, errors.New("workload is not running")
	}
	pid := s.command.Process.Pid
	address := publishedPortAddress(s.spec.Networks, ipv6)
	s.mu.Unlock()

	family := "4"
	if ipv6 {
		family = "6"
	}
	return dialInNetworkNamespace(pid, transport+family, net.JoinHostPort(address, strconv.Itoa(int(port))))
}

func publishedPortAddress(endpoints []protocol.NetworkEndpoint, ipv6 bool) string {
	for _, endpoint := range endpoints {
		for _, value := range endpoint.Addresses {
			address, _, err := net.ParseCIDR(value)
			if err != nil || (address.To4() == nil) != ipv6 {
				continue
			}
			return address.String()
		}
	}
	if ipv6 {
		return "::1"
	}
	return "127.0.0.1"
}

func dialInNetworkNamespace(pid int, network, address string) (net.Conn, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("open init network namespace: %w", err)
	}
	defer original.Close()
	target, err := netns.GetFromPid(pid)
	if err != nil {
		return nil, fmt.Errorf("open workload network namespace: %w", err)
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		return nil, fmt.Errorf("enter workload network namespace: %w", err)
	}

	connection, dialError := net.Dial(network, address)
	if err := netns.Set(original); err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, fmt.Errorf("restore init network namespace: %w", err)
	}
	return connection, dialError
}
