//go:build linux

package supervisor

import (
	"testing"

	"dev.cengine/guest/internal/protocol"
)

func TestPublishedPortAddressUsesWorkloadEndpointFamily(t *testing.T) {
	endpoints := []protocol.NetworkEndpoint{{
		Addresses: []string{"10.240.1.9/24", "fd00:cafe::9/64"},
	}}
	if got := publishedPortAddress(endpoints, false); got != "10.240.1.9" {
		t.Fatalf("publishedPortAddress(v4) = %q, want 10.240.1.9", got)
	}
	if got := publishedPortAddress(endpoints, true); got != "fd00:cafe::9" {
		t.Fatalf("publishedPortAddress(v6) = %q, want fd00:cafe::9", got)
	}
}

func TestPublishedPortAddressFallsBackToLoopback(t *testing.T) {
	if got := publishedPortAddress(nil, false); got != "127.0.0.1" {
		t.Fatalf("publishedPortAddress(v4) = %q, want loopback", got)
	}
	if got := publishedPortAddress(nil, true); got != "::1" {
		t.Fatalf("publishedPortAddress(v6) = %q, want loopback", got)
	}
}
