//go:build !cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat

package storageserver

import (
	"context"
	"net"
	"testing"
)

const tlsFailureTestEnabled = false

func TestTLSFailureOrdinaryBuildInert(t *testing.T) {
	ctx := context.Background()
	if WithTLSFailureObservation(ctx) != ctx {
		t.Fatal("ordinary build modifies context")
	}
	raw, other := net.Pipe()
	defer raw.Close()
	defer other.Close()
	transport, observation := (&Server{}).observeTLSFailure(ctx, raw)
	if transport != raw || observation != nil {
		t.Fatal("ordinary build captures reads")
	}
}
