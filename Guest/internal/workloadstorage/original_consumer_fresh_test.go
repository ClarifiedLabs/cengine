package workloadstorage

import (
	w "dev.cengine/guest/internal/storagewire"
	"encoding/json"
	"testing"
)

// Fresh-start host orchestration uses this exact positive-only Arm/Release.
// Real TLS/FIFO GETATTR, not host fixture stat or directory fsync as proof.
func TestOriginalConsumerFreshPositiveOnlyActualWire(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile only")
	}
	s, arm, f, _, requests, _ := sameEClientSession(t, "same-e-existing-data")
	raw, _ := json.Marshal(arm)
	response, err := s.originalConsumerControl("original-consumer-arm", raw)
	if err != nil {
		t.Fatal(err)
	}
	var value OriginalConsumerEvidence
	if err := json.Unmarshal(response, &value); err != nil {
		t.Fatal(err)
	}
	request := <-requests
	body, ok := request.Body.(w.GetAttrRequest)
	if !ok || body.Handle != nil || request.Auth.Kind != w.NodeMetadataAuth {
		t.Fatalf("not GETATTR: %+v", request)
	}
	if value.RootRequest == nil || value.RootRequest.RequestSequence != request.Sequence || value.RootRequest.Node == 0 || value.RootRequest.Node != uint64(body.Node) || value.OriginalOperation != (OriginalOperation{Kind: "data-getattr-root", Sequence: 1, ErrorClass: "ok"}) || value.Stage != "armed-mounted-positive" {
		t.Fatalf("not actual root GETATTR: %+v / %+v", request, value)
	}
	if _, err := s.originalConsumerControl("original-consumer-release", raw); err != nil {
		t.Fatal(err)
	}
	if !f.observer.stopped || f.observer.file != nil || f.observer.attachment != nil {
		t.Fatal("positive-only release did not join/clear owner")
	}
	if _, err := s.originalConsumerControl("original-consumer-begin", raw); err == nil {
		t.Fatal("released positive reused")
	}
}
