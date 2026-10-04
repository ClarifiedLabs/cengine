package workloadstorage

import (
	"encoding/json"
	"reflect"
	"testing"

	cc "dev.cengine/guest/internal/consumercompat"
	w "dev.cengine/guest/internal/storagewire"
)

// Genuine retained Client/TLS/FIFO, simulated mount attestation and wire peer.
// Does not claim ROOT authorization, mounted FUSE, or native acceptance.
func TestRecoveredOriginalPositiveUsesRetainedFIFO(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile")
	}
	for _, fault := range []string{"valid", "unbegun", "closed", "expired", "wrong-case", "remote-close"} {
		t.Run(fault, func(t *testing.T) {
			name := cc.SameE
			if fault == "wrong-case" {
				name = "delayed-registration"
			}
			s, arm, f, client, requests, _ := sameEClientSession(t, name, false, fault != "remote-close")
			raw, _ := json.Marshal(arm)
			var prior OriginalConsumerEvidence
			if fault == "unbegun" {
				response, err := s.originalConsumerControl("original-consumer-arm", raw)
				if err != nil || json.Unmarshal(response, &prior) != nil {
					t.Fatal("arm", err)
				}
			} else {
				prior = armSameE(t, s, arm)
			}
			first := <-requests
			if fault == "closed" {
				client.Close()
			}
			if fault == "expired" {
				f.observer.cancel()
			}
			response, err := s.originalConsumerControl("original-consumer-positive", raw)
			if fault != "valid" {
				if err == nil || !f.observer.stopped {
					t.Fatal("invalid positive accepted", fault)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var actual OriginalConsumerEvidence
			if originalDecode(response, &actual) != nil {
				t.Fatal("shape")
			}
			second := <-requests
			body, ok := second.Body.(w.GetAttrRequest)
			if !ok || uint64(body.Node) != prior.RootRequest.Node || body.Handle != nil || second.Auth.Kind != w.NodeMetadataAuth || second.Sequence <= first.Sequence || actual.RootRequest.RequestSequence != second.Sequence {
				t.Fatal("not exact retained FIFO GETATTR")
			}
			expected := prior
			expected.Stage = "original-data-positive"
			expected.RootRequest = &OriginalRootRequest{Node: prior.RootRequest.Node, RequestSequence: second.Sequence}
			expected.OriginalOperation.Sequence = 2
			if !reflect.DeepEqual(expected, actual) {
				t.Fatal("nonmatching success", actual)
			}
			deadline, ok := f.observer.ctx.Deadline()
			if !ok {
				t.Fatal("missing original budget")
			}
			if _, err = s.originalConsumerControl("original-consumer-positive", raw); err == nil {
				t.Fatal("second operation admitted")
			}
			after, _ := f.observer.ctx.Deadline()
			if after != deadline {
				t.Fatal("deadline renewed")
			}
			if _, err = s.originalConsumerControl("original-consumer-release", raw); err != nil || !f.observer.stopped {
				t.Fatal("release did not join", err)
			}
		})
	}
}
