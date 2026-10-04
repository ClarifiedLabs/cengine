//go:build linux

package main

import (
	"encoding/json"
	"testing"

	"dev.cengine/guest/internal/protocol"
)

func TestOriginalConsumerCommandsNeverFallThroughOrdinaryAdmission(t *testing.T) {
	// A nil process panics if these commands accidentally fall into ordinary
	// process admission. No managed owner means fail closed, even in full builds.
	state := &controlServer{}
	for _, operation := range []string{"original-consumer-arm", "original-consumer-begin", "original-consumer-probe", "original-consumer-result", "original-consumer-release", "original-consumer-positive", "original-consumer-resume"} {
		if _, err := state.handle(protocol.Envelope{Operation: operation, Payload: json.RawMessage(`{}`)}); err == nil {
			t.Fatalf("accepted unowned %s", operation)
		}
	}
}
