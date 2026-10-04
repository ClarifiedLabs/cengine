package storageservice

import (
	pc "dev.cengine/guest/internal/preparecompat"
	"strings"
	"testing"
)

func TestWorkerExitServiceUnarmedFailClosed(t *testing.T) {
	f := newFixture(t)
	q := pc.StorageQuery{Version: 3, Profile: pc.FullProfile, RequestID: string(id(t)), ArmDigest: strings.Repeat("a", 64), WorkerUUID: string(id(t))}
	for _, stage := range []string{"admitted-queued", "full-frame-before-admit", "drain-durable-reply-lost", "normal"} {
		if _, err := f.s.ClaimPrepareCompatibilityWorkerExit(pc.StorageRelease{Query: q, Stage: stage, Token: strings.Repeat("e", 64)}); err == nil {
			t.Fatal("unarmed claim", stage)
		}
	}
}
