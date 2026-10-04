package storagecontrol

import (
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func TestWorkloadZeroPolicyRejectsAdmission(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	policy := workloadPolicy{}
	if policy.validHello(Hello{Version: 2, Role: Controller, ControllerEpoch: 1, Store: f.initial.Grant.Identity.Store, ServiceEpoch: f.authority.Epoch()}) || policy.matchesIdentity(nil) || policy.validSnapshot(&a.Snapshot{Schema: a.SchemaVersion, Revision: 1}) {
		t.Fatal("zero policy admitted a hello, identity, or snapshot")
	}
	if _, err := newPKIServer(f.authority, workloadPKIServerConfig{}, policy); err != ErrConfiguration {
		t.Fatalf("zero policy constructed server: %v", err)
	}
}
