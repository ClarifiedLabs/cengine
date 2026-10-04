package storagepki

import (
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func TestLifecycleServiceStateValidation(t *testing.T) {
	fixture := buildLifecycleChildServiceFixture(t)
	result := *fixture.Vectors[0].Reply.ServiceResult
	boot := *fixture.Vectors[0].Challenge.Boot
	state, err := LifecycleServiceStateFromResult(result, boot)
	if err != nil || state.Validate() != nil {
		t.Fatal("valid state", err)
	}
	for name, mutate := range map[string]func(*LifecycleServiceState){
		"grant":              func(s *LifecycleServiceState) { s.Grant.Serial = 0 },
		"retire":             func(s *LifecycleServiceState) { s.Grant.Operation = a.LifecycleRetire },
		"epoch_zero":         func(s *LifecycleServiceState) { s.Context.ControllerEpoch = 0 },
		"epoch_wrong":        func(s *LifecycleServiceState) { s.Context.ControllerEpoch-- },
		"key_invalid":        func(s *LifecycleServiceState) { s.Context.ControllerKey = strings.Repeat("A", 64) },
		"key_wrong":          func(s *LifecycleServiceState) { s.Context.ControllerKey = s.Boot.ServerSPKI },
		"service_invalid":    func(s *LifecycleServiceState) { s.Context.ServiceEpoch = "bad" },
		"service_wrong":      func(s *LifecycleServiceState) { s.Context.ServiceEpoch = string(s.Grant.ID) },
		"open_zero":          func(s *LifecycleServiceState) { s.OpenRevision = 0 },
		"boot_invalid":       func(s *LifecycleServiceState) { s.Boot.TLSRootSHA256 = "bad" },
		"identity_wrong":     func(s *LifecycleServiceState) { s.Boot.Identity.Generation++ },
		"root_is_controller": func(s *LifecycleServiceState) { s.Boot.BootstrapKey = s.Context.ControllerKey },
	} {
		t.Run(name, func(t *testing.T) {
			bad := state
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
	for _, mutate := range []func(*a.LifecycleServiceResult){
		func(r *a.LifecycleServiceResult) { r.Identity.Generation++ },
		func(r *a.LifecycleServiceResult) { r.Nonce = nil },
		func(r *a.LifecycleServiceResult) { r.OpenRevision = 0 },
		func(r *a.LifecycleServiceResult) { r.Grant.Operation = a.LifecycleRetire },
	} {
		bad := result
		mutate(&bad)
		got, err := LifecycleServiceStateFromResult(bad, boot)
		if err == nil || got != (LifecycleServiceState{}) {
			t.Fatal("invalid result converted")
		}
	}
	wrongBoot := boot
	wrongBoot.Identity.Generation++
	if _, err := LifecycleServiceStateFromResult(result, wrongBoot); err == nil {
		t.Fatal("wrong boot converted")
	}
	// Both active grant operations and the upper epoch boundary match Swift.
	result.Grant.Operation = a.LifecycleInitialize
	result.Grant.ExpectedEpoch = 0
	result.ControllerEpoch = 1
	if _, err := LifecycleServiceStateFromResult(result, boot); err != nil {
		t.Fatal("initialize state", err)
	}
	if (LifecycleServiceContext{}).Validate() == nil || (LifecycleServiceState{}).Validate() == nil {
		t.Fatal("zero value accepted")
	}
}

func TestLifecycleServiceChangeValidation(t *testing.T) {
	confirmation := *buildLifecycleChildServiceFixture(t).Vectors[2].Challenge.Confirmation
	request := confirmation.Request
	if request.Validate() != nil || request.ValidateSuccessorBoot(confirmation.Successor.Boot) != nil || confirmation.Validate() != nil {
		t.Fatal("valid change rejected")
	}
	for name, mutate := range map[string]func(*LifecycleBootTrustFields){
		"invalid":       func(b *LifecycleBootTrustFields) { b.ServerSPKI = "bad" },
		"store":         func(b *LifecycleBootTrustFields) { b.Identity.Store = a.ID(request.OperationID) },
		"generation":    func(b *LifecycleBootTrustFields) { b.Identity.Generation++ },
		"binding":       func(b *LifecycleBootTrustFields) { b.Identity.Binding = a.Fingerprint(b.ServerSPKI) },
		"root":          func(b *LifecycleBootTrustFields) { b.BootstrapKey = b.ServerSPKI },
		"epoch_reused":  func(b *LifecycleBootTrustFields) { b.ServiceEpoch = request.Predecessor.Boot.ServiceEpoch },
		"ca_reused":     func(b *LifecycleBootTrustFields) { b.TLSRootSHA256 = request.Predecessor.Boot.TLSRootSHA256 },
		"server_reused": func(b *LifecycleBootTrustFields) { b.ServerSPKI = request.Predecessor.Boot.ServerSPKI },
	} {
		t.Run(name, func(t *testing.T) {
			boot := confirmation.Successor.Boot
			mutate(&boot)
			if request.ValidateSuccessorBoot(boot) == nil {
				t.Fatal("invalid successor boot accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*LifecycleServiceChangeConfirmation){
		"operation_id": func(c *LifecycleServiceChangeConfirmation) { c.Request.OperationID = "invalid" },
		"predecessor":  func(c *LifecycleServiceChangeConfirmation) { c.Request.Predecessor.OpenRevision = 0 },
		"successor":    func(c *LifecycleServiceChangeConfirmation) { c.Successor.Context.ControllerEpoch = 0 },
		"grant":        func(c *LifecycleServiceChangeConfirmation) { c.Successor.Grant.Serial-- },
		"controller_epoch": func(c *LifecycleServiceChangeConfirmation) {
			c.Successor.Grant.ExpectedEpoch--
			c.Successor.Context.ControllerEpoch--
		},
		"controller_key": func(c *LifecycleServiceChangeConfirmation) {
			c.Successor.Grant.NewKey = c.Successor.Grant.Identity.Binding
			c.Successor.Context.ControllerKey = string(c.Successor.Grant.NewKey)
		},
		"same_revision": func(c *LifecycleServiceChangeConfirmation) {
			c.Successor.OpenRevision = c.Request.Predecessor.OpenRevision
		},
		"older_revision": func(c *LifecycleServiceChangeConfirmation) {
			c.Successor.OpenRevision = c.Request.Predecessor.OpenRevision - 1
		},
		"exhausted_revision": func(c *LifecycleServiceChangeConfirmation) { c.Request.Predecessor.OpenRevision = ^uint64(0) },
		"unchanged":          func(c *LifecycleServiceChangeConfirmation) { c.Successor = c.Request.Predecessor },
	} {
		t.Run(name, func(t *testing.T) {
			bad := confirmation
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("invalid confirmation accepted")
			}
		})
	}
	if (LifecycleServiceChangeRequest{}).Validate() == nil || (LifecycleServiceChangeConfirmation{}).Validate() == nil {
		t.Fatal("zero change accepted")
	}
	if (LifecycleServiceChangeRequest{}).ValidateSuccessorBoot(confirmation.Successor.Boot) == nil {
		t.Fatal("zero request accepted successor")
	}
}
