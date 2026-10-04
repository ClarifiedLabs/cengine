package storageauthority

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
)

func lifecycleReserve(t *testing.T, f *fixture, name string) ID {
	t.Helper()
	v := f.volume(name)
	prep := mustID(t)
	b, _ := f.binding(v, PrepareRole, ReadWrite, prep)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), prep, []Binding{b}}))
	return prep
}

func queriedContext(t *testing.T, f *fixture, prep ID) PrepareContext {
	t.Helper()
	s, err := f.a.Query(f.control)
	must(t, err)
	p, ok := s.Prepares[prep]
	if !ok || p.Context == nil {
		t.Fatal("snapshot lacks owning prepare context")
	}
	// Snapshot isolation: mutating the attested copy cannot change authority.
	p.Context.ControllerEpoch = 99
	if f.a.s.Prepares[prep].Context.ControllerEpoch == 99 {
		t.Fatal("snapshot aliases authority context")
	}
	b, err := json.Marshal(s.Prepares[prep])
	must(t, err)
	var wire map[string]json.RawMessage
	must(t, json.Unmarshal(b, &wire))
	var c map[string]json.RawMessage
	must(t, json.Unmarshal(wire["context"], &c))
	if len(c) != 3 || c["service_epoch"] == nil || c["controller_epoch"] == nil || c["controller_key"] == nil {
		t.Fatal("non-canonical context wire shape", string(b))
	}
	return *f.a.s.Prepares[prep].Context
}

// E1/C1 prepare survives service change (reopen: E2) and takeover (C2); Query
// attests both the historical and the current owning contexts.
func TestLifecyclePrepareContextAttestedAcrossServiceChangeAndTakeover(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	e1, c1 := f.a.s.Epoch, f.a.s.Controller
	first := lifecycleReserve(t, f, "first")
	if got := queriedContext(t, f, first); got != (PrepareContext{e1, c1.Epoch, c1.Key}) {
		t.Fatal("wrong reserve context", got)
	}
	must(t, f.a.Close())
	var err error
	f.a, err = OpenLifecycle(f.c, initial.Grant.Identity)
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	e2 := f.a.s.Epoch
	if e2 == e1 {
		t.Fatal("reopen did not change service epoch")
	}
	if got := queriedContext(t, f, first); got != (PrepareContext{e1, c1.Epoch, c1.Key}) {
		t.Fatal("service change rewrote historical context", got)
	}
	key := newKey(t)
	g := LifecycleGrant{LifecycleTakeover, mustID(t), initial.Grant.Identity, f.a.s.Lifecycle.Latest.Grant.Serial + 1, 1, fp(t, key)}
	p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	_, err = f.a.TakeoverLifecycle(p, signLifecycle(t, f.bootstrap, g))
	must(t, err)
	f.control = f.authControl(key, 2)
	second := lifecycleReserve(t, f, "second")
	must(t, f.a.Close())
	f.a, err = OpenLifecycle(f.c, initial.Grant.Identity)
	must(t, err)
	f.control = f.authControl(key, 2)
	if got := queriedContext(t, f, first); got != (PrepareContext{e1, c1.Epoch, c1.Key}) {
		t.Fatal("takeover/reopen rewrote historical context", got)
	}
	if got := queriedContext(t, f, second); got != (PrepareContext{e2, 2, fp(t, key)}) {
		t.Fatal("wrong post-takeover context", got)
	}
	must(t, f.a.validate())
}

// The context is bounded to its record and must be present and consistent with
// the controller chain in registry schema 4.
func TestLifecyclePrepareContextValidation(t *testing.T) {
	f, _ := newLifecycleFixture(t)
	prep := lifecycleReserve(t, f, "validate")
	good := f.a.s.Prepares[prep]
	for name, mutate := range map[string]func(*PrepareContext) *PrepareContext{
		"missing":      func(*PrepareContext) *PrepareContext { return nil },
		"future":       func(c *PrepareContext) *PrepareContext { c.ControllerEpoch++; return c },
		"zero":         func(c *PrepareContext) *PrepareContext { c.ControllerEpoch = 0; return c },
		"bad-epoch":    func(c *PrepareContext) *PrepareContext { c.ServiceEpoch = "x"; return c },
		"bad-key":      func(c *PrepareContext) *PrepareContext { c.ControllerKey = "zz"; return c },
		"current-key":  func(c *PrepareContext) *PrepareContext { c.ControllerKey = fp(t, newKey(t)); return c },
		"bootstrapkey": func(c *PrepareContext) *PrepareContext { c.ControllerKey = f.a.s.Bootstrap; return c },
	} {
		c := *good.Context
		bad := good
		bad.Context = mutate(&c)
		f.a.s.Prepares[prep] = bad
		if f.a.validate() == nil {
			t.Fatal("accepted", name)
		}
	}
	f.a.s.Prepares[prep] = good
	must(t, f.a.validate())

	// A retired registry envelope is invalid regardless of PREPARE context.
	f.a.s.Schema = SchemaVersion
	if f.a.validate() == nil {
		t.Fatal("accepted retired schema with lifecycle context")
	}
	good.Context = nil
	f.a.s.Prepares[prep] = good
	if f.a.validate() == nil {
		t.Fatal("accepted retired schema without lifecycle context")
	}
}
