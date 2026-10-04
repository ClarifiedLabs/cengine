package storageauthority

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLifecycleServiceResultLiveOpenAndStableAppliedResult(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	nonce := bytes.Repeat([]byte{1}, 32)
	applied, err := f.a.LifecycleResult(f.control, initial.Grant, nonce)
	must(t, err)
	live, err := f.a.LifecycleServiceResult(f.control, initial.Grant, nonce)
	must(t, err)
	if live.OpenRevision != 1 || live.ServiceEpoch != applied.ServiceEpoch {
		t.Fatal("initialize did not publish live anchor with E")
	}
	nonce[0]++
	if live.Nonce[0] != 1 {
		t.Fatal("nonce was not detached")
	}
	f.volume("live-result")
	_, err = f.a.Query(f.control)
	must(t, err)
	again, err := f.a.LifecycleServiceResult(f.control, initial.Grant, live.Nonce)
	must(t, err)
	if !reflect.DeepEqual(live, again) || f.a.s.Revision <= live.OpenRevision {
		t.Fatal("ordinary workload changed open anchor")
	}

	expected := expectedLifecycleStartup(f)
	beforeRevision := f.a.s.Revision
	must(t, f.a.Close())
	f.a, err = OpenLifecycleExpected(f.c, initial, expected)
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	stable, err := f.a.LifecycleResult(f.control, initial.Grant, live.Nonce)
	must(t, err)
	if !reflect.DeepEqual(stable, applied) {
		t.Fatal("reopen rewrote the stable applied result")
	}
	fresh, err := f.a.LifecycleServiceResult(f.control, initial.Grant, nonce)
	must(t, err)
	if fresh.ServiceEpoch == stable.ServiceEpoch || fresh.ServiceEpoch != f.a.Epoch() || fresh.OpenRevision != beforeRevision+1 || fresh.OpenRevision != f.a.s.Revision {
		t.Fatal("reopen did not publish new E/open revision")
	}
	persisted, err := f.a.j.load()
	must(t, err)
	if persisted.Epoch != fresh.ServiceEpoch || persisted.Lifecycle.OpenRevision != fresh.OpenRevision {
		t.Fatal("open anchor was not persisted with E")
	}

	key := newKey(t)
	g := LifecycleGrant{LifecycleTakeover, mustID(t), initial.Grant.Identity, initial.Grant.Serial + 1, 1, fp(t, key)}
	successor, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
	must(t, err)
	_, err = f.a.TakeoverLifecycle(successor, signLifecycle(t, f.bootstrap, g))
	must(t, err)
	_, err = f.a.LifecycleServiceResult(f.control, initial.Grant, nonce)
	wantErr(t, err, ErrUnauthorized)
	f.control = f.authControl(key, 2)
	after, err := f.a.LifecycleServiceResult(f.control, g, nonce)
	must(t, err)
	if after.OpenRevision != fresh.OpenRevision || after.ServiceEpoch != fresh.ServiceEpoch || after.ControllerEpoch != 2 || after.ControllerKey != g.NewKey {
		t.Fatal("takeover changed open anchor or lost controller binding")
	}
}

func TestLifecycleServiceResultAdmission(t *testing.T) {
	f, initial := newLifecycleFixture(t)
	nonce := make([]byte, 32)
	for _, change := range []func(*LifecycleGrant){
		func(g *LifecycleGrant) { g.ID = mustID(t) },
		func(g *LifecycleGrant) { g.Identity.Store = mustID(t) },
		func(g *LifecycleGrant) { g.Identity.Generation++ },
		func(g *LifecycleGrant) { g.Identity.Binding = g.NewKey },
		func(g *LifecycleGrant) { g.Serial++ },
		func(g *LifecycleGrant) { g.ExpectedEpoch++ },
		func(g *LifecycleGrant) { g.NewKey = fp(t, newKey(t)) },
		func(g *LifecycleGrant) { g.Operation = LifecycleRetire },
	} {
		g := initial.Grant
		change(&g)
		_, err := f.a.LifecycleServiceResult(f.control, g, nonce)
		wantErr(t, err, ErrUnauthorized)
	}
	for _, p := range []*ControllerPrincipal{nil, {}, {owner: f.a, epoch: 2, key: initial.Grant.NewKey}, {owner: f.a, epoch: 1, key: fp(t, newKey(t))}} {
		_, err := f.a.LifecycleServiceResult(p, initial.Grant, nonce)
		wantErr(t, err, ErrUnauthorized)
	}
	for _, size := range []int{0, 31, 33} {
		_, err := f.a.LifecycleServiceResult(f.control, initial.Grant, make([]byte, size))
		wantErr(t, err, ErrInvalid)
	}
	for name, change := range map[string]func(){
		"poisoned":      func() { f.a.fault = ErrBlocked },
		"retiring":      func() { g := lifecycleRetirement(t, f).Grant; f.a.s.Lifecycle.Retiring = &g },
		"sealed":        func() { f.a.s.Lifecycle.Seal = &lifecycleApplied{} },
		"closed":        func() { f.a.closed = true },
		"zero-anchor":   func() { f.a.s.Lifecycle.OpenRevision = 0 },
		"future-anchor": func() { f.a.s.Lifecycle.OpenRevision = f.a.s.Revision + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			before := f.a.clone()
			change()
			if _, err := f.a.LifecycleServiceResult(f.control, initial.Grant, nonce); err == nil {
				t.Fatal("unavailable owner returned live result")
			}
			f.a.s = before
			f.a.fault = nil
			f.a.closed = false
		})
	}
}

func TestLifecycleOpenRevisionRequiredOnDisk(t *testing.T) {
	for _, kind := range []string{"absent", "zero", "future"} {
		t.Run(kind, func(t *testing.T) {
			f, initial := newLifecycleFixture(t)
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName, stateName)
			b, err := os.ReadFile(path)
			must(t, err)
			var state map[string]json.RawMessage
			must(t, json.Unmarshal(b, &state))
			var life map[string]json.RawMessage
			must(t, json.Unmarshal(state["lifecycle"], &life))
			switch kind {
			case "absent":
				delete(life, "open_revision")
			case "zero":
				life["open_revision"] = json.RawMessage(`0`)
			case "future":
				life["open_revision"] = json.RawMessage(`18446744073709551615`)
			}
			state["lifecycle"], err = json.Marshal(life)
			must(t, err)
			b, err = json.Marshal(state)
			must(t, err)
			must(t, os.WriteFile(path, b, 0600))
			before := lifecycleFiles(t, f)
			for _, open := range []func() (*Authority, error){func() (*Authority, error) { return OpenLifecycle(f.c, initial.Grant.Identity) }, func() (*Authority, error) { return OpenLifecycleCurrent(f.c, initial) }} {
				got, err := open()
				wantErr(t, err, ErrInvalid)
				if got != nil {
					t.Fatal("invalid disk state admitted")
				}
				if !reflect.DeepEqual(before, lifecycleFiles(t, f)) {
					t.Fatal("rejected old schema was repaired")
				}
			}
		})
	}
}
