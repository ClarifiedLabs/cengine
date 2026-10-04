// Package storageauthoritytest provisions real signed lifecycle authorities for tests.
// Fixture is trusted test-owner state; persist it in crash manifests, never reconstruct
// its grant or open anchor from the registry under test.
package storageauthoritytest

import (
	"crypto/ed25519"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

type Fixture struct {
	Current  a.SignedLifecycleGrant
	Expected a.ExpectedLifecycleStartup
}

func New(t testing.TB, bootstrap ed25519.PrivateKey, store a.ID, controller a.Fingerprint) *Fixture {
	t.Helper()
	id, err := a.NewID()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := a.PublicKeyFingerprint(bootstrap.Public())
	if err != nil {
		t.Fatal(err)
	}
	grant := a.LifecycleGrant{Operation: a.LifecycleInitialize, ID: id, Identity: a.LifecycleIdentity{Store: store, Generation: 1, Binding: binding}, Serial: 1, NewKey: controller}
	data, err := a.LifecycleGrantSigningBytes(grant)
	if err != nil {
		t.Fatal(err)
	}
	return &Fixture{Current: a.SignedLifecycleGrant{Grant: grant, Signature: ed25519.Sign(bootstrap, data)}}
}

// Capture records only a successfully admitted live owner's open anchor. The
// signed grant remains the fixture owner's original input, not disk-derived trust.
func (f *Fixture) Capture(owner *a.Authority) error {
	m, err := owner.LifecycleMetadata()
	if err != nil {
		return err
	}
	if m.CurrentGrant != f.Current.Grant {
		return a.ErrConflict
	}
	f.Expected = a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: m.Store.ID, Epoch: m.Epoch, Controller: m.Controller}, OpenRevision: m.OpenRevision}
	return nil
}
func (f *Fixture) capture(owner *a.Authority, err error) (*a.Authority, error) {
	if err != nil {
		return owner, err
	}
	if err = f.Capture(owner); err != nil {
		_ = owner.Close()
		return nil, err
	}
	return owner, nil
}
func (f *Fixture) Initialize(c a.Config) (*a.Authority, error) {
	return f.capture(a.InitializeLifecycle(c, f.Current))
}
func (f *Fixture) Open(c a.Config) (*a.Authority, error) {
	return f.capture(a.OpenLifecycleCurrent(c, f.Current))
}
func (f *Fixture) OpenExpected(c a.Config, expected a.ExpectedStartup) (*a.Authority, error) {
	return f.capture(a.OpenLifecycleExpected(c, f.Current, a.ExpectedLifecycleStartup{ExpectedStartup: expected, OpenRevision: f.Expected.OpenRevision}))
}
