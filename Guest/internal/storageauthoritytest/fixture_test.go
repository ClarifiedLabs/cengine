package storageauthoritytest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func TestFixtureRetainsTrustedGrantAndConsumedOpenAnchor(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, rootKey, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	controller, _, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	pin, err := a.PublicKeyFingerprint(controller)
	must(err)
	store, err := a.NewID()
	must(err)
	path := t.TempDir()
	must(os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	must(err)
	defer root.Close()
	config := a.Config{Root: root, DeviceID: "signed-test-fixture", BootstrapKey: rootKey.Public().(ed25519.PublicKey), Barrier: func(a.Binding, *os.File) error { return nil }}
	fixture := New(t, rootKey, store, pin)
	owner, err := fixture.Initialize(config)
	must(err)
	original := fixture.Expected
	must(owner.Close())
	// Model a crash handoff using only trusted fixture state, not state.json.
	data, err := json.Marshal(fixture)
	must(err)
	var restored Fixture
	must(json.Unmarshal(data, &restored))
	wrong := restored
	wrong.Current.Signature = make([]byte, ed25519.SignatureSize)
	if got, err := wrong.Open(config); got != nil || !errors.Is(err, a.ErrUnauthorized) {
		t.Fatal("unsigned fixture opened", err)
	}
	owner, err = restored.OpenExpected(config, original.ExpectedStartup)
	must(err)
	if restored.Expected.Epoch == original.Epoch || restored.Expected.OpenRevision <= original.OpenRevision || restored.Current.Grant != fixture.Current.Grant {
		t.Fatal("lost current grant or fresh open anchor")
	}
	must(owner.Close())
	if got, err := fixture.OpenExpected(config, original.ExpectedStartup); got != nil || !errors.Is(err, a.ErrConflict) {
		t.Fatal("consumed predecessor reopened", err)
	}
	owner, err = restored.Open(config)
	must(err)
	must(owner.Close())
}
