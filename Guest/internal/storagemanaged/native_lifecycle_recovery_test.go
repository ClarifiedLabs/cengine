package storagemanaged

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageauthoritytest"
)

// Neither identity nor signed-current alone can discharge schema-4 recovery
// evidence. The caller checks its complete held census and external ACK after
// each refusal, before any exact open is permitted to mutate the journal.
func lifecycleRecoveryRefuseUnanchored(t *testing.T, cfg a.Config, trust *storageauthoritytest.Fixture, unchanged func()) {
	t.Helper()
	before := *trust
	for _, call := range []func() (*a.Authority, error){
		func() (*a.Authority, error) { return a.OpenLifecycle(cfg, trust.Current.Grant.Identity) },
		func() (*a.Authority, error) { return trust.Open(cfg) },
	} {
		owner, err := call()
		if owner != nil {
			_ = owner.Close()
			t.Fatal("unanchored recovery returned an authority")
		}
		if !errors.Is(err, a.ErrRepairRequired) {
			t.Fatalf("unanchored recovery: want repair-required, got %v", err)
		}
		if !reflect.DeepEqual(before, *trust) {
			t.Fatal("refused open changed trusted fixture anchors")
		}
		unchanged()
	}
}

// Fixture.OpenExpected captures only the successfully admitted owner's fresh
// E/OpenRevision. Never derive either trust anchor from the disk being recovered.
func lifecycleRecoveryOpenExact(t *testing.T, cfg a.Config, trust *storageauthoritytest.Fixture) *a.Authority {
	t.Helper()
	before := trust.Expected
	owner, err := trust.OpenExpected(cfg, before.ExpectedStartup)
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil {
		t.Fatal("exact open returned no authority")
	}
	if trust.Expected.Epoch == before.Epoch || trust.Expected.OpenRevision <= before.OpenRevision {
		_ = owner.Close()
		t.Fatal("exact open did not capture fresh E/OpenRevision")
	}
	return owner
}

// Host-only contract coverage, not native barrier/process-death evidence.
func TestLifecycleRecoveryFixtureAnchors(t *testing.T) {
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	controller, _, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	pin, err := a.PublicKeyFingerprint(controller)
	check(err)
	store, err := a.NewID()
	check(err)
	path := t.TempDir()
	check(os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	check(err)
	defer root.Close()
	cfg := a.Config{Root: root, DeviceID: "recovery-fixture-host", BootstrapKey: public, Barrier: func(a.Binding, *os.File) error {
		t.Error("startup invoked barrier")
		return a.ErrBlocked
	}}
	trust := storageauthoritytest.New(t, private, store, pin)
	owner, err := trust.Initialize(cfg)
	check(err)
	check(owner.Close())
	journal := filepath.Join(path, ".cengine-storage-authority")
	census := func() map[string][]byte {
		entries, err := os.ReadDir(journal)
		check(err)
		files := make(map[string][]byte, len(entries))
		for _, entry := range entries {
			files[entry.Name()], err = os.ReadFile(filepath.Join(journal, entry.Name()))
			check(err)
		}
		return files
	}
	// An unproven artifact exercises the shared refusal checker without
	// fabricating a native certificate or granting a filename cleanup waiver.
	artifact := filepath.Join(journal, "state-unproven.tmp")
	check(os.WriteFile(artifact, []byte("must remain evidence"), 0600))
	before := census()
	refusals := 0
	lifecycleRecoveryRefuseUnanchored(t, cfg, trust, func() {
		refusals++
		if !reflect.DeepEqual(before, census()) {
			t.Fatal("refusal changed evidence")
		}
	})
	if refusals != 2 {
		t.Fatal("did not check both unanchored APIs")
	}
	if got, err := trust.OpenExpected(cfg, trust.Expected.ExpectedStartup); got != nil || !errors.Is(err, a.ErrRepairRequired) {
		if got != nil {
			_ = got.Close()
		}
		t.Fatal("exact anchor accepted unproven temporary", err)
	}
	if !reflect.DeepEqual(before, census()) {
		t.Fatal("exact refusal changed evidence")
	}
	check(os.Remove(artifact)) // remove only the test's own negative-control file
	for attempt := 0; attempt < 2; attempt++ {
		stale := *trust
		owner = lifecycleRecoveryOpenExact(t, cfg, trust)
		check(owner.Close())
		before = census()
		if got, err := stale.OpenExpected(cfg, stale.Expected.ExpectedStartup); got != nil || !errors.Is(err, a.ErrConflict) {
			if got != nil {
				_ = got.Close()
			}
			t.Fatal("consumed fixture anchor reopened", err)
		}
		if !reflect.DeepEqual(before, census()) {
			t.Fatal("stale anchor refusal changed evidence")
		}
	}
}
