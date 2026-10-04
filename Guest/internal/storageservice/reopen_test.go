package storageservice

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

func expectedReopen(f *fixture) a.ExpectedLifecycleStartup {
	return a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: f.ready.Store.ID, Epoch: f.ready.ServiceEpoch, Controller: f.ready.Controller}, OpenRevision: f.s.openRevision}
}

func reopenJournal(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	path := filepath.Join(f.root.Name(), ".cengine-storage-authority")
	entries, err := os.ReadDir(path)
	must(t, err)
	contents := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		must(t, err)
		contents[entry.Name()] = string(data)
	}
	return contents
}

func TestReopenMismatchNeverAdvancesEpoch(t *testing.T) {
	for _, field := range []string{"store", "epoch", "controller", "key", "config-store", "open-revision"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			expected, cfg := expectedReopen(f), f.cfg
			switch field {
			case "store":
				expected.Store = id(t)
				cfg.Store = expected.Store // passes config guard, must check locked state
			case "epoch":
				expected.Epoch = id(t)
			case "controller":
				expected.Controller.Epoch++
			case "open-revision":
				expected.OpenRevision++
			case "key":
				key, err := p.NewControllerKey()
				must(t, err)
				expected.Controller.Key = fingerprint(t, key)
			case "config-store":
				cfg.Store = id(t)
				cfg.Now = time.Time{} // store guard precedes issuer construction
			}
			must(t, f.s.Close())
			before := reopenJournal(t, f)
			got, err := f.reopen(cfg, expected)
			if got != nil || !errors.Is(err, a.ErrConflict) {
				t.Fatalf("mismatch: service=%v err=%v", got, err)
			}
			if !reflect.DeepEqual(before, reopenJournal(t, f)) {
				t.Fatal("mismatched Reopen changed journal/E/revision")
			}
			reopened, err := f.reopen(f.cfg, expectedReopen(f))
			must(t, err)
			defer reopened.Close()
			next, err := reopened.Ready()
			must(t, err)
			if next.Revision != f.ready.Revision+1 || next.ServiceEpoch == f.ready.ServiceEpoch {
				t.Fatal("refused Reopen consumed epoch/revision")
			}
		})
	}
}

func TestReopenSuccessRotatesOnlyServiceGeneration(t *testing.T) {
	f := newFixture(t)
	expected := expectedReopen(f)
	must(t, f.s.Close())
	reopened, err := f.reopen(f.cfg, expected)
	must(t, err)
	defer reopened.Close()
	next, err := reopened.Ready()
	must(t, err)
	if next.ServiceEpoch == expected.Epoch || next.Revision != f.ready.Revision+1 || next.Store != f.ready.Store || next.Controller != expected.Controller || next.Bootstrap != f.ready.Bootstrap {
		t.Fatal("wrong guarded startup generation")
	}
	if bytes.Equal(next.TLSRootDER, f.ready.TLSRootDER) || next.ServerKey == f.ready.ServerKey {
		t.Fatal("reopen reused private TLS generation")
	}
	must(t, reopened.Close())
	before := reopenJournal(t, f)
	_, err = f.reopen(f.cfg, expected)
	if !errors.Is(err, a.ErrConflict) || !reflect.DeepEqual(before, reopenJournal(t, f)) {
		t.Fatal("stale predecessor replay changed journal", err)
	}
}

func TestReopenInvalidIntentAndConfigBeforeJournal(t *testing.T) {
	f := newFixture(t) // held flock makes ordering observable as ErrLocked
	before := reopenJournal(t, f)
	for _, field := range []string{"store", "epoch", "controller", "key", "bootstrap", "time", "lifetime", "data-limits", "control-limits", "authority-limits", "root", "device", "open-revision"} {
		t.Run(field, func(t *testing.T) {
			cfg, expected := f.cfg, expectedReopen(f)
			invalidIntent := false
			switch field {
			case "store":
				expected.Store = "bad"
				invalidIntent = true
			case "epoch":
				expected.Epoch = "bad"
				invalidIntent = true
			case "controller":
				expected.Controller.Epoch = 0
				invalidIntent = true
			case "key":
				expected.Controller.Key = "bad"
				invalidIntent = true
			case "open-revision":
				expected.OpenRevision = 0
				invalidIntent = true
			case "bootstrap":
				cfg.Bootstrap = p.BootstrapPublicKey{}
			case "time":
				cfg.Now = time.Time{}
			case "lifetime":
				cfg.Lifetime = -time.Second
			case "data-limits":
				cfg.DataLimits = d.DefaultLimits()
				cfg.DataLimits.Connections = -1
			case "control-limits":
				cfg.ControlLimits = c.DefaultLimits()
				cfg.ControlLimits.RequestBytes = 1
			case "authority-limits":
				cfg.AuthorityLimits = a.DefaultLimits()
				cfg.AuthorityLimits.Volumes = -1
			case "root":
				cfg.Root = nil
			case "device":
				cfg.DeviceUUID = ""
			}
			got, err := f.reopen(cfg, expected)
			if got != nil || err == nil || errors.Is(err, a.ErrLocked) {
				t.Fatalf("validation reached journal: service=%v err=%v", got, err)
			}
			if invalidIntent && !errors.Is(err, a.ErrInvalid) {
				t.Fatal("invalid intent must return ErrInvalid", err)
			}
			if !reflect.DeepEqual(before, reopenJournal(t, f)) {
				t.Fatal("invalid startup changed journal")
			}
		})
	}
}

func TestReopenHeldPredecessorRefuses(t *testing.T) {
	f := newFixture(t)
	before := reopenJournal(t, f)
	got, err := f.reopen(f.cfg, expectedReopen(f))
	if got != nil || !errors.Is(err, a.ErrLocked) || !reflect.DeepEqual(before, reopenJournal(t, f)) {
		t.Fatal("reopen adopted held predecessor", err)
	}
}

func TestReopenMissingAndUncertaintyFailClosed(t *testing.T) {
	for _, obstacle := range []string{"registry", "state.json", "uncertain", "barrier-uncertain", "data-uncertain"} {
		t.Run(obstacle, func(t *testing.T) {
			f := newFixture(t)
			must(t, f.s.Close())
			path := filepath.Join(f.root.Name(), ".cengine-storage-authority")
			want := a.ErrRepairRequired
			if obstacle == "registry" {
				must(t, os.RemoveAll(path))
				want = a.ErrMissing
			} else if obstacle == "state.json" {
				must(t, os.Remove(filepath.Join(path, obstacle)))
				want = a.ErrMissing
			} else {
				must(t, os.WriteFile(filepath.Join(path, obstacle), []byte("retained uncertainty"), 0600))
			}
			var before map[string]string
			if obstacle != "registry" {
				before = reopenJournal(t, f)
			}
			got, err := f.reopen(f.cfg, expectedReopen(f))
			if got != nil || !errors.Is(err, want) {
				t.Fatalf("service=%v err=%v; want %v", got, err, want)
			}
			if obstacle == "registry" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("Reopen initialized registry", err)
				}
			} else if !reflect.DeepEqual(before, reopenJournal(t, f)) {
				t.Fatal("refused Reopen changed journal")
			}
		})
	}
}
