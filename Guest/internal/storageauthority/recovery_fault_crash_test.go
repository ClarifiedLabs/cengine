package storageauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Exercise real journal IO and a returned error followed by immediate process
// death, without the authority's best-effort poison path. The certificate must
// prove data safety on its own; absence of io-quarantined is never that proof.
func TestMetadataFaultBeforePoisonWorker(t *testing.T) {
	path := os.Getenv("CENGINE_METADATA_FAULT_ROOT")
	if path == "" {
		return
	}
	f := newFixtureAt(t, nil, path)
	b, _ := f.runtime(f.volume("stable"), ReadOnly)
	stable := f.retire(b)
	before := f.a.clone()
	raw, err := json.Marshal(crashManifest{Current: f.signedCurrent(), Bootstrap: f.c.BootstrapKey, Before: *before, Stable: stable})
	must(t, err)
	writeCrashWitness(t, path, crashManifestName, raw)
	boundary := os.Getenv("CENGINE_METADATA_FAULT_BOUNDARY")
	failure := error(unix.EIO)
	if os.Getenv("CENGINE_METADATA_FAULT_ERRNO") == "enospc" {
		failure = unix.ENOSPC
	}
	reached := false
	f.a.j.fault = func(step string) error {
		if step == boundary {
			reached = true
			return failure
		}
		return nil
	}
	// Use persist directly only to intercept the returned error before commit
	// can poison. A fresh epoch exercises the predecessor-epoch distinction.
	next := f.a.clone()
	next.Revision++
	next.Epoch = mustID(t)
	err = f.a.j.persist(next)
	if !reached || !errors.Is(err, failure) {
		t.Fatalf("fault not reached: %v", err)
	}
	os.Exit(crashExit)
}

func TestMetadataFaultCrashPreservesACKWithoutQuarantine(t *testing.T) {
	for _, errno := range []string{"eio", "enospc"} {
		for _, boundary := range persistBoundaries {
			t.Run(errno+"/"+boundary, func(t *testing.T) {
				path := t.TempDir()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMetadataFaultBeforePoisonWorker$", "-test.count=1")
				cmd.Env = append(os.Environ(), "CENGINE_METADATA_FAULT_ROOT="+path,
					"CENGINE_METADATA_FAULT_BOUNDARY="+boundary, "CENGINE_METADATA_FAULT_ERRNO="+errno,
					"GORACE=atexit_sleep_ms=0")
				output, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
					t.Fatalf("worker: %v\n%s", err, output)
				}
				raw, err := os.ReadFile(filepath.Join(path, crashManifestName))
				must(t, err)
				var manifest crashManifest
				must(t, json.Unmarshal(raw, &manifest))
				for _, name := range []string{pendingName, quarantineName} {
					if _, err := os.Stat(filepath.Join(path, registryName, name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("poison ran: %s: %v", name, err)
					}
				}
				root, err := os.Open(path)
				must(t, err)
				defer root.Close()
				open := func() (*Authority, error) {
					return OpenLifecycleExpected(Config{Root: root, DeviceID: manifest.Before.Store.DeviceID, BootstrapKey: manifest.Bootstrap,
						Barrier: func(Binding, *os.File) error { t.Fatal("recovery manufactured barrier"); return nil }}, manifest.Current, ExpectedLifecycleStartup{ExpectedStartup{manifest.Before.Store.ID, manifest.Before.Epoch, manifest.Before.Controller}, manifest.Before.Lifecycle.OpenRevision})
				}
				// The worker deliberately persists a different E. Only faults before
				// any proof IO leave a clean predecessor. Unpublished/published
				// cross-E evidence is not same-E workload recovery; after rename the
				// trusted predecessor itself conflicts. Never authorize from disk.
				if boundary != "state-read-prior" && boundary != "proof-open" {
					raw, err := os.ReadFile(filepath.Join(path, registryName, stateName))
					must(t, err)
					var disk diskState
					must(t, json.Unmarshal(raw, &disk))
					rec := disk.Attachments[manifest.Stable.Attachment]
					if rec.Receipt == nil || *rec.Receipt != manifest.Stable {
						t.Fatal("crash lost acknowledged receipt")
					}
					prior, err := json.Marshal(manifest.Before.Operations)
					must(t, err)
					current, err := json.Marshal(disk.Operations)
					must(t, err)
					if !bytes.Equal(prior, current) {
						t.Fatal("crash changed acknowledged operation history")
					}
					want := ErrRepairRequired
					switch boundary {
					case "state-parent-sync", "proof-unlink", "proof-clear-sync":
						want = ErrConflict
					}
					lifecycleCrashRefusesUnchanged(t, path, open, want)
					return
				}
				a, err := open()
				must(t, err)
				defer a.Close()
				rec := a.s.Attachments[manifest.Stable.Attachment]
				if rec.Receipt == nil || *rec.Receipt != manifest.Stable {
					t.Fatal("acknowledged receipt lost")
				}
				prior, err := json.Marshal(manifest.Before.Operations)
				must(t, err)
				current, err := json.Marshal(a.s.Operations)
				must(t, err)
				if !bytes.Equal(prior, current) {
					t.Fatal("acknowledged operation history changed")
				}
				if a.s.Epoch == manifest.Before.Epoch {
					t.Fatal("recovery reused epoch")
				}
			})
		}
	}
}
