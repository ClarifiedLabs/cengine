package storageauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDurabilityObligationOwnershipAndOrderedClear(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("data")
	b, p := f.runtime(v, ReadWrite)
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	d, err := g.BeginDurability(^uint64(0))
	must(t, err)
	raw, err := os.ReadFile(filepath.Join(f.path, registryName, dataIOName))
	must(t, err)
	var record durabilityRecord
	must(t, json.Unmarshal(raw, &record))
	if record.Binding != b || record.Epoch != f.a.Epoch() || record.Controller != f.a.s.Controller || record.Sequence != ^uint64(0) || len(raw) > maxDurabilityBytes {
		t.Fatal("obligation lost exact tuple", record)
	}
	_, err = g.BeginDurability(1)
	wantErr(t, err, ErrBusy)
	// A disjoint control commit must not clear or replace the obligation.
	f.volume("disjoint")
	after, err := os.ReadFile(filepath.Join(f.path, registryName, dataIOName))
	must(t, err)
	if !bytes.Equal(raw, after) {
		t.Fatal("control commit rewrote data obligation")
	}
	must(t, d.Complete(nil))
	wantErr(t, d.Complete(nil), ErrClosed)
	g.Release()
	if _, err = os.Stat(filepath.Join(f.path, registryName, dataIOName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	stable := f.retire(b)
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	snapshot, err := f.a.Query(f.control)
	must(t, err)
	if *snapshot.Attachments[b.Attachment].Receipt != stable {
		t.Fatal("clean reopen changed receipt")
	}
}

func TestDurabilityObligationFailuresCannotClearOrMintReceipt(t *testing.T) {
	for _, stage := range []string{"data-open", "data-write", "data-sync", "data-close", "data-parent-sync", "data-unlink", "data-clear-sync", "operation", "abandon"} {
		for _, fault := range []error{syscall.EIO, syscall.ENOSPC} {
			t.Run(stage+"/"+fault.Error(), func(t *testing.T) {
				f := newFixture(t, nil)
				v := f.volume("data")
				b, p := f.runtime(v, ReadWrite)
				g, err := f.a.Admit(p, v.ID, true)
				must(t, err)
				f.a.j.fault = func(step string) error {
					if step == stage {
						return fault
					}
					return nil
				}
				d, err := g.BeginDurability(1)
				if d != nil {
					if stage == "abandon" {
						g.Release()
						err = d.Complete(nil)
					} else if stage == "operation" {
						err = d.Complete(fault)
					} else {
						err = d.Complete(nil)
					}
				}
				if err == nil {
					t.Fatal("fault accepted")
				}
				g.Release()
				f.a.j.fault = nil
				_, err = f.a.Retire(context.Background(), f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
				wantErr(t, err, ErrBlocked)
				must(t, f.a.Close())
				_, err = f.openCurrent()
				wantErr(t, err, ErrRepairRequired)
			})
		}
	}
}

func TestDurabilityFormatNeverSilentlyUpgrades(t *testing.T) {
	for _, version := range []int{0, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			f := newFixture(t, nil)
			f.a.s.Durability = version
			raw, err := json.Marshal(f.a.s)
			must(t, err)
			must(t, f.a.Close())
			must(t, os.WriteFile(filepath.Join(f.path, registryName, stateName), raw, 0600))
			_, err = f.openCurrent()
			wantErr(t, err, ErrInvalid)
		})
	}
}

type ioCrashManifest struct {
	Bootstrap ed25519.PublicKey
	Before    diskState
	Stable    Receipt
	Current   SignedLifecycleGrant
}

// The external process observes ACK lines only after ordered completion. Crashing
// intentionally bypasses Complete/Release/poison and all deferred test cleanup.
func TestDurabilityCrashWorker(t *testing.T) {
	if os.Getenv("CENGINE_DATA_CRASH_WORKER") != "1" {
		return
	}
	path := os.Getenv("CENGINE_DATA_CRASH_ROOT")
	mode := os.Getenv("CENGINE_DATA_CRASH_MODE")
	f := newFixtureAt(t, nil, path)
	v := f.volume("data")
	b, p := f.runtime(v, ReadWrite)
	stableBinding, _ := f.runtime(f.volume("stable"), ReadOnly)
	stable := f.retire(stableBinding)
	raw, err := json.Marshal(ioCrashManifest{f.c.BootstrapKey, *f.a.clone(), stable, f.signedCurrent()})
	must(t, err)
	fmt.Printf("ACK:stable:%s\n", raw)
	file, err := os.OpenFile(filepath.Join(path, "volumes", "data", "payload"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	_, err = file.Write([]byte("external-ACK-prefix\n"))
	must(t, err)
	must(t, file.Sync())
	fmt.Println("ACK:prefix")
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	// Crashes at journal boundaries prove mutation is not reached before durability.
	f.a.j.afterStep = func(stage string) {
		if mode == stage {
			os.Exit(crashExit)
		}
	}
	f.a.j.fault = func(stage string) error {
		if mode == "clear-fault-crash" && stage == "data-clear-sync" {
			fmt.Println("FAULT:post-completion-clear-sync")
			os.Exit(crashExit) // unlink visible; quarantine cannot run
		}
		return nil
	}
	d, err := g.BeginDurability(1)
	must(t, err)
	if mode == "before-mutation" {
		os.Exit(crashExit)
	}
	_, err = file.Write([]byte("unacknowledged-suffix\n"))
	must(t, err)
	if mode == "after-mutation" {
		os.Exit(crashExit)
	}
	if mode == "eio" || mode == "enospc" {
		// The fault occurs after real mutation, before the IO result can be persisted.
		fault := syscall.EIO
		if mode == "enospc" {
			fault = syscall.ENOSPC
		}
		fmt.Printf("FAULT:%s\n", fault)
		os.Exit(crashExit)
	}
	must(t, file.Sync())
	must(t, d.Complete(nil))
	g.Release()
	fmt.Println("ACK:mutation")
	_ = b
	os.Exit(crashExit)
}

func TestDurabilityCrashNeverForgetsFaultAndKeepsACKPrefix(t *testing.T) {
	for _, mode := range []string{"data-open", "data-write", "data-sync", "data-close", "data-parent-sync", "before-mutation", "after-mutation", "eio", "enospc", "data-unlink", "data-clear-sync", "clear-fault-crash", "success"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDurabilityCrashWorker$", "-test.count=1")
			cmd.Env = append(os.Environ(), "CENGINE_DATA_CRASH_WORKER=1", "CENGINE_DATA_CRASH_ROOT="+path, "CENGINE_DATA_CRASH_MODE="+mode, "GORACE=atexit_sleep_ms=0")
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
				t.Fatalf("worker: %v\n%s", err, output)
			}
			var manifest ioCrashManifest
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, "ACK:stable:") {
					must(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "ACK:stable:")), &manifest))
				}
			}
			if manifest.Stable.Revision == 0 || !bytes.Contains(output, []byte("ACK:prefix\n")) {
				t.Fatalf("missing external ACK %s", output)
			}
			payload, err := os.ReadFile(filepath.Join(path, "volumes", "data", "payload"))
			must(t, err)
			if !bytes.HasPrefix(payload, []byte("external-ACK-prefix\n")) {
				t.Fatal("lost externally acknowledged prefix")
			}
			raw, err := os.ReadFile(filepath.Join(path, registryName, stateName))
			must(t, err)
			var disk diskState
			must(t, json.Unmarshal(raw, &disk))
			if *disk.Attachments[manifest.Stable.Attachment].Receipt != manifest.Stable {
				t.Fatal("old receipt changed")
			}
			root, err := os.Open(path)
			must(t, err)
			defer root.Close()
			open := func() (*Authority, error) {
				return OpenLifecycleExpected(Config{Root: root, DeviceID: manifest.Before.Store.DeviceID, BootstrapKey: manifest.Bootstrap, Barrier: func(Binding, *os.File) error { t.Fatal("Open fabricated barrier"); return nil }}, manifest.Current, ExpectedLifecycleStartup{ExpectedStartup{manifest.Before.Store.ID, manifest.Before.Epoch, manifest.Before.Controller}, manifest.Before.Lifecycle.OpenRevision})
			}
			safe := mode == "success" || mode == "data-unlink" || mode == "data-clear-sync" || mode == "clear-fault-crash"
			if !safe {
				// Outstanding DATA evidence cannot be consumed by a refused open.
				lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
				return
			}
			a, err := open()
			must(t, err)
			must(t, a.Close())
			if mode == "clear-fault-crash" && string(payload) != "external-ACK-prefix\nunacknowledged-suffix\n" {
				t.Fatal("clear began before ordered payload completion")
			}
			if mode == "success" {
				if !bytes.Contains(output, []byte("ACK:mutation\n")) {
					t.Fatal("missing completed mutation ACK")
				}
				if string(payload) != "external-ACK-prefix\nunacknowledged-suffix\n" {
					t.Fatal("lost acknowledged completed payload")
				}
			}
		})
	}
}
