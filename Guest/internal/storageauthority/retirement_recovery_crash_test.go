//go:build linux || darwin

package storageauthority

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const retirementCrashRoot = "CENGINE_RETIREMENT_RECOVERY_ROOT"

// These are same-host process deaths, not physical power-loss/ext4 proofs.
// os.Exit bypasses authority Close, poison and deferred cleanup. No production
// safety bypass or fault API is exposed; hooks are the existing private journal IO hooks.
func TestRetirementRecoveryCrashWorker(t *testing.T) {
	path := os.Getenv(retirementCrashRoot)
	if path == "" {
		return
	}
	defer func() { _ = os.WriteFile(filepath.Join(path, "retirement-cleanup-ran"), []byte("bad"), 0600) }()
	mode := os.Getenv("CENGINE_RETIREMENT_RECOVERY_MODE")
	edge := os.Getenv("CENGINE_RETIREMENT_RECOVERY_EDGE")
	boundary := os.Getenv("CENGINE_RETIREMENT_RECOVERY_BOUNDARY")
	checkpoint := func(when, name string) {
		if edge == when && boundary == name {
			os.Exit(crashExit)
		}
	}
	if mode == "cleanup" {
		m := retirementReadManifest(t, path)
		root, err := os.Open(path)
		must(t, err)
		cfg, err := configured(Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { t.Fatal("cleanup ran barrier"); return nil }})
		must(t, err)
		j, err := openJournal(cfg, false)
		must(t, err)
		must(t, j.validateRetirementRecovery())
		if j.uncertain {
			must(t, j.recoverUncertainty())
		}
		// Public Open has no fault-injection option. Invoke the same validated,
		// flock-held cleanup directly, then let the parent exercise real Open.
		j.fault = func(name string) error { checkpoint("before", name); return nil }
		j.afterStep = func(name string) { checkpoint("after", name) }
		must(t, j.recoverRetirement())
		t.Fatal("cleanup checkpoint was not reached")
	}
	f := newFixtureAt(t, nil, path)
	stableBinding, _ := f.runtime(f.volume("stable"), ReadOnly)
	writeCrashWitness(t, filepath.Join(path, "volumes", "stable"), "acked-payload", []byte("stable ACK prefix\n"))
	stable := f.retire(stableBinding)
	fmt.Printf("ACK:stable:%s\n", retirementJSON(t, stable))
	b, key := f.binding(f.volume("target"), RuntimeRole, ReadWrite, "")
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}))
	prep := mustID(t)
	reserved, _ := f.binding(f.volume("reserved"), PrepareRole, ReadWrite, prep)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), prep, []Binding{reserved}}))
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	armed := false
	f.a.j.fault = func(name string) error {
		if armed {
			if (mode == "candidate-fault" || mode == "candidate-partial-fault") && name == "barrier-complete-open" {
				// This hook is reached only AFTER the actual Barrier returned nil
				// and a.available passed. Intercept the candidate IO error before
				// its caller can poison; never derive completion from a later sync.
				before := f.a.clone()
				next := f.a.clone()
				next.Revision++
				rec := next.Attachments[b.Attachment]
				receipt := Receipt{SchemaVersion, b.Store, b.Volume, b.Attachment, b.Launch, b.Prepare, next.Revision}
				rec.Phase, rec.Receipt = Drained, &receipt
				next.Attachments[b.Attachment] = rec
				proof := retirementProof{retirementProofVersion, mustID(t), before.Store, before.Epoch,
					before.Controller, before.Bootstrap, before.Volumes[b.Volume], b,
					rec.Retirement, next.Revision, contentDigest(retirementJSON(t, before)), contentDigest(retirementJSON(t, next))}
				failure := error(unix.EIO)
				if edge == "enospc" {
					failure = unix.ENOSPC
				}
				reached := false
				f.a.j.afterStep = nil
				f.a.j.fault = func(step string) error {
					if step != boundary {
						return nil
					}
					reached = true
					if mode == "candidate-partial-fault" {
						raw := retirementJSON(t, proof)
						must(t, os.WriteFile(registryFile(t, f, "barrier-"+string(proof.Attempt)+".tmp"), raw[:len(raw)/2], 0600))
					}
					return failure
				}
				err := f.a.j.writeRetirementProof(proof)
				if !reached || !errors.Is(err, failure) {
					t.Fatalf("candidate fault not reached: %v", err)
				}
				os.Exit(crashExit)
			}
			checkpoint("before", name)
		}
		return nil
	}
	f.a.j.afterStep = func(name string) {
		if !armed {
			return
		}
		if mode == "receipt-fault" && name == "barrier-complete-parent-sync" {
			// Intercept persist's returned error before Authority.commit can
			// poison. Completed barrier + independently proven PRIOR is safe,
			// even when a later receipt IO error preceded death. This is NOT
			// permission to certify a failed or incomplete Barrier.
			f.a.j.afterStep = nil
			failure := error(unix.EIO)
			if edge == "enospc" {
				failure = unix.ENOSPC
			}
			reached := false
			f.a.j.fault = func(name string) error {
				if name == boundary {
					reached = true
					return failure
				}
				return nil
			}
			next := f.a.clone()
			next.Revision++
			rec := next.Attachments[b.Attachment]
			receipt := Receipt{SchemaVersion, b.Store, b.Volume, b.Attachment, b.Launch, b.Prepare, next.Revision}
			rec.Phase, rec.Receipt = Drained, &receipt
			next.Attachments[b.Attachment] = rec
			err := f.a.j.persist(next)
			if !reached || !errors.Is(err, failure) {
				t.Fatalf("receipt fault not reached: %v", err)
			}
			os.Exit(crashExit)
		}
		checkpoint("after", name)
	}
	f.a.barrier = func(binding Binding, root *os.File) error {
		if binding != b {
			return ErrConflict
		}
		got, err := identity(root)
		if err != nil {
			return err
		}
		f.a.mu.Lock()
		before := f.a.clone()
		f.a.mu.Unlock()
		if got != before.Volumes[b.Volume].Root {
			return ErrConflict
		}
		manifest := crashManifest{f.c.BootstrapKey, f.controllerKey, f.caKey, f.ca.Raw, key, *before, []Binding{reserved}, req, stable, f.signedCurrent()}
		writeCrashWitness(t, path, crashManifestName, retirementJSON(t, manifest))
		if mode == "inside-barrier" {
			// Even a successful substep sync cannot prove resource teardown or
			// the entire retained-resource Barrier return. RTM107 stays blocked.
			must(t, root.Sync())
			os.Exit(crashExit)
		}
		if mode == "failed-barrier-before-poison" {
			// As with direct persist interception above, stop between the full
			// callback's failed return and its caller's best-effort poison path.
			err := callBarrier(func(Binding, *os.File) error { return unix.EIO }, binding, root)
			wantErr(t, err, unix.EIO)
			os.Exit(crashExit)
		}
		armed = true
		return nil
	}
	_, err := f.a.Retire(context.Background(), f.control, req)
	t.Fatalf("unreached checkpoint %s/%s/%s: %v", mode, edge, boundary, err)
}

func retirementReadManifest(t *testing.T, path string) crashManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(path, crashManifestName))
	must(t, err)
	var m crashManifest
	must(t, json.Unmarshal(raw, &m))
	return m
}

func retirementCrash(t *testing.T, path, mode, edge, boundary string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRetirementRecoveryCrashWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), retirementCrashRoot+"="+path, "CENGINE_RETIREMENT_RECOVERY_MODE="+mode,
		"CENGINE_RETIREMENT_RECOVERY_EDGE="+edge, "CENGINE_RETIREMENT_RECOVERY_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
		t.Fatalf("worker: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(path, "retirement-cleanup-ran")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("process ran deferred cleanup", err)
	}
	if mode != "cleanup" {
		m := retirementReadManifest(t, path)
		if !bytes.Contains(output, append([]byte("ACK:stable:"), retirementJSON(t, m.Stable)...)) {
			t.Fatalf("missing externally observed ACK: %s", output)
		}
	}
}

func retirementCheckCrash(t *testing.T, path string, repair, landed, guarded bool) {
	t.Helper()
	m := retirementReadManifest(t, path)
	raw, err := os.ReadFile(filepath.Join(path, registryName, stateName))
	must(t, err)
	var disk diskState
	must(t, json.Unmarshal(raw, &disk))
	stable := disk.Attachments[m.Stable.Attachment]
	if stable.Receipt == nil || *stable.Receipt != m.Stable {
		t.Fatal("lost/changed acknowledged receipt")
	}
	payload, err := os.ReadFile(filepath.Join(path, "volumes", "stable", "acked-payload"))
	must(t, err)
	if string(payload) != "stable ACK prefix\n" {
		t.Fatal("lost acknowledged payload")
	}
	if !reflect.DeepEqual(m.Before.Operations, disk.Operations) {
		t.Fatal("crash changed operation history")
	}
	target := disk.Attachments[m.Retire.Attachment]
	if landed {
		b := target.Binding
		want := Receipt{SchemaVersion, b.Store, b.Volume, b.Attachment, b.Launch, b.Prepare, m.Before.Revision + 1}
		if target.Phase != Drained || target.Receipt == nil || *target.Receipt != want {
			t.Fatal("wrong exact candidate receipt")
		}
	} else if target.Phase != Retiring || target.Receipt != nil {
		t.Fatal("prior image fabricated receipt")
	}
	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	calls := 0
	cfg := Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(b Binding, fd *os.File) error {
		calls++
		got, err := identity(fd)
		if err != nil {
			return err
		}
		if b != target.Binding || got != disk.Volumes[b.Volume].Root {
			return ErrConflict
		}
		return nil
	}}
	expected := ExpectedLifecycleStartup{ExpectedStartup{m.Before.Store.ID, m.Before.Epoch, m.Before.Controller}, m.Before.Lifecycle.OpenRevision}
	if repair {
		lifecycleCrashRefusesUnchanged(t, path, func() (*Authority, error) {
			return OpenLifecycleExpected(cfg, m.Current, expected)
		}, ErrRepairRequired)
		if calls != 0 {
			t.Fatal("refused recovery ran barrier")
		}
		return
	}
	var a *Authority
	// Pending recovery evidence always requires the externally retained open
	// anchor. Current-only opens below remain covered once cleanup is complete.
	a, err = OpenLifecycleExpected(cfg, m.Current, expected)
	must(t, err)
	defer a.Close()
	if calls != 0 || a.Epoch() == disk.Epoch || a.s.Revision != disk.Revision+1 {
		t.Fatal("Open ran a barrier or failed to advance epoch exactly once")
	}
	// Beyond normal epoch/revision rotation and startup fencing, EVERYTHING is
	// exact, including stable receipt, operations, prepares, bindings and grants.
	disk.Epoch = a.Epoch()
	disk.Revision++
	disk.Lifecycle.OpenRevision = disk.Revision
	for id, rec := range disk.Attachments {
		if rec.Phase == Active || rec.Phase == Reserved {
			rec.Phase = Retiring
			disk.Attachments[id] = rec
		}
	}
	if !reflect.DeepEqual(&disk, a.s) {
		t.Fatal("recovery changed more than normal startup fencing")
	}
	for _, name := range []string{barrierName, commitProofName, pendingName, quarantineName} {
		if _, err := os.Stat(filepath.Join(path, registryName, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery retained %s: %v", name, err)
		}
	}
	// Both public open paths remain repeatable after each publication/promotion
	// edge. A retained predecessor still has no receipt until ordinary Retire.
	for _, guardedAgain := range []bool{!guarded, guarded} {
		before := a.clone()
		must(t, a.Close())
		if guardedAgain {
			a, err = OpenLifecycleExpected(cfg, m.Current, ExpectedLifecycleStartup{ExpectedStartup{before.Store.ID, before.Epoch, before.Controller}, before.Lifecycle.OpenRevision})
		} else {
			a, err = OpenLifecycleCurrent(cfg, m.Current)
		}
		must(t, err)
		before.Epoch = a.Epoch()
		before.Revision++
		before.Lifecycle.OpenRevision = before.Revision
		if calls != 0 || !reflect.DeepEqual(before, a.s) {
			t.Fatal("repeated Open changed receipts/history or ran barrier")
		}
	}
	defer a.Close()
	disk = *a.clone()
	f := &fixture{t: t, a: a, c: cfg, controllerKey: m.ControllerKey, caKey: m.CAKey, path: path}
	f.ca, err = x509.ParseCertificate(m.CACertificate)
	must(t, err)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.ca)
	f.server = f.cert(newKey(t))
	f.control = f.authControl(m.ControllerKey, disk.Controller.Epoch)
	receipt, err := a.Retire(context.Background(), f.control, m.Retire)
	must(t, err)
	if landed {
		if receipt != *target.Receipt || calls != 0 {
			t.Fatal("lost reply replay changed receipt or reran barrier")
		}
	} else if calls != 1 || receipt.Revision != disk.Revision+1 {
		t.Fatal("prior recovery did not require a fresh complete barrier")
	}
	again, err := a.Retire(context.Background(), f.control, m.Retire)
	must(t, err)
	if receipt != again || !reflect.DeepEqual(m.Before.Operations, a.s.Operations) {
		t.Fatal("retry changed receipt/history")
	}
}

func TestRetirementRecoveryAbruptPublicationBoundaries(t *testing.T) {
	boundaries := append(append([]string{}, retirementCompletionBoundaries...), persistBoundaries...)
	boundaries = append(boundaries, "barrier-unlink", "barrier-clear-sync")
	for _, boundary := range boundaries {
		for _, edge := range []string{"before", "after"} {
			t.Run(boundary+"/"+edge, func(t *testing.T) {
				path := t.TempDir()
				retirementCrash(t, path, "publication", edge, boundary)
				// Complete candidate bytes are the first recoverable image, not
				// candidate fsync, close or rename. Earlier/partial writes refuse.
				repair := boundary == "barrier-complete-open" || boundary == "barrier-complete-write" && edge == "before" ||
					lifecycleMetadataCrashRefuses(edge, boundary, true)
				landed := boundary == "state-rename" && edge == "after" || boundary == "state-parent-sync" || boundary == "proof-unlink" || boundary == "proof-clear-sync" || boundary == "barrier-unlink" || boundary == "barrier-clear-sync"
				retirementCheckCrash(t, path, repair, landed, edge == "after")
			})
		}
	}
	for _, mode := range []string{"inside-barrier", "failed-barrier-before-poison"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			retirementCrash(t, path, mode, "", "")
			retirementCheckCrash(t, path, true, false, false)
		})
	}
}

func TestRetirementRecoveryAbruptCleanupBoundaries(t *testing.T) {
	for _, image := range []string{"candidate", "prior", "next"} {
		boundaries := append([]string{}, retirementCleanupBoundaries...)
		if image == "candidate" {
			boundaries = append(append([]string{}, retirementCandidatePromotionBoundaries...), boundaries...)
		}
		for _, boundary := range boundaries {
			for _, edge := range []string{"before", "after"} {
				t.Run(image+"/"+boundary+"/"+edge, func(t *testing.T) {
					path := t.TempDir()
					seed := "state-open"
					if image == "next" {
						seed = "state-parent-sync"
					} else if image == "candidate" {
						seed = "barrier-complete-write"
					}
					retirementCrash(t, path, "publication", "after", seed)
					retirementCrash(t, path, "cleanup", edge, boundary)
					// The prior seed stops just after state-open: its empty state
					// candidate remains unproven even after barrier-only cleanup.
					retirementCheckCrash(t, path, image == "prior", image == "next", edge == "after")
				})
			}
		}
	}
}

func TestRetirementCandidateIOFailureBeforePoison(t *testing.T) {
	for _, errno := range []string{"eio", "enospc"} {
		for _, boundary := range []string{"barrier-complete-write", "barrier-complete-sync", "barrier-complete-close", "barrier-complete-rename"} {
			t.Run(errno+"/"+boundary, func(t *testing.T) {
				path := t.TempDir()
				retirementCrash(t, path, "candidate-fault", errno, boundary)
				for _, name := range []string{pendingName, quarantineName, commitProofName} {
					if _, err := os.Stat(filepath.Join(path, registryName, name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("poison/metadata unexpectedly ran", name, err)
					}
				}
				retirementCheckCrash(t, path, boundary == "barrier-complete-write", false, true)
			})
		}
		t.Run(errno+"/partial-write", func(t *testing.T) {
			path := t.TempDir()
			retirementCrash(t, path, "candidate-partial-fault", errno, "barrier-complete-write")
			retirementCheckCrash(t, path, true, false, false)
		})
	}
}

func TestRetirementRecoveryReceiptIOFailureBeforePoisonKeepsProvenPrior(t *testing.T) {
	for _, errno := range []string{"eio", "enospc"} {
		for _, boundary := range []string{"state-write", "state-sync", "state-close"} {
			t.Run(errno+"/"+boundary, func(t *testing.T) {
				path := t.TempDir()
				retirementCrash(t, path, "receipt-fault", errno, boundary)
				for _, name := range []string{pendingName, quarantineName} {
					if _, err := os.Stat(filepath.Join(path, registryName, name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("poison unexpectedly ran", name, err)
					}
				}
				// A returned state-write fault leaves an empty candidate. The
				// sync/close cuts retain complete, digest-bound predecessor proof.
				retirementCheckCrash(t, path, boundary == "state-write", false, true)
			})
		}
	}
}
