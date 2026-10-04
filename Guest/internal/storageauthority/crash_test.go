package storageauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const crashExit = 91
const crashManifestName = "crash-test-manifest.json"
const barrierWitnessName = "crash-test-barrier-completed.json"

type crashManifest struct {
	Bootstrap     ed25519.PublicKey
	ControllerKey ed25519.PrivateKey
	CAKey         ed25519.PrivateKey
	CACertificate []byte
	DataKey       ed25519.PrivateKey
	Before        diskState
	Planned       []Binding
	Retire        RetireRequest
	Stable        Receipt
	Current       SignedLifecycleGrant
}

// Lifecycle admission requires complete, bound temporary bytes. These exact
// cuts leave an empty candidate, or an unpublished metadata proof alongside a
// retirement proof (which is not the standalone initial-publication contract).
func lifecycleMetadataCrashRefuses(edge, boundary string, retirement bool) bool {
	for _, prefix := range []string{"proof", "state", "proof-ready"} {
		if boundary == prefix+"-open" && edge == "after" || boundary == prefix+"-write" && edge == "before" {
			return true
		}
	}
	if retirement {
		switch boundary {
		case "proof-write", "proof-sync", "proof-close":
			return true
		case "proof-rename":
			return edge == "before"
		}
	}
	return false
}

// Preserve every journal entry, including children of unproven private
// directories, not merely state.json or the published obligation slots.
func lifecycleCrashCensus(t *testing.T, path string) map[string]any {
	t.Helper()
	out := retirementJournalCensus(t, path)
	entries, err := os.ReadDir(path)
	must(t, err)
	for _, entry := range entries {
		if entry.IsDir() {
			out[entry.Name()+"/"] = lifecycleCrashCensus(t, filepath.Join(path, entry.Name()))
		}
	}
	return out
}

func lifecycleCrashRefusesUnchanged(t *testing.T, path string, open func() (*Authority, error), want error) {
	t.Helper()
	journal := filepath.Join(path, registryName)
	before := lifecycleCrashCensus(t, journal)
	for range 2 {
		a, err := open()
		if a != nil {
			a.Close()
			t.Fatal("unproven crash evidence reopened")
		}
		wantErr(t, err, want)
		if !reflect.DeepEqual(before, lifecycleCrashCensus(t, journal)) {
			t.Fatal("refused startup changed journal evidence")
		}
	}
}

// This worker is a real test subprocess. os.Exit bypasses deferred Close and
// poison/quarantine cleanup; the OS releases its lifetime flock. These are local
// process-crash tests, NOT device, VM, ext4, or physical-power-loss tests.
func TestAbruptExitWorker(t *testing.T) {
	if os.Getenv("CENGINE_AUTHORITY_CRASH_WORKER") != "1" {
		return
	}
	root := os.Getenv("CENGINE_AUTHORITY_CRASH_ROOT")
	defer func() { _ = os.WriteFile(filepath.Join(root, "cleanup-ran"), []byte("unexpected cleanup"), 0600) }()
	mode := os.Getenv("CENGINE_AUTHORITY_CRASH_MODE")
	edge := os.Getenv("CENGINE_AUTHORITY_CRASH_EDGE")
	boundary := os.Getenv("CENGINE_AUTHORITY_CRASH_BOUNDARY")
	f := newFixtureAt(t, nil, root)
	v1, v2 := f.volume("one"), f.volume("two")
	stableBinding, _ := f.runtime(v2, ReadOnly)
	stable := f.retire(stableBinding)
	target, key := f.binding(v1, RuntimeRole, ReadWrite, "")
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), target}))
	// A separate RESERVED peer must also be fenced by recovery, not silently
	// reactivated merely because this crash targeted another attachment.
	prep := mustID(t)
	first, firstKey := f.binding(v1, PrepareRole, ReadWrite, prep)
	second, _ := f.binding(v2, PrepareRole, ReadWrite, prep)
	reserve := ReserveRequest{mustID(t), prep, []Binding{first, second}}
	if mode != "reserve" {
		must(t, f.a.ReservePrepare(f.control, reserve))
	}
	if mode == "register" {
		target = first
		key = firstKey
	}
	req := RetireRequest{mustID(t), target.Store, target.Volume, target.Attachment, target.Launch}
	manifest := crashManifest{f.c.BootstrapKey, f.controllerKey, f.caKey, f.ca.Raw, key, *f.a.clone(), reserve.Attachments, req, stable, f.signedCurrent()}
	data, err := json.Marshal(manifest)
	must(t, err)
	writeCrashWitness(t, root, crashManifestName, data)

	armed := mode != "receipt" && mode != "barrier"
	checkpoint := func(when, name string) {
		if armed && edge == when && boundary == name {
			os.Exit(crashExit)
		}
	}
	f.a.j.fault = func(name string) error { checkpoint("before", name); return nil }
	f.a.j.afterStep = func(name string) { checkpoint("after", name) }
	f.a.barrier = func(binding Binding, fd *os.File) error {
		if mode == "barrier" {
			os.Exit(crashExit)
		}
		if binding != target {
			return ErrConflict
		}
		got, err := identity(fd)
		if err != nil {
			return err
		}
		if got != v1.Root {
			return ErrConflict
		}
		// The witness records only successful completion of the mock retained-FD
		// barrier, before receipt publication. It is not a live ext4 drain proof.
		data, err := json.Marshal(binding)
		if err != nil {
			return err
		}
		writeCrashWitness(t, root, barrierWitnessName, data)
		armed = true
		return nil
	}
	switch mode {
	case "reserve":
		err = f.a.ReservePrepare(f.control, reserve)
	case "register":
		err = f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), target})
	case "intent", "receipt", "barrier":
		_, err = f.a.Retire(context.Background(), f.control, req)
	default:
		t.Fatalf("unknown crash mode %q", mode)
	}
	t.Fatalf("crash boundary was not reached: %s/%s/%s: %v", mode, edge, boundary, err)
}

func writeCrashWitness(t *testing.T, root, name string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	_, err = f.Write(data)
	must(t, err)
	must(t, f.Sync())
	must(t, f.Close())
	dir, err := os.Open(root)
	must(t, err)
	must(t, dir.Sync())
	must(t, dir.Close())
}

func runAbruptExit(t *testing.T, mode, edge, boundary string) {
	t.Helper()
	path := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAbruptExitWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CENGINE_AUTHORITY_CRASH_WORKER=1", "CENGINE_AUTHORITY_CRASH_ROOT="+path, "CENGINE_AUTHORITY_CRASH_MODE="+mode, "CENGINE_AUTHORITY_CRASH_EDGE="+edge, "CENGINE_AUTHORITY_CRASH_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
		t.Fatalf("worker did not exit at checkpoint: %v\n%s", err, output)
	}
	if _, err = os.Stat(filepath.Join(path, "cleanup-ran")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash ran deferred cleanup: %v", err)
	}
	bytes, err := os.ReadFile(filepath.Join(path, crashManifestName))
	must(t, err)
	var m crashManifest
	must(t, json.Unmarshal(bytes, &m))
	bytes, err = os.ReadFile(filepath.Join(path, registryName, stateName))
	must(t, err)
	var disk diskState
	must(t, json.Unmarshal(bytes, &disk))
	if disk.Attachments[m.Stable.Attachment].Receipt == nil || *disk.Attachments[m.Stable.Attachment].Receipt != m.Stable {
		t.Fatal("crash lost or changed an acknowledged receipt")
	}
	if mode == "reserve" {
		_, one := disk.Attachments[m.Planned[0].Attachment]
		_, two := disk.Attachments[m.Planned[1].Attachment]
		if one != two {
			t.Fatal("crash left a partial all-volume reservation")
		}
	}
	// No new receipt may exist without the completed mock barrier, even in an
	// unpublished state that Open will correctly quarantine.
	for id, rec := range disk.Attachments {
		if rec.Receipt == nil || m.Before.Attachments[id].Receipt != nil {
			continue
		}
		witness, err := os.ReadFile(filepath.Join(path, barrierWitnessName))
		must(t, err)
		var binding Binding
		must(t, json.Unmarshal(witness, &binding))
		if id != m.Retire.Attachment || binding != rec.Binding {
			t.Fatal("fabricated or cross-attachment receipt")
		}
	}

	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	barrierCalls := 0
	config := Config{Root: root, DeviceID: m.Before.Store.DeviceID, BootstrapKey: m.Bootstrap, Barrier: func(Binding, *os.File) error { barrierCalls++; return nil }}
	outcome := abruptRecoveryOutcome(edge, boundary)
	if lifecycleMetadataCrashRefuses(edge, boundary, mode == "receipt") {
		outcome = "repair"
	}
	if mode == "barrier" {
		// The configured barrier has not returned, so no completion certificate
		// exists. Receipt-mode cuts now follow a certified successful barrier.
		outcome = "repair"
	}
	open := func() (*Authority, error) {
		return OpenLifecycleExpected(config, m.Current, ExpectedLifecycleStartup{ExpectedStartup{m.Before.Store.ID, m.Before.Epoch, m.Before.Controller}, m.Before.Lifecycle.OpenRevision})
	}
	if outcome == "repair" {
		lifecycleCrashRefusesUnchanged(t, path, open, ErrRepairRequired)
		if barrierCalls != 0 {
			t.Fatal("refused recovery ran barrier")
		}
		return
	}
	a, err := open()
	must(t, err)
	defer func() { must(t, a.Close()) }()
	if mode == "barrier" {
		t.Fatal("interrupted barrier was silently recovered")
	}
	if barrierCalls != 0 || a.Epoch() == m.Before.Epoch {
		t.Fatal("Open manufactured barrier completion or reused epoch")
	}
	f := &fixture{t: t, a: a, c: config, controllerKey: m.ControllerKey, caKey: m.CAKey, path: path}
	f.ca, err = x509.ParseCertificate(m.CACertificate)
	must(t, err)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.ca)
	f.server = f.cert(newKey(t))
	f.control = f.authControl(m.ControllerKey, m.Before.Controller.Epoch)
	snapshot, err := a.Query(f.control)
	must(t, err)
	for _, rec := range snapshot.Attachments {
		if rec.Phase != Retiring && rec.Phase != Drained {
			t.Fatalf("recovered attachment can admit: %s", rec.Phase)
		}
		before := disk.Attachments[rec.Binding.Attachment]
		if rec.Phase == Drained && (before.Receipt == nil || *rec.Receipt != *before.Receipt) {
			t.Fatal("Open fabricated a receipt")
		}
	}
	target := snapshot.Attachments[m.Retire.Attachment].Binding
	conn := f.conn(m.DataKey, tls.VersionTLS13, true)
	_, err = a.AuthenticateData(context.Background(), conn, DataHello{m.Before.Epoch, target})
	wantErr(t, err, ErrUnauthorized)
	_, err = a.AuthenticateData(context.Background(), conn, DataHello{a.Epoch(), target})
	wantErr(t, err, ErrBlocked)
	if receipt := snapshot.Attachments[m.Retire.Attachment].Receipt; receipt != nil {
		got, err := a.Retire(context.Background(), f.control, m.Retire)
		must(t, err)
		if got != *receipt || barrierCalls != 0 {
			t.Fatal("lost-reply retry changed receipt or reran barrier")
		}
	} else {
		if snapshot.Attachments[m.Retire.Attachment].Phase != Retiring {
			t.Fatal("unacknowledged work was not fenced")
		}
		// Recovery can complete only by explicitly running the required barrier.
		_, err = a.Retire(context.Background(), f.control, m.Retire)
		must(t, err)
		if barrierCalls != 1 {
			t.Fatal("recovery omitted the retained-resource barrier")
		}
	}
}

func TestAbruptExitAtJournalBoundaries(t *testing.T) {
	for _, mode := range []string{"reserve", "register", "intent", "receipt"} {
		for _, boundary := range persistBoundaries {
			for _, edge := range []string{"before", "after"} {
				t.Run(mode+"/"+boundary+"/"+edge, func(t *testing.T) { runAbruptExit(t, mode, edge, boundary) })
			}
		}
	}
	for _, boundary := range []string{"barrier-unlink", "barrier-clear-sync"} {
		for _, edge := range []string{"before", "after"} {
			t.Run("receipt/"+boundary+"/"+edge, func(t *testing.T) { runAbruptExit(t, "receipt", edge, boundary) })
		}
	}
	t.Run("inside-barrier", func(t *testing.T) { runAbruptExit(t, "barrier", "", "") })
}
