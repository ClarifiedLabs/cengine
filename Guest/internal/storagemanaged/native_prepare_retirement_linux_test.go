//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storagemanaged

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

const prepareRetirementWorkerEnv = "CENGINE_NATIVE_PREPARE_RETIREMENT_WORKER"

var prepareRetirementUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Public evidence only. Controller/owner private keys travel solely down the
// inherited command pipe, never into this fsynced manifest or test output.
type prepareRetirementManifest struct {
	Kind       string
	Public     policyManifest
	BeforeDisk json.RawMessage
}

type prepareRetirementObservation struct {
	Kind         string
	ProofCalls   int
	BarrierCalls int
	SyncCalls    int
	Closed       int
	Census       [32]byte
}

// Closed, canonical v2 retry-only schema. This is NOT a barrier-success proof.
type prepareRetirementRecord struct {
	Version    int           `json:"version"`
	Kind       string        `json:"kind"`
	Attempt    a.ID          `json:"attempt"`
	Store      a.Store       `json:"store"`
	Epoch      a.ID          `json:"epoch"`
	Controller a.Controller  `json:"controller"`
	Bootstrap  a.Fingerprint `json:"bootstrap"`
	Volume     a.Volume      `json:"volume"`
	Binding    a.Binding     `json:"binding"`
	Operation  a.ID          `json:"operation"`
	Revision   uint64        `json:"revision"`
	Prior      string        `json:"prior_digest"`
}

func prepareRetirementKind(kind string) bool {
	return kind == "published" || kind == "inside-barrier" || kind == "completed"
}

func prepareRetirementExt4(t *testing.T, root *os.File) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("RTM110 requires Linux root and real storageidentity capabilities")
	}
	st, err := stat(int(root.Fd()))
	must(t, err)
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(int(root.Fd()), &fs))
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Bsize <= 0 || fs.Blocks > (128<<20)/uint64(fs.Bsize) {
		t.Fatal("requires owned root on the runner's bounded 128 MiB ext4 fixture")
	}
}

// Reuse the real identity102 fixture, but install the production optional proof
// callback before creating ANY owner. The extra setup reopen is not crash evidence.
func prepareRetirementInstall(t *testing.T, f *fixture, keys copyDataKeys, proof func(a.Binding, *os.File, func() (bool, error)) (bool, error), barrier a.Barrier) {
	t.Helper()
	before, err := f.authority.Query(f.control)
	must(t, err)
	if len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 {
		t.Fatal("configuration switch with retained resources")
	}
	must(t, f.authority.Close())
	cfg := a.Config{Root: f.root, DeviceID: before.Store.DeviceID, BootstrapKey: keys.Bootstrap, Barrier: barrier, PrepareRetirementProof: proof}
	f.authority, err = f.lifecycle.OpenExpected(cfg, f.lifecycle.Expected.ExpectedStartup)
	must(t, err)
	f.control, err = f.authority.AuthenticateController(t.Context(), f.conn(keys.Controller), before.Controller.Epoch)
	must(t, err)
}

func prepareRetirementRequest(b a.Binding, operation a.ID) a.RetireRequest {
	return a.RetireRequest{Operation: operation, Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}
}

func prepareRetirementSetup(t *testing.T, f *fixture, kind string, owner ed25519.PrivateKey) (*Session, prepareRetirementManifest) {
	t.Helper()
	// The earlier ACK has a real PREPARE owner's real retained-resource receipt.
	old := copyDataOwner(t, f, nil)
	created := f.call(old, caller(1001, 1001), w.CreateRequest{Parent: 1, Name: []byte("payload"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	written := f.call(old, grantAuth, w.WriteRequest{Node: created.Entry.Node, Handle: created.Opened.Handle, Data: []byte(policyACK)}).(w.WriteReply)
	if written.Written != uint32(len(policyACK)) {
		t.Fatal("short real ACK write")
	}
	stable, err := f.authority.Retire(t.Context(), f.control, prepareRetirementRequest(old.binding, newID(t)))
	must(t, err)
	if !old.closed || len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 {
		t.Fatal("earlier receipt did not drain every retained owner")
	}
	must(t, f.authority.CompletePrepare(f.control, a.CompleteRequest{Operation: newID(t), Prepare: old.binding.Prepare, Receipts: []a.Receipt{stable}, Attestation: a.Attestation{Prepare: old.binding.Prepare, Succeeded: true, CleanCopyUp: true}}))
	s := copyDataOwner(t, f, nil, owner) // Session.New, no BeginCopy or private action
	f.call(s, metadata, w.GetAttrRequest{Node: 1})
	f.call(s, caller(0, 0), w.OpenDirRequest{Node: 1})
	before, err := f.authority.Query(f.control)
	must(t, err)
	initial, err := policyCensus(f.root)
	must(t, err)
	m := prepareRetirementManifest{Kind: kind, Public: policyManifest{Lifecycle: *f.lifecycle, Kind: "barrier", Bootstrap: f.bootstrap, Before: before, Stable: stable, Binding: s.binding, Operation: newID(t), ACK: []byte(policyACK)}, BeforeDisk: initial["state.json"]}
	must(t, prepareRetirementValidateManifest(m))
	return s, m
}

func prepareRetirementValidateManifest(m prepareRetirementManifest) error {
	if !prepareRetirementKind(m.Kind) {
		return errors.New("unknown PREPARE retirement cut")
	}
	if err := policyValidateManifest(m.Public, "barrier"); err != nil {
		return err
	}
	var image retirementImage
	if len(m.BeforeDisk) > policyFileLimit {
		return errors.New("oversized predecessor")
	}
	if err := policyJSON(m.BeforeDisk, &image); err != nil {
		return err
	}
	state, err := policyState(map[string][]byte{"state.json": m.BeforeDisk})
	if err != nil || !reflect.DeepEqual(state, m.Public.Before) || image.Revision > ^uint64(0)-3 || image.Operations == nil {
		return errors.New("non-exact full predecessor")
	}
	b := m.Public.Binding
	prep, ok := image.Prepares[b.Prepare]
	if b.Role != a.PrepareRole || b.Mode != a.ReadWrite || b.Prepare == "" || !ok || prep.Phase != a.Pending || len(prep.Attachments) != 1 || prep.Attachments[0] != b || prep.Attestation != nil || prep.Successor != "" {
		return errors.New("not a fresh pending PREPARE owner")
	}
	for id, rec := range image.Attachments {
		if id != b.Attachment && (rec.Phase != a.Drained || rec.Receipt == nil) {
			return errors.New("another undrained authority owner")
		}
	}
	if _, exists := image.Operations[m.Public.Operation]; exists {
		return errors.New("retirement operation already exists")
	}
	return nil
}

// retirementImages has exact full-image semantics for either role; unlike
// retirementValidateCompletion, it includes Binding.Prepare in the receipt.
func prepareRetirementImages(m prepareRetirementManifest) ([]byte, []byte, a.Receipt, error) {
	return retirementImages(retirementManifest{Public: m.Public, BeforeDisk: m.BeforeDisk, Plan: a.NativeRetirementRecoveryPlan{Binding: m.Public.Binding, Operation: m.Public.Operation}})
}

func prepareRetirementValidate(m prepareRetirementManifest, proof prepareRetirementObservation, census map[string][]byte) error {
	if err := prepareRetirementValidateManifest(m); err != nil {
		return err
	}
	if proof.Kind != m.Kind || proof.ProofCalls != 1 || proof.Census != policyDigest(census) {
		return errors.New("unbound proof/census")
	}
	if m.Kind == "published" {
		if proof.BarrierCalls != 0 || proof.SyncCalls != 0 || proof.Closed != 0 {
			return errors.New("published cut already entered barrier")
		}
	} else if proof.BarrierCalls != 1 || proof.SyncCalls != 1 || proof.Closed != 5 {
		return errors.New("inside cut lacks actual syncfs and complete resource closure")
	}
	prior, _, _, err := prepareRetirementImages(m)
	if err != nil {
		return err
	}
	if len(census) != 3 || !bytes.Equal(census["state.json"], prior) {
		return errors.New("unexpected complete retirement census/prior image")
	}
	if lock, exists := census["lock"]; !exists || len(lock) != 0 {
		return errors.New("missing exact lock")
	}
	raw := census["barrier-uncertain"]
	if len(raw) == 0 || len(raw) > 4096 {
		return errors.New("unbounded retry-only marker")
	}
	var record prepareRetirementRecord
	if err := policyJSON(raw, &record); err != nil {
		return err
	}
	// Attempt is generated by production; require the exact lowercase UUIDv4
	// grammar without the runtime-only NativeRetirementRecoveryPlan validation.
	if !prepareRetirementUUID.MatchString(string(record.Attempt)) {
		return errors.New("invalid publication attempt")
	}
	boot, err := a.PublicKeyFingerprint(m.Public.Bootstrap)
	if err != nil {
		return err
	}
	b := m.Public.Binding
	want := prepareRetirementRecord{Version: 2, Kind: "prepare-root-only-retry", Attempt: record.Attempt, Store: m.Public.Before.Store, Epoch: m.Public.Before.Epoch, Controller: m.Public.Before.Controller, Bootstrap: boot, Volume: m.Public.Before.Volumes[b.Volume], Binding: b, Operation: m.Public.Operation, Revision: m.Public.Before.Revision + 1, Prior: retirementDigest(prior)}
	if record != want {
		return errors.New("retry-only marker changed full binding/root/operation/revision/prior")
	}
	return nil
}

func prepareRetirementCompletion(m prepareRetirementManifest, receipt a.Receipt, census map[string][]byte) error {
	_, next, want, err := prepareRetirementImages(m)
	if err != nil {
		return err
	}
	if receipt != want || len(census) != 2 || !bytes.Equal(census["state.json"], next) {
		return errors.New("Retire did not return exact PREPARE receipt after real barrier")
	}
	if lock, ok := census["lock"]; !ok || len(lock) != 0 {
		return errors.New("non-exact completion census")
	}
	return nil
}

// The worker is an environment-gated branch of the parent, not an extra selected
// test name. Successful controls also die without Authority.Close or cleanup.
func prepareRetirementWorker(t *testing.T, kind string) {
	if !prepareRetirementKind(kind) {
		t.Fatal("invalid worker kind")
	}
	root, commands, proofs := os.NewFile(3, "prepare-retirement-root"), os.NewFile(4, "prepare-retirement-commands"), os.NewFile(5, "prepare-retirement-proofs")
	defer root.Close()
	defer commands.Close()
	defer proofs.Close()
	prepareRetirementExt4(t, root)
	must(t, policyPipe(commands, unix.O_RDONLY))
	must(t, policyPipe(proofs, unix.O_WRONLY))
	left, err := stat(int(commands.Fd()))
	must(t, err)
	right, err := stat(int(proofs.Fd()))
	must(t, err)
	if left.Dev == right.Dev && left.Ino == right.Ino {
		t.Fatal("aliased owned pipes")
	}
	var keys copyDataKeys
	must(t, policyReceive(commands, &keys))
	if len(keys.Controller) != ed25519.PrivateKeySize || len(keys.Owner) != ed25519.PrivateKeySize || len(keys.Bootstrap) != ed25519.PublicKeySize {
		t.Fatal("invalid private key channel")
	}
	f := copyDataFixture(t, "/proc/self/fd/3", keys, nil, false)
	var selected *Session
	var m prepareRetirementManifest
	proofCalls, barrierCalls, syncCalls := 0, 0, 0
	fds := []int{}
	hold := func(closed int) error {
		cut, err := policyCensus(root)
		if err != nil {
			return err
		}
		proof := prepareRetirementObservation{Kind: kind, ProofCalls: proofCalls, BarrierCalls: barrierCalls, SyncCalls: syncCalls, Closed: closed, Census: policyDigest(cut)}
		if err = prepareRetirementValidate(m, proof, cut); err != nil {
			return err
		}
		if err = policySend(proofs, proof); err != nil {
			return err
		}
		policyCommand(t, commands, 'R')
		return nil
	}
	prepareRetirementInstall(t, f, keys, func(b a.Binding, fd *os.File, publish func() (bool, error)) (bool, error) {
		proved, err := f.registry.PrepareRetirementProof(b, fd, publish)
		if selected != nil && b == selected.binding {
			proofCalls++
			if err != nil || !proved || proofCalls != 1 {
				return false, fmt.Errorf("actual root-only callback did not publish exactly once: proved=%v calls=%d: %w", proved, proofCalls, err)
			}
			if kind == "published" {
				// Marker is real and Registry has returned true, but Authority has
				// not received that true and therefore cannot call Barrier yet.
				if selected.closed || len(f.registry.sessions) != 1 || len(f.registry.objects) != 1 {
					return false, errors.New("publication unexpectedly drained resources")
				}
				if err = hold(0); err != nil {
					return false, err
				}
			}
		}
		return proved, err
	}, func(b a.Binding, fd *os.File) error {
		if selected != nil && b == selected.binding {
			barrierCalls++
		}
		return f.registry.Barrier(b, fd)
	})
	selected, m = prepareRetirementSetup(t, f, kind, keys.Owner)
	fds = append(fds, int(selected.root.Fd()), int(selected.metadataFD.Fd()))
	for _, n := range selected.nodes {
		fds = append(fds, n.fd)
	}
	for _, h := range selected.handles {
		fds = append(fds, h.fd)
	}
	for _, obj := range f.registry.objects {
		fds = append(fds, obj.fd)
	}
	if len(fds) != 5 || f.sequence[selected] != 2 {
		t.Fatal("selected session was not exactly New + root GETATTR + OPENDIR")
	}
	must(t, policySend(proofs, m))
	policyCommand(t, commands, 'A')
	f.registry.syncOps.syncfs = func(fd int) error {
		syncCalls++
		if kind == "published" || syncCalls != 1 || barrierCalls != 1 || f.registry.barrierBinding == nil || *f.registry.barrierBinding != selected.binding || !selected.closed || len(selected.nodes) != 0 || len(selected.handles) != 0 || len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 {
			return errors.New("wrong retained-resource syncfs seam")
		}
		for _, old := range fds {
			if _, err := stat(old); !errors.Is(err, unix.EBADF) {
				return errors.New("retained descriptor at final syncfs")
			}
		}
		if err := unix.Syncfs(fd); err != nil { // REAL syscall, never synthetic success
			return err
		}
		return hold(len(fds)) // hold before real delegate result reaches Registry
	}
	receipt, err := f.authority.Retire(t.Context(), f.control, prepareRetirementRequest(selected.binding, m.Public.Operation))
	must(t, err)
	cut, err := policyCensus(root)
	must(t, err)
	must(t, prepareRetirementCompletion(m, receipt, cut))
	must(t, policySend(proofs, policyCompletion{Receipt: receipt}))
	policyCommand(t, commands, '!')
	t.Fatal("parent must SIGKILL final hold")
}

// RTM110: process death only. Linux/ext4 remain alive; not VM power-loss proof.
// Exactly five selected names: parent, three leaves, and Helpers.
func TestNativePrepareRetirementProcessDeath(t *testing.T) {
	if kind := os.Getenv(prepareRetirementWorkerEnv); kind != "" {
		prepareRetirementWorker(t, kind)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires native Linux root")
	}
	for _, kind := range []string{"published", "inside-barrier", "completed"} {
		t.Run(kind, func(t *testing.T) { prepareRetirementProcessDeath(t, kind) })
	}
}

func prepareRetirementProcessDeath(t *testing.T, kind string) {
	t.Helper()
	path, err := os.MkdirTemp("", "native-prepare-retirement-")
	must(t, err)
	joined := true
	t.Cleanup(func() {
		if joined && !t.Failed() {
			must(t, os.RemoveAll(path))
		} else {
			t.Logf("retaining owned scratch %s (joined=%v)", path, joined)
		}
	})
	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	prepareRetirementExt4(t, root)
	commands, writer, err := os.Pipe()
	must(t, err)
	reader, proofs, err := os.Pipe()
	must(t, err)
	defer commands.Close()
	defer writer.Close()
	defer reader.Close()
	defer proofs.Close()
	must(t, policyPipe(writer, unix.O_WRONLY))
	must(t, policyPipe(reader, unix.O_RDONLY))
	binary, err := os.Executable()
	must(t, err)
	cmd := exec.Command(binary, "-test.run=^TestNativePrepareRetirementProcessDeath$", "-test.v", "-test.count=1", "-test.timeout=50s")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, prepareRetirementWorkerEnv+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, prepareRetirementWorkerEnv+"="+kind)
	cmd.ExtraFiles = []*os.File{root, commands, proofs}
	capture := new(policyOutput)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = capture, capture, 2*time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	started, done := make(chan error, 1), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		done <- cmd.Wait() // sole actual Wait; timeout/EOF never count as death
		if cmd.ProcessState == nil {
			select {}
		}
	}()
	must(t, <-started)
	joined = false
	defer func() {
		if !joined {
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			} else {
				_ = cmd.Process.Kill()
			}
			select {
			case <-done:
				joined = cmd.ProcessState != nil
			case <-time.After(10 * time.Second):
				t.Error("owned worker unjoined; not death evidence")
			}
		}
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		if t.Failed() {
			t.Logf("bounded worker output: %s", capture.String())
		}
	}()
	if pidfd < 0 {
		t.Fatal("missing owned pidfd")
	}
	must(t, commands.Close())
	must(t, proofs.Close())
	deadline := time.Now().Add(40 * time.Second)
	must(t, reader.SetReadDeadline(deadline))
	must(t, writer.SetWriteDeadline(deadline))
	keys := newCopyDataKeys(t)
	must(t, policySend(writer, keys))
	var m prepareRetirementManifest
	must(t, policyReceive(reader, &m))
	must(t, prepareRetirementValidateManifest(m))
	st, err := stat(int(root.Fd()))
	must(t, err)
	if !reflect.DeepEqual(m.Public.Lifecycle.Current, keys.Lifecycle.Current) || m.Public.Lifecycle.Expected.Store != m.Public.Before.Store.ID || m.Public.Lifecycle.Expected.Epoch != m.Public.Before.Epoch || m.Public.Lifecycle.Expected.Controller != m.Public.Before.Controller || m.Public.Lifecycle.Expected.OpenRevision == 0 {
		t.Fatal("worker lifecycle trust differs from parent grant/live predecessor")
	}
	if m.Kind != kind || m.Public.Before.Store.Root != (a.RootIdentity{Device: st.Dev, Inode: st.Ino}) || !bytes.Equal(m.Public.Bootstrap, keys.Bootstrap) {
		t.Fatal("manifest not bound to selected kind/root/bootstrap")
	}
	initial, err := policyCensus(root)
	must(t, err)
	if len(initial) != 2 || !bytes.Equal(initial["state.json"], m.BeforeDisk) {
		t.Fatal("manifest differs from actual full predecessor census")
	}
	ack, err := os.OpenFile(filepath.Join(path, "parent-ack.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	must(t, policySend(ack, m))
	must(t, ack.Sync())
	must(t, ack.Close())
	must(t, root.Sync())
	ackBytes, err := policyReadPath(root, "parent-ack.json", policyLimit)
	must(t, err)
	retirementCheckACK(t, root, ackBytes)
	_, err = writer.Write([]byte{'A'})
	must(t, err)
	var proof prepareRetirementObservation
	must(t, policyReceive(reader, &proof))
	cut, err := policyCensus(root)
	must(t, err)
	must(t, prepareRetirementValidate(m, proof, cut))
	prepareRetirementParserNegatives(t, m, proof, cut)
	policyLogCensus(t, kind+"-held", cut)
	if kind == "completed" {
		_, err = writer.Write([]byte{'R'})
		must(t, err)
		var completion policyCompletion
		must(t, policyReceive(reader, &completion))
		cut, err = policyCensus(root)
		must(t, err)
		if completion.Sequence != 0 || completion.Count != 0 {
			t.Fatal("non-retirement completion")
		}
		must(t, prepareRetirementCompletion(m, completion.Receipt, cut))
	}
	must(t, unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0))
	select {
	case err = <-done:
		joined = cmd.ProcessState != nil
		if !policyKilled(err, cmd.ProcessState) {
			t.Fatalf("not actual SIGKILL/sole Wait: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGKILL deadline is not proof of death")
	}
	dead, err := policyCensus(root)
	must(t, err)
	if !reflect.DeepEqual(cut, dead) {
		t.Fatal("death changed held census")
	}
	retirementCheckACK(t, root, ackBytes)
	if kind == "published" {
		prepareRetirementRefusals(t, path, root, keys, m)
	}
	registry, err := NewRegistry(new(sync.Mutex))
	must(t, err)
	barriers, callbacks := 0, 0
	cfg := a.Config{Root: root, DeviceID: m.Public.Before.Store.DeviceID, BootstrapKey: keys.Bootstrap, Barrier: func(b a.Binding, fd *os.File) error {
		barriers++
		return registry.Barrier(b, fd)
	}, PrepareRetirementProof: func(b a.Binding, fd *os.File, publish func() (bool, error)) (bool, error) {
		callbacks++
		return registry.PrepareRetirementProof(b, fd, publish)
	}}
	if kind != "completed" {
		lifecycleRecoveryRefuseUnanchored(t, cfg, &m.Public.Lifecycle, func() {
			unchanged, err := policyCensus(root)
			must(t, err)
			if !reflect.DeepEqual(dead, unchanged) || barriers != 0 || callbacks != 0 {
				t.Fatal("unanchored refusal changed census or invoked retirement callbacks")
			}
			retirementCheckACK(t, root, ackBytes)
		})
	}
	for attempt := 1; attempt <= 2; attempt++ {
		var expected retirementImage
		must(t, policyJSON(dead["state.json"], &expected))
		reopened := lifecycleRecoveryOpenExact(t, cfg, &m.Public.Lifecycle)
		epoch := reopened.Epoch()
		must(t, reopened.Close())
		if epoch == expected.Epoch || barriers != 0 || callbacks != 0 {
			t.Fatal("startup failed fresh E or invoked retirement callbacks")
		}
		expected.Epoch, expected.Revision = epoch, expected.Revision+1
		expected.Lifecycle.OpenRevision = expected.Revision
		want, err := json.Marshal(expected)
		must(t, err)
		dead, err = policyCensus(root)
		must(t, err)
		if len(dead) != 2 || !bytes.Equal(dead["state.json"], want) {
			t.Fatal("startup changed full predecessor beyond fresh E/revision or retained marker")
		}
		rec := expected.Attachments[m.Public.Binding.Attachment]
		if expected.Prepares[m.Public.Binding.Prepare].Phase != a.Pending || (kind != "completed" && (rec.Phase != a.Retiring || rec.Receipt != nil)) || (kind == "completed" && (rec.Phase != a.Drained || rec.Receipt == nil)) {
			t.Fatal("startup manufactured completion or activated old binding")
		}
		retirementCheckACK(t, root, ackBytes)
		policyLogCensus(t, fmt.Sprintf("reopened-exact-%d", attempt), dead)
	}
	before, err := policyState(dead)
	must(t, err)
	keys.Lifecycle = &m.Public.Lifecycle
	f := copyDataFixture(t, path, keys, &before, true)
	prepareRetirementRetry(t, f, keys, m)
	retirementCheckACK(t, root, ackBytes)
}

func prepareRetirementRefusals(t *testing.T, path string, root *os.File, keys copyDataKeys, m prepareRetirementManifest) {
	t.Helper()
	registry, err := NewRegistry(new(sync.Mutex))
	must(t, err)
	cfg := a.Config{Root: root, DeviceID: m.Public.Before.Store.DeviceID, BootstrapKey: keys.Bootstrap, Barrier: registry.Barrier, PrepareRetirementProof: registry.PrepareRetirementProof}
	refuse := func(exact bool, expected a.ExpectedStartup) {
		t.Helper()
		before, err := policyCensus(root)
		must(t, err)
		all := copyDataSnapshot(t, path)
		var opened *a.Authority
		if exact {
			opened, err = m.Public.Lifecycle.OpenExpected(cfg, expected)
		} else {
			opened, err = m.Public.Lifecycle.Open(cfg)
		}
		if opened != nil {
			_ = opened.Close()
			t.Fatal("tampered startup unexpectedly opened")
		}
		if err == nil {
			t.Fatal("tampered startup lacked error")
		}
		after, err := policyCensus(root)
		must(t, err)
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(all, copyDataSnapshot(t, path)) {
			t.Fatal("refused startup changed complete registry/volume census")
		}
	}
	expected := a.ExpectedStartup{Store: m.Public.Before.Store.ID, Epoch: m.Public.Before.Epoch, Controller: m.Public.Before.Controller}
	wrong := expected
	wrong.Epoch = newID(t)
	refuse(true, wrong)
	volume := filepath.Join(path, "volumes", "data")
	must(t, os.Rename(volume, volume+"-saved"))
	must(t, os.Mkdir(volume, 0700))
	refuse(true, expected)
	refuse(false, expected)
	must(t, os.Remove(volume))
	must(t, os.Rename(volume+"-saved", volume))
	marker := filepath.Join(path, ".cengine-storage-authority", "barrier-uncertain")
	original, err := policyReadPath(root, ".cengine-storage-authority/barrier-uncertain", 4096)
	must(t, err)
	for _, raw := range [][]byte{[]byte("{}"), append(bytes.Clone(original), '\n'), bytes.Repeat([]byte("x"), 4097)} {
		must(t, os.WriteFile(marker, raw, 0600))
		refuse(true, expected)
		refuse(false, expected)
	}
	must(t, os.WriteFile(marker, original, 0600))
	f, err := os.Open(marker)
	must(t, err)
	must(t, f.Sync())
	must(t, f.Close())
}

func prepareRetirementRetry(t *testing.T, f *fixture, keys copyDataKeys, m prepareRetirementManifest) {
	t.Helper()
	proofCalls, barriers, syncs := 0, 0, 0
	selected := m.Public.Binding
	prepareRetirementInstall(t, f, keys, func(b a.Binding, fd *os.File, publish func() (bool, error)) (bool, error) {
		if b != selected {
			return f.registry.PrepareRetirementProof(b, fd, publish)
		}
		proofCalls++
		called := false
		proved, err := f.registry.PrepareRetirementProof(b, fd, func() (bool, error) { called = true; return publish() })
		if proved || called || err != nil || len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 {
			return false, errors.New("fresh empty registry classified PREPARE retry")
		}
		return proved, err
	}, func(b a.Binding, fd *os.File) error {
		if b == selected {
			barriers++
			cut, err := policyCensus(f.root)
			if err != nil {
				return err
			}
			if string(cut["barrier-uncertain"]) != retirementPendingBarrier {
				return errors.New("retry did not install ordinary barrier fence")
			}
		}
		return f.registry.Barrier(b, fd)
	})
	f.registry.syncOps.syncfs = func(fd int) error { syncs++; return unix.Syncfs(fd) }
	if stale, err := f.authority.AuthenticateData(t.Context(), f.conn(keys.Owner), a.DataHello{Epoch: m.Public.Before.Epoch, Binding: selected}); !errors.Is(err, a.ErrUnauthorized) || stale != nil {
		t.Fatal("old epoch data owner was not fenced")
	}
	beforeRetry, err := policyCensus(f.root)
	must(t, err)
	var expected retirementImage
	must(t, policyJSON(beforeRetry["state.json"], &expected))
	rec := expected.Attachments[selected.Attachment]
	wantReceipt := a.Receipt{}
	if m.Kind == "completed" {
		if rec.Receipt == nil {
			t.Fatal("completed control lost receipt before retry")
		}
		wantReceipt = *rec.Receipt
	} else {
		expected.Revision++
		wantReceipt = a.Receipt{Schema: a.SchemaVersion, Store: selected.Store, Volume: selected.Volume, Attachment: selected.Attachment, Launch: selected.Launch, Prepare: selected.Prepare, Revision: expected.Revision}
		rec.Phase, rec.Receipt = a.Drained, &wantReceipt
		expected.Attachments[selected.Attachment] = rec
	}
	receipt, err := f.authority.Retire(t.Context(), f.control, prepareRetirementRequest(selected, m.Public.Operation))
	must(t, err)
	wantCalls := 1
	if m.Kind == "completed" {
		wantCalls = 0
	}
	if proofCalls != wantCalls || barriers != wantCalls || syncs != wantCalls || receipt != wantReceipt {
		t.Fatal("fresh retry did not return the exact receipt after the ordinary real barrier")
	}
	wantDisk, err := json.Marshal(expected)
	must(t, err)
	afterRetry, err := policyCensus(f.root)
	must(t, err)
	if len(afterRetry) != 2 || !bytes.Equal(afterRetry["state.json"], wantDisk) {
		t.Fatal("retry changed full state beyond exact receipt or retained barrier marker")
	}
	if lock, ok := afterRetry["lock"]; !ok || len(lock) != 0 {
		t.Fatal("retry did not leave exact state/lock census")
	}
	snapshot, err := f.authority.Query(f.control)
	must(t, err)
	must(t, policyReceipts(m.Public.Before, snapshot, selected.Attachment))
	// Replacement, completed successor, and real runtime readback are independent
	// of PREPARE replay/private actions; no copy transaction was ever begun.
	successor := copyDataOwner(t, f, &selected)
	if successor.binding.Prepare == selected.Prepare || successor.binding.Attachment == selected.Attachment {
		t.Fatal("replacement reused predecessor identity")
	}
	retired, err := f.authority.Retire(t.Context(), f.control, prepareRetirementRequest(successor.binding, newID(t)))
	must(t, err)
	must(t, f.authority.CompletePrepare(f.control, a.CompleteRequest{Operation: newID(t), Prepare: successor.binding.Prepare, Receipts: []a.Receipt{retired}, Attestation: a.Attestation{Prepare: successor.binding.Prepare, Succeeded: true, CleanCopyUp: true}}))
	s, entry := f.session(a.ReadWrite)
	payload := f.call(s, caller(1001, 1001), w.LookupRequest{Parent: entry.Node, Name: []byte("payload")}).(w.LookupReply).Entry
	handle := f.call(s, caller(1001, 1001), w.OpenRequest{Node: payload.Node, Flags: w.OpenReadOnly}).(w.OpenReply).Opened.Handle
	read := f.call(s, grantAuth, w.ReadRequest{Node: payload.Node, Handle: handle, Size: 4096}).(w.ReadReply)
	if string(read.Data) != policyACK {
		t.Fatal("runtime readback lost earlier ACK")
	}
}

func TestNativePrepareRetirementHelpers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires Linux root, never skip RTM110 helpers")
	}
	for _, raw := range [][]byte{nil, []byte("{}{}"), []byte("null"), []byte(`{"Unknown":1}`), []byte(`{"version":2,"version":2}`), bytes.Repeat([]byte("x"), policyLimit+1)} {
		if policyJSON(raw, new(prepareRetirementRecord)) == nil {
			t.Fatal("accepted malformed canonical proof")
		}
	}
	if prepareRetirementKind("unknown") || prepareRetirementValidate(prepareRetirementManifest{}, prepareRetirementObservation{}, nil) == nil || policyKilled(nil, nil) || policyKilled(os.ErrDeadlineExceeded, nil) {
		t.Fatal("accepted unbound stage/proof or non-death event")
	}
	// No extra t.Run names: these finite controls belong to the fifth RTM110 name.
	for _, kind := range []string{"no-session", "runtime", "begin-copy", "readdir", "write-sync-cleanup", "other-owner", "pins", "orphan-pin", "eio", "enospc"} {
		prepareRetirementRegistryNegative(t, kind)
	}
}

func prepareRetirementRegistryNegative(t *testing.T, kind string) {
	t.Helper()
	path := t.TempDir()
	root, err := os.Open(path)
	must(t, err)
	prepareRetirementExt4(t, root)
	must(t, root.Close())
	keys := newCopyDataKeys(t)
	f := copyDataFixture(t, path, keys, nil, false)
	var other *Session
	if kind == "other-owner" {
		// Register before PREPARE reserves the volume; runtime admission after
		// reservation is correctly fenced by Authority.
		other, _ = f.session(a.ReadWrite)
	}
	var s *Session
	var b a.Binding
	if kind == "no-session" || kind == "runtime" {
		if kind == "no-session" {
			b = a.Binding{Store: f.storeID, Volume: f.volumeID, Attachment: newID(t), Prepare: newID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: newID(t), Key: fingerprint(t, keys.Owner), Role: a.PrepareRole, Mode: a.ReadWrite}
			must(t, f.authority.ReservePrepare(f.control, a.ReserveRequest{Operation: newID(t), Prepare: b.Prepare, Attachments: []a.Binding{b}}))
			must(t, f.authority.RegisterAttachment(f.control, a.RegisterRequest{Operation: newID(t), Binding: b}))
		} else {
			s, _ = f.session(a.ReadWrite)
			b = s.binding
		}
	} else {
		s = copyDataOwner(t, f, nil)
		b = s.binding
		h := f.call(s, caller(0, 0), w.OpenDirRequest{Node: 1}).(w.OpenDirReply).Opened.Handle
		switch kind {
		case "begin-copy":
			f.call(s, caller(0, 0), w.PrepareRequest{Node: 1, Handle: h, Action: w.BeginCopy})
		case "readdir":
			f.call(s, grantAuth, w.ReadDirRequest{Node: 1, Handle: h, MaxBytes: 4096})
		case "write-sync-cleanup", "pins":
			created := f.call(s, caller(1001, 1001), w.CreateRequest{Parent: 1, Name: []byte("owned"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
			f.call(s, grantAuth, w.WriteRequest{Node: created.Entry.Node, Handle: created.Opened.Handle, Data: []byte("owned")})
			f.call(s, grantAuth, w.FsyncRequest{Node: created.Entry.Node, Handle: created.Opened.Handle})
			if kind == "write-sync-cleanup" {
				f.call(s, lifecycle, w.ReleaseRequest{Node: created.Entry.Node, Handle: created.Opened.Handle})
				f.call(s, caller(1001, 1001), w.UnlinkRequest{Parent: 1, Name: []byte("owned")})
				f.call(s, lifecycle, w.ForgetRequest{Entries: []w.ForgetEntry{{Node: created.Entry.Node, Count: 1}}})
				must(t, unix.Syncfs(int(f.volume.Fd())))
			}
		case "orphan-pin":
			// A real extra inode pin is independently disqualifying even though
			// this session's dispatch history remains root-only.
			must(t, os.WriteFile(filepath.Join(path, "volumes", "data", "orphan"), []byte("pin"), 0600))
			fd, err := pinAt(int(f.volume.Fd()), "orphan")
			must(t, err)
			st, err := stat(fd)
			must(t, err)
			f.gate.Lock()
			_, err = f.registry.retainObject(fd, inodeKey{b.Volume, st.Dev, st.Ino})
			f.gate.Unlock()
			must(t, err)
		case "eio", "enospc":
			fault := unix.EIO
			if kind == "enospc" {
				fault = unix.ENOSPC
			}
			f.expectFaults = true
			f.gate.Lock()
			f.registry.latch(b.Volume, fault)
			f.gate.Unlock()
		}
	}
	before, err := policyCensus(f.root)
	must(t, err)
	published := 0
	proved, proofErr := f.registry.PrepareRetirementProof(b, f.volume, func() (bool, error) {
		published++
		return false, errors.New("ineligible callback reached publication")
	})
	if proved || published != 0 {
		t.Fatalf("%s: ineligible registry reached publisher", kind)
	}
	if kind == "eio" || kind == "enospc" {
		fault := unix.EIO
		if kind == "enospc" {
			fault = unix.ENOSPC
		}
		if !errors.Is(proofErr, fault) {
			t.Fatalf("%s: sticky fault was hidden", kind)
		}
	} else if proofErr != nil {
		t.Fatalf("%s: clean ineligibility returned error: %v", kind, proofErr)
	}
	after, err := policyCensus(f.root)
	must(t, err)
	if !reflect.DeepEqual(before, after) || (s != nil && s.closed) {
		t.Fatalf("%s: read-only eligibility check mutated/drained", kind)
	}
	if other != nil {
		_, err := f.authority.Retire(t.Context(), f.control, prepareRetirementRequest(other.binding, newID(t)))
		must(t, err)
	}
}

// Start from the ACTUAL production marker, not a synthetic positive barrier.
// Rehash every corrupted census so rejection cannot rely on transport integrity.
func prepareRetirementParserNegatives(t *testing.T, m prepareRetirementManifest, proof prepareRetirementObservation, census map[string][]byte) {
	t.Helper()
	var original prepareRetirementRecord
	must(t, policyJSON(census["barrier-uncertain"], &original))
	reject := func(change func(map[string][]byte)) {
		t.Helper()
		bad := make(map[string][]byte, len(census)+1)
		for name, raw := range census {
			bad[name] = bytes.Clone(raw)
		}
		change(bad)
		p := proof
		p.Census = policyDigest(bad)
		if prepareRetirementValidate(m, p, bad) == nil {
			t.Fatal("accepted malformed/rebound full marker census")
		}
	}
	for _, mutate := range []func(*prepareRetirementRecord){
		func(p *prepareRetirementRecord) { p.Version = 1 },
		func(p *prepareRetirementRecord) { p.Kind = "completed" },
		func(p *prepareRetirementRecord) { p.Attempt = "not-a-uuid" },
		func(p *prepareRetirementRecord) { p.Store.Root.Inode++ },
		func(p *prepareRetirementRecord) { p.Store.Exports.Inode++ },
		func(p *prepareRetirementRecord) { p.Store.DeviceID += "-foreign" },
		func(p *prepareRetirementRecord) { p.Epoch = newID(t) },
		func(p *prepareRetirementRecord) { p.Controller.Epoch++ },
		func(p *prepareRetirementRecord) { p.Bootstrap = a.Fingerprint(strings.Repeat("a", 64)) },
		func(p *prepareRetirementRecord) { p.Volume.Root.Inode++ },
		func(p *prepareRetirementRecord) { p.Binding.Prepare = newID(t) },
		func(p *prepareRetirementRecord) { p.Binding.Attachment = newID(t) },
		func(p *prepareRetirementRecord) { p.Binding.Launch = newID(t) },
		func(p *prepareRetirementRecord) { p.Binding.Container = a.ContainerID(strings.Repeat("b", 64)) },
		func(p *prepareRetirementRecord) { p.Binding.Key = a.Fingerprint(strings.Repeat("c", 64)) },
		func(p *prepareRetirementRecord) { p.Binding.Mode = a.ReadOnly },
		func(p *prepareRetirementRecord) { p.Binding.Role = a.RuntimeRole },
		func(p *prepareRetirementRecord) { p.Operation = newID(t) },
		func(p *prepareRetirementRecord) { p.Revision++ },
		func(p *prepareRetirementRecord) { p.Prior = retirementDigest(m.BeforeDisk) },
	} {
		bad := original
		mutate(&bad)
		raw, err := json.Marshal(bad)
		must(t, err)
		reject(func(c map[string][]byte) { c["barrier-uncertain"] = raw })
	}
	for _, name := range []string{"uncertain", "data-uncertain", "copy-operation", "io-quarantined", "commit-proof", "unrecognized"} {
		reject(func(c map[string][]byte) { c[name] = []byte("unrelated") })
	}
	for _, raw := range [][]byte{nil, []byte("{}"), append(bytes.Clone(census["barrier-uncertain"]), '\n'), bytes.Repeat([]byte("x"), 4097)} {
		reject(func(c map[string][]byte) { c["barrier-uncertain"] = raw })
	}
	reject(func(c map[string][]byte) { c["state.json"] = m.BeforeDisk })
	_, next, _, err := prepareRetirementImages(m)
	must(t, err)
	reject(func(c map[string][]byte) { c["state.json"] = next })
}
