//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storagemanaged

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

const retirementWorkerEnv = "CENGINE_NATIVE_RETIREMENT_RECOVERY_WORKER"
const retirementPendingBarrier = "Uncertain authority IO or barrier: offline repair required.\n"

type retirementManifest struct {
	Public     policyManifest
	Plan       a.NativeRetirementRecoveryPlan
	BeforeDisk json.RawMessage
}

type retirementObservation struct {
	Authority       a.NativeRetirementRecoveryObservation
	Closed          int
	ResourcesClosed bool
	Census          [32]byte
}

type retirementOperation struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

// Public on-disk fields in canonical order. Opaque copy records remain bytes;
// this validator cannot accidentally overlook grants, operations or successors.
type retirementImage struct {
	Schema           int                          `json:"schema"`
	Durability       int                          `json:"durability"`
	Revision         uint64                       `json:"revision"`
	Store            a.Store                      `json:"store"`
	Epoch            a.ID                         `json:"epoch"`
	Controller       a.Controller                 `json:"controller"`
	Bootstrap        a.Fingerprint                `json:"bootstrap"`
	ControllerKeys   *struct{}                    `json:"controller_keys"`
	Volumes          map[a.ID]a.Volume            `json:"volumes"`
	VolumeLifecycles map[a.ID]a.VolumeLifecycle   `json:"volume_lifecycles"`
	Attachments      map[a.ID]a.Attachment        `json:"attachments"`
	Prepares         map[a.ID]a.Prepare           `json:"prepares"`
	Operations       map[a.ID]retirementOperation `json:"operations"`
	Grants           *struct{}                    `json:"grants"`
	Copy             json.RawMessage              `json:"copy,omitempty"`
	CopyReplay       json.RawMessage              `json:"copy_replay,omitempty"`
	Lifecycle        *retirementLifecycleImage    `json:"lifecycle,omitempty"`
}

// Preserve every lifecycle byte in the full-image assertions; only a successful
// live open may advance its anchor alongside the startup revision.
type retirementLifecycleImage struct {
	Version       string              `json:"version"`
	Identity      a.LifecycleIdentity `json:"identity"`
	Latest        json.RawMessage     `json:"latest"`
	OpenRevision  uint64              `json:"open_revision"`
	Retiring      json.RawMessage     `json:"retiring,omitempty"`
	Seal          json.RawMessage     `json:"seal,omitempty"`
	ColdApplied   json.RawMessage     `json:"cold_applied,omitempty"`
	ResumeApplied json.RawMessage     `json:"resume_applied,omitempty"`
}

func retirementStage(kind string) (a.NativeRetirementRecoveryStage, error) {
	switch kind {
	case "candidate":
		return a.NativeRetirementCandidate, nil
	case "certified":
		return a.NativeRetirementCertified, nil
	case "prepared", "completed":
		return a.NativeRetirementPrepared, nil
	case "published":
		return a.NativeRetirementPublished, nil
	default:
		return 0, errors.New("invalid retirement worker selection")
	}
}

// Separate, fresh, gated worker; deliberately excluded from the RTM108 selector.
// The inherited descriptors, not an environment path or stdout, bind the protocol.
func TestNativeRetirementRecoveryWorker(t *testing.T) {
	kind := os.Getenv(retirementWorkerEnv)
	if kind == "" {
		return
	}
	stage, err := retirementStage(kind)
	must(t, err)
	if os.Geteuid() != 0 {
		t.Fatal("native retirement recovery requires Linux root")
	}
	root, commands, proofs := os.NewFile(3, "retirement-root"), os.NewFile(4, "retirement-commands"), os.NewFile(5, "retirement-proofs")
	defer root.Close()
	defer commands.Close()
	defer proofs.Close()
	must(t, policyPipe(commands, unix.O_RDONLY))
	must(t, policyPipe(proofs, unix.O_WRONLY))
	left, err := stat(int(commands.Fd()))
	must(t, err)
	right, err := stat(int(proofs.Fd()))
	must(t, err)
	if left.Dev == right.Dev && left.Ino == right.Ino {
		t.Fatal("aliased protocol pipes")
	}
	rst, err := stat(int(root.Fd()))
	must(t, err)
	if rst.Mode&unix.S_IFMT != unix.S_IFDIR || rst.Uid != uint32(os.Geteuid()) {
		t.Fatal("unowned fixture root")
	}
	f := newFixtureAt(t, "/proc/self/fd/3")
	stableSession, stableRoot := f.session(a.ReadWrite)
	created := f.call(stableSession, caller(1001, 1001), w.CreateRequest{Parent: stableRoot.Node, Name: []byte("payload"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	written := f.call(stableSession, grantAuth, w.WriteRequest{Node: created.Entry.Node, Handle: created.Opened.Handle, Data: []byte(policyACK)}).(w.WriteReply)
	if written.Written != uint32(len(policyACK)) {
		t.Fatal("short acknowledged identity-worker write")
	}
	stable, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: f.storeID, Volume: f.volumeID, Attachment: stableSession.binding.Attachment, Launch: stableSession.binding.Launch})
	must(t, err)
	if !stableSession.closed || len(stableSession.handles) != 0 || len(stableSession.nodes) != 0 || len(f.registry.objects) != 0 {
		t.Fatal("stable receipt without real resource drain")
	}
	s, entry := f.session(a.ReadWrite)
	payload := f.call(s, caller(1001, 1001), w.LookupRequest{Parent: entry.Node, Name: []byte("payload")}).(w.LookupReply)
	f.call(s, caller(1001, 1001), w.OpenRequest{Node: payload.Entry.Node, Flags: w.OpenReadWrite})
	before, err := f.authority.Query(f.control)
	must(t, err)
	initial, err := policyCensus(root)
	must(t, err)
	m := retirementManifest{Public: policyManifest{Lifecycle: *f.lifecycle, Kind: "barrier", Bootstrap: f.bootstrap, Before: before, Stable: stable, Binding: s.binding, Operation: newID(t), ACK: []byte(policyACK)}, BeforeDisk: initial["state.json"]}
	m.Plan = a.NativeRetirementRecoveryPlan{Stage: stage, Binding: s.binding, Epoch: before.Epoch, Controller: before.Controller, Operation: m.Public.Operation}
	// Rejected plans cannot install or overwrite a journal hook.
	for _, mutate := range []func(*a.NativeRetirementRecoveryPlan){
		func(p *a.NativeRetirementRecoveryPlan) { p.Binding.Launch = newID(t) },
		func(p *a.NativeRetirementRecoveryPlan) { p.Epoch = newID(t) },
		func(p *a.NativeRetirementRecoveryPlan) { p.Controller.Epoch++ },
		func(p *a.NativeRetirementRecoveryPlan) { p.Stage = 255 },
	} {
		bad := m.Plan
		mutate(&bad)
		if witness, err := f.authority.NewNativeRetirementRecoveryWitness(bad); err == nil || witness != nil {
			t.Fatal("installed wrong binding/stage plan")
		}
	}
	witness, err := f.authority.NewNativeRetirementRecoveryWitness(m.Plan)
	must(t, err)
	if err := witness.Release(); err == nil {
		t.Fatal("released before actual hold")
	}
	if duplicate, err := f.authority.NewNativeRetirementRecoveryWitness(m.Plan); err == nil || duplicate != nil {
		t.Fatal("overwrote installed afterStep hook")
	}
	must(t, policySend(proofs, m))
	policyCommand(t, commands, 'A') // parent fsynced the earlier ACK manifest first
	fds := []int{int(s.root.Fd()), int(s.metadataFD.Fd())}
	for _, h := range s.handles {
		fds = append(fds, h.fd)
	}
	for _, n := range s.nodes {
		fds = append(fds, n.fd)
	}
	for _, obj := range f.registry.objects {
		fds = append(fds, obj.fd)
	}
	calls, closed := 0, 0
	f.registry.syncOps.syncfs = func(fd int) error {
		calls++
		if calls != 1 || f.registry.barrierBinding == nil || *f.registry.barrierBinding != s.binding ||
			!s.closed || len(s.handles) != 0 || len(s.nodes) != 0 || len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 {
			return errors.New("wrong real retained-resource barrier seam")
		}
		// Check before journal IO can reuse descriptor numbers, after ALL owners close.
		for _, fd := range fds {
			if _, err := stat(fd); !errors.Is(err, unix.EBADF) {
				return errors.New("retained descriptor at final syncfs")
			}
			closed++
		}
		return unix.Syncfs(fd) // never fake success or hold inside the barrier
	}
	type result struct {
		receipt a.Receipt
		err     error
	}
	finished := make(chan result, 1)
	go func() {
		receipt, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: m.Public.Operation, Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch})
		finished <- result{receipt, err}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	observation, err := witness.Wait(ctx)
	must(t, err)
	if calls != 1 || closed != len(fds) || !s.closed || len(s.handles) != 0 || len(s.nodes) != 0 || len(f.registry.sessions) != 0 || len(f.registry.objects) != 0 || f.registry.barrierBinding != nil {
		t.Fatal("certificate did not follow complete real registry barrier return")
	}
	cut, err := policyCensus(root)
	must(t, err)
	proof := retirementObservation{Authority: observation, Closed: closed, ResourcesClosed: true, Census: policyDigest(cut)}
	must(t, retirementValidateProof(m, proof, cut))
	must(t, policySend(proofs, proof))
	policyCommand(t, commands, 'R')
	must(t, witness.Release())
	if err := witness.Release(); err == nil {
		t.Fatal("released twice")
	}
	completion := <-finished
	must(t, completion.err)
	cut, err = policyCensus(root)
	must(t, err)
	must(t, retirementValidateCompletion(m, completion.receipt, cut))
	must(t, policySend(proofs, policyCompletion{Receipt: completion.receipt}))
	policyCommand(t, commands, '!')
	t.Fatal("parent must SIGKILL, not release final hold")
}

// Process-death evidence only: Linux/ext4 stay alive; no VM power-loss claim.
// Seven selected names: this parent, five leaves, and the separate Helpers test.
func TestNativeRetirementRecoveryProcessDeath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires Linux root and real ext4 storageidentity capabilities")
	}
	for _, kind := range []string{"candidate", "certified", "prepared", "published", "completed"} {
		t.Run(kind, func(t *testing.T) { retirementProcessDeath(t, kind) })
	}
}

func retirementProcessDeath(t *testing.T, kind string) {
	t.Helper()
	path, err := os.MkdirTemp("", "native-retirement-")
	must(t, err)
	joined := true
	t.Cleanup(func() {
		if joined {
			must(t, os.RemoveAll(path))
		} else {
			t.Logf("unjoined child: retained owned scratch %s", path)
		}
	})
	root, err := os.Open(path)
	must(t, err)
	defer root.Close()
	var fs unix.Statfs_t
	must(t, unix.Fstatfs(int(root.Fd()), &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("TMPDIR must be actual ext4 (runner-owned 128 MiB fixture)")
	}
	commands, commandWriter, err := os.Pipe()
	must(t, err)
	proofReader, proofs, err := os.Pipe()
	must(t, err)
	defer commands.Close()
	defer commandWriter.Close()
	defer proofReader.Close()
	defer proofs.Close()
	binaryPath, err := os.Executable()
	must(t, err)
	cmd := exec.Command(binaryPath, "-test.run=^TestNativeRetirementRecoveryWorker$", "-test.count=1", "-test.timeout=50s")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, retirementWorkerEnv+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, retirementWorkerEnv+"="+kind)
	cmd.ExtraFiles = []*os.File{root, commands, proofs}
	capture := new(policyOutput)
	cmd.Stdout, cmd.Stderr = capture, capture
	cmd.WaitDelay = 2 * time.Second
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
		done <- cmd.Wait() // sole actual Wait; EOF/timeouts never stand in for death
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
				t.Error("owned worker unjoined (not evidence of death)")
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
		t.Fatal("owned worker missing pidfd")
	}
	must(t, commands.Close())
	must(t, proofs.Close())
	must(t, proofReader.SetReadDeadline(time.Now().Add(40*time.Second)))
	must(t, commandWriter.SetWriteDeadline(time.Now().Add(40*time.Second)))
	var m retirementManifest
	must(t, policyReceive(proofReader, &m))
	must(t, retirementValidateManifest(m))
	stage, err := retirementStage(kind)
	must(t, err)
	st, err := stat(int(root.Fd()))
	must(t, err)
	if m.Plan.Stage != stage || m.Public.Before.Store.Root != (a.RootIdentity{Device: st.Dev, Inode: st.Ino}) {
		t.Fatal("manifest not bound to selected root/stage")
	}
	initial, err := policyCensus(root)
	must(t, err)
	if !bytes.Equal(initial["state.json"], m.BeforeDisk) {
		t.Fatal("manifest differs from actual durable predecessor")
	}
	ack, err := os.OpenFile(filepath.Join(path, "parent-ack.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	must(t, policySend(ack, m))
	must(t, ack.Sync())
	must(t, ack.Close())
	must(t, root.Sync())
	ackBytes, err := policyReadPath(root, "parent-ack.json", policyLimit)
	must(t, err)
	_, err = commandWriter.Write([]byte{'A'})
	must(t, err)
	var proof retirementObservation
	must(t, policyReceive(proofReader, &proof))
	cut, err := policyCensus(root)
	must(t, err)
	must(t, retirementValidateProof(m, proof, cut))
	policyLogCensus(t, kind+"-held", cut)
	if kind == "completed" {
		_, err = commandWriter.Write([]byte{'R'})
		must(t, err)
		var completion policyCompletion
		must(t, policyReceive(proofReader, &completion))
		if completion.Sequence != 0 || completion.Count != 0 {
			t.Fatal("non-retirement completion")
		}
		cut, err = policyCensus(root)
		must(t, err)
		must(t, retirementValidateCompletion(m, completion.Receipt, cut))
		policyLogCensus(t, "completed-real-retire-return", cut)
	}
	must(t, unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0))
	select {
	case err = <-done:
		joined = cmd.ProcessState != nil
		if !policyKilled(err, cmd.ProcessState) {
			t.Fatalf("expected actual SIGKILL/Wait, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGKILL deadline is NOT proof of death")
	}
	dead, err := policyCensus(root)
	must(t, err)
	if !reflect.DeepEqual(cut, dead) {
		t.Fatal("registry changed between held proof and actual death")
	}
	retirementCheckACK(t, root, ackBytes)
	registry, err := NewRegistry(new(sync.Mutex))
	must(t, err)
	barriers := 0
	cfg := a.Config{Root: root, DeviceID: m.Public.Before.Store.DeviceID, BootstrapKey: m.Public.Bootstrap, Barrier: func(b a.Binding, fd *os.File) error {
		barriers++
		return registry.Barrier(b, fd)
	}}
	if kind != "completed" {
		lifecycleRecoveryRefuseUnanchored(t, cfg, &m.Public.Lifecycle, func() {
			unchanged, err := policyCensus(root)
			must(t, err)
			if !reflect.DeepEqual(dead, unchanged) || barriers != 0 {
				t.Fatal("unanchored refusal changed census or invoked barrier")
			}
			retirementCheckACK(t, root, ackBytes)
		})
	}
	previous := dead
	for attempt := 1; attempt <= 2; attempt++ {
		var expected retirementImage
		must(t, policyJSON(previous["state.json"], &expected))
		reopened := lifecycleRecoveryOpenExact(t, cfg, &m.Public.Lifecycle)
		epoch := reopened.Epoch()
		must(t, reopened.Close())
		if barriers != 0 || epoch == expected.Epoch {
			t.Fatal("recovery invoked barrier or failed fresh E rotation")
		}
		expected.Epoch, expected.Revision = epoch, expected.Revision+1
		expected.Lifecycle.OpenRevision = expected.Revision
		post, err := policyCensus(root)
		must(t, err)
		want, err := json.Marshal(expected)
		must(t, err)
		if !bytes.Equal(post["state.json"], want) {
			t.Fatal("recovery manufactured receipt/control/successor authority or changed old binding fence")
		}
		target := expected.Attachments[m.Plan.Binding.Attachment]
		if target.Phase != a.Retiring && target.Phase != a.Drained {
			t.Fatal("old binding became active")
		}
		// The held census was validated against the exact certificate and A6
		// prior/next pair above. Schema 4 removes those bound state/proof
		// temporaries without adopting them; no filename-pattern waiver.
		if !reflect.DeepEqual(post, map[string][]byte{"lock": previous["lock"], "state.json": want}) {
			t.Fatal("recovery did not leave the exact state/lock census")
		}
		retirementCheckACK(t, root, ackBytes)
		policyLogCensus(t, fmt.Sprintf("recovered-exact-%d", attempt), post)
		previous = post
	}
}

func retirementCheckACK(t *testing.T, root *os.File, ack []byte) {
	t.Helper()
	payload, err := policyReadPath(root, "volumes/data/payload", policyFileLimit)
	must(t, err)
	journal, err := policyReadPath(root, "parent-ack.json", policyLimit)
	must(t, err)
	if string(payload) != policyACK || !bytes.Equal(journal, ack) {
		t.Fatal("lost externally acknowledged payload/manifest")
	}
}

func retirementValidateManifest(m retirementManifest) error {
	if err := policyValidateManifest(m.Public, "barrier"); err != nil {
		return err
	}
	if err := m.Plan.Validate(); err != nil {
		return err
	}
	if m.Plan.Binding != m.Public.Binding || m.Plan.Epoch != m.Public.Before.Epoch || m.Plan.Controller != m.Public.Before.Controller || m.Plan.Operation != m.Public.Operation {
		return errors.New("plan/manifest binding mismatch")
	}
	var image retirementImage
	if len(m.BeforeDisk) > policyFileLimit {
		return errors.New("oversized initial image")
	}
	if err := policyJSON(m.BeforeDisk, &image); err != nil {
		return err
	}
	state, err := policyState(map[string][]byte{"state.json": m.BeforeDisk})
	if err != nil || !reflect.DeepEqual(state, m.Public.Before) || image.Revision > ^uint64(0)-2 || image.Operations == nil {
		return errors.New("non-exact initial image")
	}
	if _, exists := image.Operations[m.Plan.Operation]; exists {
		return errors.New("selected retirement already exists")
	}
	return nil
}

func retirementImages(m retirementManifest) ([]byte, []byte, a.Receipt, error) {
	var image retirementImage
	if err := policyJSON(m.BeforeDisk, &image); err != nil {
		return nil, nil, a.Receipt{}, err
	}
	b := m.Plan.Binding
	req := a.RetireRequest{Operation: m.Plan.Operation, Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, nil, a.Receipt{}, err
	}
	image.Operations[m.Plan.Operation] = retirementOperation{"retire", retirementDigest(raw)}
	image.Revision++
	rec := image.Attachments[b.Attachment]
	rec.Phase, rec.Retirement = a.Retiring, m.Plan.Operation
	image.Attachments[b.Attachment] = rec
	prior, err := json.Marshal(image)
	if err != nil {
		return nil, nil, a.Receipt{}, err
	}
	image.Revision++
	receipt := a.Receipt{Schema: a.SchemaVersion, Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch, Prepare: b.Prepare, Revision: image.Revision}
	rec.Phase, rec.Receipt = a.Drained, &receipt
	image.Attachments[b.Attachment] = rec
	next, err := json.Marshal(image)
	return prior, next, receipt, err
}

func retirementDigest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func retirementValidateProof(m retirementManifest, o retirementObservation, census map[string][]byte) error {
	if err := retirementValidateManifest(m); err != nil {
		return err
	}
	if o.Authority.Plan != m.Plan || o.Authority.BarrierSucceeded != 1 || !o.ResourcesClosed || o.Closed < 5 || o.Census != policyDigest(census) {
		return errors.New("unbound retirement observation/census")
	}
	prior, next, _, err := retirementImages(m)
	if err != nil {
		return err
	}
	certificateName := "barrier-uncertain"
	if m.Plan.Stage == a.NativeRetirementCandidate {
		if string(census["barrier-uncertain"]) != retirementPendingBarrier {
			return errors.New("candidate cut missing exact generic pending barrier")
		}
		certificateName = ""
		for name := range census {
			if strings.HasPrefix(name, "barrier-") && strings.HasSuffix(name, ".tmp") {
				if certificateName != "" {
					return errors.New("multiple completed barrier candidates")
				}
				certificateName = name
			}
		}
		if certificateName == "" {
			return errors.New("candidate cut missing completed barrier candidate")
		}
	}
	var cert a.NativeRetirementRecoveryCertificate
	if len(census[certificateName]) > 4096 {
		return errors.New("oversized completed barrier certificate")
	}
	if err := policyJSON(census[certificateName], &cert); err != nil {
		return err
	}
	attempt := m.Plan
	attempt.Operation = cert.Attempt
	if err := attempt.Validate(); err != nil {
		return err
	}
	if m.Plan.Stage == a.NativeRetirementCandidate && certificateName != "barrier-"+string(cert.Attempt)+".tmp" {
		return errors.New("completed barrier candidate name/attempt mismatch")
	}
	boot, err := a.PublicKeyFingerprint(m.Public.Bootstrap)
	if err != nil {
		return err
	}
	want := a.NativeRetirementRecoveryCertificate{Version: 1, Attempt: cert.Attempt, Store: m.Public.Before.Store, Epoch: m.Plan.Epoch, Controller: m.Plan.Controller, Bootstrap: boot, Volume: m.Public.Before.Volumes[m.Plan.Binding.Volume], Binding: m.Plan.Binding, Operation: m.Plan.Operation, Revision: m.Public.Before.Revision + 2, Prior: retirementDigest(prior), Next: retirementDigest(next)}
	if cert != want || o.Authority.Certificate != want {
		return errors.New("completed certificate is not the exact bound prior/next pair")
	}
	visible := prior
	if m.Plan.Stage == a.NativeRetirementPublished {
		visible = next
	}
	if !bytes.Equal(census["state.json"], visible) || o.Authority.StateDigest != retirementDigest(visible) {
		return errors.New("wrong exact visible retirement image")
	}
	allowed := map[string]bool{"lock": true, "state.json": true, "barrier-uncertain": true}
	if m.Plan.Stage == a.NativeRetirementCandidate {
		allowed[certificateName] = true
	}
	if m.Plan.Stage == a.NativeRetirementCertified || m.Plan.Stage == a.NativeRetirementCandidate {
		if o.Authority.Metadata != nil || o.Authority.ReadyTemporary != nil || o.Authority.CandidateDigest != "" {
			return errors.New("pre-metadata cut already entered receipt metadata transaction")
		}
	} else {
		var meta a.NativeRetirementRecoveryMetadata
		if err := policyJSON(census["commit-proof"], &meta); err != nil {
			return err
		}
		wantMeta := a.NativeRetirementRecoveryMetadata{Version: 2, Store: m.Plan.Binding.Store, Epoch: m.Plan.Epoch, Revision: want.Revision, Prior: want.Prior, Next: want.Next, Ready: m.Plan.Stage == a.NativeRetirementPublished}
		if meta != wantMeta || o.Authority.Metadata == nil || *o.Authority.Metadata != meta {
			return errors.New("metadata/completed certificate mismatch")
		}
		allowed["commit-proof"] = true
		if m.Plan.Stage == a.NativeRetirementPrepared {
			wantMeta.Ready = true
			if o.Authority.ReadyTemporary == nil || *o.Authority.ReadyTemporary != wantMeta || o.Authority.CandidateDigest != want.Next {
				return errors.New("missing actual A6 Ready temporary/candidate")
			}
			readyRaw, _ := json.Marshal(wantMeta)
			proofs, states := 0, 0
			for name, raw := range census {
				if strings.HasPrefix(name, "proof-") && strings.HasSuffix(name, ".tmp") {
					proofs++
					if !bytes.Equal(raw, readyRaw) {
						return errors.New("wrong unpublished Ready bytes")
					}
					allowed[name] = true
				}
				if strings.HasPrefix(name, "state-") && strings.HasSuffix(name, ".tmp") {
					states++
					if !bytes.Equal(raw, next) {
						return errors.New("wrong unpublished candidate")
					}
					allowed[name] = true
				}
			}
			if proofs != 1 || states != 1 {
				return errors.New("non-exact A6 temporary census")
			}
		} else if o.Authority.ReadyTemporary != nil || o.Authority.CandidateDigest != "" {
			return errors.New("published cut retained candidate observation")
		}
	}
	for name := range census {
		if !allowed[name] {
			return fmt.Errorf("unexpected cut file %s", name)
		}
	}
	return nil
}

func retirementValidateCompletion(m retirementManifest, receipt a.Receipt, census map[string][]byte) error {
	if err := policyValidateCompletion(m.Public, policyCompletion{Receipt: receipt}, census); err != nil {
		return err
	}
	_, next, want, err := retirementImages(m)
	if err != nil {
		return err
	}
	if receipt != want || !bytes.Equal(census["state.json"], next) || len(census) != 2 {
		return errors.New("completed Retire did not return exact receipt after proof/barrier clear")
	}
	return nil
}

// A parser fixture only, not a native durability fixture or a barrier substitute.
func retirementParserFixture(t *testing.T, plan a.NativeRetirementRecoveryPlan, stage a.NativeRetirementRecoveryStage) (retirementManifest, retirementObservation, map[string][]byte) {
	t.Helper()
	plan.Stage = stage
	bootstrap := key(t).Public().(ed25519.PublicKey)
	boot, err := a.PublicKeyFingerprint(bootstrap)
	must(t, err)
	stableBinding := plan.Binding
	stableBinding.Attachment, stableBinding.Launch = newID(t), newID(t)
	stable := a.Receipt{Schema: a.SchemaVersion, Store: stableBinding.Store, Volume: stableBinding.Volume, Attachment: stableBinding.Attachment, Launch: stableBinding.Launch, Revision: 8}
	image := retirementImage{Schema: a.LifecycleSchemaVersion, Durability: 1, Revision: 10,
		Store: a.Store{ID: plan.Binding.Store, DeviceID: "parser-only", Root: a.RootIdentity{Device: 1, Inode: 2}, Exports: a.RootIdentity{Device: 1, Inode: 3}},
		Epoch: plan.Epoch, Controller: plan.Controller, Bootstrap: boot,
		Volumes:          map[a.ID]a.Volume{plan.Binding.Volume: {ID: plan.Binding.Volume, Name: "data", Root: a.RootIdentity{Device: 1, Inode: 4}}},
		VolumeLifecycles: map[a.ID]a.VolumeLifecycle{},
		Attachments:      map[a.ID]a.Attachment{plan.Binding.Attachment: {Binding: plan.Binding, Phase: a.Active}, stableBinding.Attachment: {Binding: stableBinding, Phase: a.Drained, Receipt: &stable}},
		Prepares:         map[a.ID]a.Prepare{}, Operations: map[a.ID]retirementOperation{}, Lifecycle: &retirementLifecycleImage{Version: a.LifecycleVersion, Identity: a.LifecycleIdentity{Store: plan.Binding.Store, Generation: 1, Binding: boot}, Latest: json.RawMessage(`{}`), OpenRevision: 1}}
	raw, err := json.Marshal(image)
	must(t, err)
	before, err := policyState(map[string][]byte{"state.json": raw})
	must(t, err)
	m := retirementManifest{Public: policyManifest{Kind: "barrier", Bootstrap: bootstrap, Before: before, Stable: stable, Binding: plan.Binding, Operation: plan.Operation, ACK: []byte(policyACK)}, Plan: plan, BeforeDisk: raw}
	prior, next, _, err := retirementImages(m)
	must(t, err)
	cert := a.NativeRetirementRecoveryCertificate{Version: 1, Attempt: newID(t), Store: image.Store, Epoch: plan.Epoch, Controller: plan.Controller, Bootstrap: boot, Volume: image.Volumes[plan.Binding.Volume], Binding: plan.Binding, Operation: plan.Operation, Revision: 12, Prior: retirementDigest(prior), Next: retirementDigest(next)}
	certRaw, err := json.Marshal(cert)
	must(t, err)
	census := map[string][]byte{"lock": {}, "state.json": prior, "barrier-uncertain": certRaw}
	o := retirementObservation{Authority: a.NativeRetirementRecoveryObservation{Plan: plan, Certificate: cert, StateDigest: cert.Prior, BarrierSucceeded: 1}, Closed: 7, ResourcesClosed: true}
	if stage == a.NativeRetirementCandidate {
		census["barrier-uncertain"] = []byte(retirementPendingBarrier)
		census["barrier-"+string(cert.Attempt)+".tmp"] = certRaw
	} else if stage != a.NativeRetirementCertified {
		meta := a.NativeRetirementRecoveryMetadata{Version: 2, Store: image.Store.ID, Epoch: plan.Epoch, Revision: 12, Prior: cert.Prior, Next: cert.Next, Ready: stage == a.NativeRetirementPublished}
		o.Authority.Metadata = &meta
		census["commit-proof"], err = json.Marshal(meta)
		must(t, err)
		if stage == a.NativeRetirementPrepared {
			ready := meta
			ready.Ready = true
			o.Authority.ReadyTemporary, o.Authority.CandidateDigest = &ready, cert.Next
			census["proof-"+string(newID(t))+".tmp"], err = json.Marshal(ready)
			must(t, err)
			census["state-"+string(newID(t))+".tmp"] = next
		} else {
			census["state.json"], o.Authority.StateDigest = next, cert.Next
		}
	}
	o.Census = policyDigest(census)
	return m, o, census
}

func TestNativeRetirementRecoveryHelpers(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("{}{}"), []byte(`{"Unknown":1}`), []byte(`{"Closed":1,"Closed":2}`), []byte(`null`), bytes.Repeat([]byte("x"), policyLimit+1)} {
		if policyJSON(raw, new(retirementObservation)) == nil {
			t.Fatal("accepted malformed proof")
		}
	}
	if _, err := retirementStage("unknown"); err == nil {
		t.Fatal("accepted open-ended stage")
	}
	if (a.NativeRetirementRecoveryPlan{}).Validate() == nil {
		t.Fatal("accepted empty plan")
	}
	if retirementValidateProof(retirementManifest{}, retirementObservation{}, nil) == nil {
		t.Fatal("accepted empty proof")
	}
	if policyKilled(nil, nil) || policyKilled(errors.New("deadline"), nil) || policyKilled(&exec.ExitError{}, nil) {
		t.Fatal("non-signal completion counted as death")
	}
	// A genuine successful Wait is not process-death proof, either.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$", "-test.count=1")
	output := new(policyOutput)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, output, 2*time.Second
	err := cmd.Run()
	must(t, err)
	if cmd.ProcessState == nil || policyKilled(err, cmd.ProcessState) {
		t.Fatal("successful real Wait counted as SIGKILL")
	}
	// Parser controls only; never reported as native barrier/death evidence.
	b := a.Binding{Store: newID(t), Volume: newID(t), Attachment: newID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: newID(t), Key: a.Fingerprint(strings.Repeat("b", 64)), Role: a.RuntimeRole, Mode: a.ReadWrite}
	plan := a.NativeRetirementRecoveryPlan{Stage: a.NativeRetirementCertified, Binding: b, Epoch: newID(t), Controller: a.Controller{Epoch: 1, Key: a.Fingerprint(strings.Repeat("c", 64))}, Operation: newID(t)}
	must(t, plan.Validate())
	for _, mutate := range []func(*a.NativeRetirementRecoveryPlan){
		func(p *a.NativeRetirementRecoveryPlan) { p.Stage = 0 },
		func(p *a.NativeRetirementRecoveryPlan) { p.Stage = 5 },
		func(p *a.NativeRetirementRecoveryPlan) { p.Binding.Launch = "bad" },
		func(p *a.NativeRetirementRecoveryPlan) { p.Binding.Prepare = newID(t) },
		func(p *a.NativeRetirementRecoveryPlan) { p.Binding.Role = a.PrepareRole },
		func(p *a.NativeRetirementRecoveryPlan) { p.Binding.Mode = a.ReadOnly },
		func(p *a.NativeRetirementRecoveryPlan) { p.Epoch = "bad" },
		func(p *a.NativeRetirementRecoveryPlan) { p.Operation = "bad" },
		func(p *a.NativeRetirementRecoveryPlan) { p.Controller.Key = "bad" },
	} {
		bad := plan
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("accepted malformed closed plan")
		}
	}
	// A known-valid parser control is corrupted one field at a time; none of
	// these synthetic bytes are ever written to a registry or passed to Open.
	stages := []a.NativeRetirementRecoveryStage{a.NativeRetirementCandidate, a.NativeRetirementCertified, a.NativeRetirementPrepared, a.NativeRetirementPublished}
	for _, stage := range stages {
		m, proof, census := retirementParserFixture(t, plan, stage)
		must(t, retirementValidateProof(m, proof, census))
		// Rebind both protocol plans: the actual disk boundary must still match.
		for _, otherStage := range stages {
			if otherStage == stage {
				continue
			}
			wrongManifest, wrongProof := m, proof
			wrongManifest.Plan.Stage, wrongProof.Authority.Plan.Stage = otherStage, otherStage
			if retirementValidateProof(wrongManifest, wrongProof, census) == nil {
				t.Fatal("accepted evidence from another closed stage")
			}
		}
		rejectCensus := func(mutate func(map[string][]byte)) {
			t.Helper()
			changed := make(map[string][]byte, len(census))
			for name, raw := range census {
				changed[name] = bytes.Clone(raw)
			}
			mutate(changed)
			bad := proof
			bad.Census = policyDigest(changed)
			if retirementValidateProof(m, bad, changed) == nil {
				t.Fatal("accepted malformed or conflicting retirement census")
			}
		}
		for _, marker := range []string{"uncertain", "io-quarantined", "data-uncertain"} {
			rejectCensus(func(c map[string][]byte) { c[marker] = []byte(retirementPendingBarrier) })
		}
		if stage == a.NativeRetirementCandidate {
			candidate := "barrier-" + string(proof.Authority.Certificate.Attempt) + ".tmp"
			_, next, _, err := retirementImages(m)
			must(t, err)
			for _, mutate := range []func(map[string][]byte){
				func(c map[string][]byte) { delete(c, candidate) },
				func(c map[string][]byte) { delete(c, "barrier-uncertain") },
				func(c map[string][]byte) { c["barrier-uncertain"] = c[candidate] },
				func(c map[string][]byte) { c["barrier-uncertain"] = []byte(retirementPendingBarrier + "\n") },
				func(c map[string][]byte) { c[candidate] = nil },
				func(c map[string][]byte) { c[candidate] = []byte("{}") },
				func(c map[string][]byte) { c[candidate] = append(c[candidate], '\n') },
				func(c map[string][]byte) { c[candidate] = append(c[candidate], []byte("{}")...) },
				func(c map[string][]byte) { c[candidate] = bytes.Repeat([]byte("x"), 4097) },
				func(c map[string][]byte) { c["barrier-"+string(newID(t))+".tmp"] = c[candidate] },
				func(c map[string][]byte) {
					c["barrier-"+string(newID(t))+".tmp"] = c[candidate]
					delete(c, candidate)
				},
				func(c map[string][]byte) { c["state.json"] = next },
			} {
				rejectCensus(mutate)
			}
			// Even metadata for the exact same prior/next pair is forbidden here.
			for _, ready := range []bool{false, true} {
				cert := proof.Authority.Certificate
				meta := a.NativeRetirementRecoveryMetadata{Version: 2, Store: cert.Store.ID, Epoch: cert.Epoch, Revision: cert.Revision, Prior: cert.Prior, Next: cert.Next, Ready: ready}
				raw, err := json.Marshal(meta)
				must(t, err)
				rejectCensus(func(c map[string][]byte) { c["commit-proof"] = raw })
				bad := proof
				bad.Authority.Metadata = &meta
				if retirementValidateProof(m, bad, census) == nil {
					t.Fatal("accepted metadata observation at candidate cut")
				}
			}
		}
		for _, mutate := range []func(*retirementObservation){
			func(p *retirementObservation) { p.Authority.Plan.Binding.Launch = newID(t) },
			func(p *retirementObservation) { p.Authority.Plan.Stage = 255 },
			func(p *retirementObservation) {
				p.Authority.Certificate.Binding.Container = a.ContainerID(strings.Repeat("d", 64))
			},
			func(p *retirementObservation) { p.Authority.Certificate.Attempt = newID(t) },
			func(p *retirementObservation) { p.Authority.Certificate.Operation = newID(t) },
			func(p *retirementObservation) { p.Authority.Certificate.Revision++ },
			func(p *retirementObservation) { p.Authority.Certificate.Prior = p.Authority.Certificate.Next },
			func(p *retirementObservation) { p.Authority.BarrierSucceeded = 0 },
			func(p *retirementObservation) { p.ResourcesClosed = false },
			func(p *retirementObservation) { p.Census = [32]byte{} },
		} {
			bad := proof
			mutate(&bad)
			if retirementValidateProof(m, bad, census) == nil {
				t.Fatal("accepted wrong-bound proof")
			}
		}
		if proof.Authority.Metadata != nil {
			bad := proof
			meta := *proof.Authority.Metadata
			meta.Ready = !meta.Ready
			bad.Authority.Metadata = &meta
			if retirementValidateProof(m, bad, census) == nil {
				t.Fatal("accepted wrong metadata Ready")
			}
		}
		badCensus := make(map[string][]byte, len(census))
		for name, raw := range census {
			badCensus[name] = raw
		}
		badCensus["state.json"] = m.BeforeDisk
		bad := proof
		bad.Census = policyDigest(badCensus)
		if retirementValidateProof(m, bad, badCensus) == nil {
			t.Fatal("accepted unrelated visible state")
		}
	}
	var witness *a.NativeRetirementRecoveryWitness
	if witness.Release() == nil {
		t.Fatal("nil witness released")
	}
	if _, err := witness.Wait(t.Context()); err == nil {
		t.Fatal("nil witness observed")
	}
	if _, err := new(a.NativeRetirementRecoveryWitness).Wait(t.Context()); err == nil {
		t.Fatal("uninstalled witness observed")
	}
}
