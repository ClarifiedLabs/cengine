//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storagefuse_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Only the tagged test binary understands this flag. There is no production
// env/debug endpoint, arbitrary path/PID selector, or caller-supplied callback.
var nativeServiceFaultChild = flag.Bool("native-service-fault-child", false, "owned native fault child with fixed inherited descriptors")

const nativeServiceFaultSequence = 4

// A bounded capture prevents a failing child from consuming scratch indefinitely.
// os/exec owns and joins the pipe copier, with a finite WaitDelay.
type nativeServiceFaultOutput struct {
	mu        sync.Mutex
	file      *os.File
	remaining int
}

func (o *nativeServiceFaultOutput) Write(b []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(b)
	kept := min(n, o.remaining)
	if kept > 0 {
		_, err := o.file.Write(b[:kept])
		if err != nil {
			return 0, err
		}
		o.remaining -= kept
	}
	return n, nil
}

type nativeServiceFaultEvidence struct {
	Hello       a.DataHello
	Controller  a.Controller
	Reopen      staleLifecycleReopen
	Count       uint32
	Plan        a.NativeFaultPlan
	Observation a.NativeFaultObservation
	Receipt     *a.Receipt
}

func nativeServiceFaultProfile(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires disposable native Linux root fixture")
	}
	if filepath.Clean(os.TempDir()) != "/scratch" {
		t.Fatal("requires TMPDIR=/scratch")
	}
	var uts unix.Utsname
	staleMust(t, unix.Uname(&uts))
	if !strings.HasPrefix(string(bytes.TrimRight(uts.Release[:], "\x00")), "6.18.") {
		t.Fatal("requires patched Linux 6.18")
	}
	var fs unix.Statfs_t
	staleMust(t, unix.Statfs("/scratch", &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("/scratch must be real ext4")
	}
}

func nativeServiceFaultRootKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
}

func nativeServiceFaultConfig(t *testing.T, root *os.File, store a.ID) s.Config {
	t.Helper()
	// Fixed TEST-ONLY bootstrap identity allows exact parent reopen without a key
	// handoff channel. All controller and workload keys remain freshly generated.
	key := nativeServiceFaultRootKey()
	bootstrap, err := p.NewBootstrapPublicKey(key.Public().(ed25519.PublicKey))
	staleMust(t, err)
	return s.Config{Root: root, DeviceUUID: "native-service-data-fault-test", Store: store, Bootstrap: bootstrap, Now: time.Now().Add(-time.Minute), Lifetime: time.Hour}
}

// Component service/TLS acceptance, NOT a VM crash, power-loss or PREPARE claim.
// Six real DATA/retirement boundaries x EIO/ENOSPC, plus one durable lost reply.
// No operation deadline, cancellation, or transport loss is used as drain proof.
func TestNativeServiceFaults(t *testing.T) {
	nativeServiceFaultProfile(t)
	for _, stage := range []a.NativeFaultStage{a.NativeDataFsync, a.NativePostCreateNamespace, a.NativeRetireIntent, a.NativeRetireFinalSyncfs, a.NativeRetireReceipt, a.NativeRetireBarrierClear, a.NativeRetireLostReply} {
		errors := []a.NativeFaultError{a.NativeEIO, a.NativeENOSPC}
		if stage == a.NativeRetireLostReply {
			errors = []a.NativeFaultError{a.NativeDropReply}
		}
		for _, errno := range errors {
			t.Run(fmt.Sprintf("stage-%d-error-%d", stage, errno), func(t *testing.T) {
				if *nativeServiceFaultChild {
					nativeServiceFaultRun(t, stage, errno)
					return
				}
				nativeServiceFaultOwn(t, stage, errno)
			})
		}
	}
}

func nativeServiceFaultOwn(t *testing.T, stage a.NativeFaultStage, errno a.NativeFaultError) {
	t.Helper()
	path, err := os.MkdirTemp("/scratch", "native-service-fault-")
	staleMust(t, err)
	staleMust(t, os.Mkdir(filepath.Join(path, "volumes"), 0700))
	root, err := os.Open(path)
	staleMust(t, err)
	defer root.Close()
	report, err := os.OpenFile(filepath.Join(path, "child-evidence.json"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	staleMust(t, err)
	defer report.Close()
	output, err := os.OpenFile(filepath.Join(path, "child-output.txt"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	staleMust(t, err)
	defer output.Close()
	binary, err := os.Executable()
	staleMust(t, err)
	cmd := exec.Command(binary, "-test.run=^"+strings.ReplaceAll(t.Name(), "/", "$/^")+"$", "-test.timeout=30s", "-native-service-fault-child")
	cmd.ExtraFiles = []*os.File{root, report}
	capture := &nativeServiceFaultOutput{file: output, remaining: 64 << 10}
	cmd.Stdout, cmd.Stderr = capture, capture
	cmd.WaitDelay = 2 * time.Second
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	started, done := make(chan error, 1), make(chan error, 1)
	go func() {
		// PDEATHSIG belongs to the creating OS thread. Reserve it through the
		// sole real Wait, never substitute kill/cancellation for a joined exit.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		err := cmd.Wait()
		done <- err
		if cmd.ProcessState == nil {
			select {}
		}
	}()
	staleMust(t, <-started)
	if pidfd >= 0 {
		defer unix.Close(pidfd)
	}
	joined := false
	defer func() {
		if !joined {
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
				joined = cmd.ProcessState != nil
			case <-time.After(10 * time.Second):
				t.Error("owned child unjoined; retain fixture")
			}
		}
		if joined && !t.Failed() {
			staleMust(t, os.RemoveAll(path))
		} else {
			t.Logf("retained native fault evidence: %s", path)
		}
	}()
	if pidfd < 0 {
		t.Fatal("owned child missing pidfd; retain fixture")
	}
	select {
	case err = <-done:
		joined = cmd.ProcessState != nil
		if !joined || err != nil {
			t.Fatalf("owned fault child failed: %v; output retained", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("owned fault child exceeded bounded deadline")
	}
	_, err = report.Seek(0, io.SeekStart)
	staleMust(t, err)
	var evidence nativeServiceFaultEvidence
	decoder := json.NewDecoder(io.LimitReader(report, 4097))
	decoder.DisallowUnknownFields()
	staleMust(t, decoder.Decode(&evidence))
	if decoder.Decode(new(any)) != io.EOF || evidence.Count != 1 {
		t.Fatal("missing exact single-fire child evidence")
	}
	if evidence.Plan.Stage != stage || evidence.Plan.Error != errno || evidence.Plan.Validate() != nil || evidence.Plan.Epoch != evidence.Hello.Epoch || !evidence.Plan.Matches(evidence.Hello.Binding) || evidence.Observation.Fired != 1 {
		t.Fatal("child fault evidence does not match selected closed case")
	}
	if evidence.Reopen.Identity != evidence.Reopen.Current.Grant.Identity || evidence.Reopen.Identity.Store != evidence.Hello.Binding.Store || evidence.Reopen.Expected.Store != evidence.Hello.Binding.Store || evidence.Reopen.Expected.Epoch != evidence.Hello.Epoch || evidence.Reopen.Expected.Controller != evidence.Controller || evidence.Reopen.Expected.OpenRevision == 0 {
		t.Fatal("child reopen evidence does not match exact lifecycle predecessor")
	}
	if stage >= a.NativeRetireIntent {
		nativeServiceRetireEvidence(t, path, root, evidence)
		return
	}
	markerPath := filepath.Join(path, ".cengine-storage-authority", "data-uncertain")
	before, err := os.ReadFile(markerPath)
	staleMust(t, err)
	var marker struct {
		Version    int          `json:"version"`
		Epoch      a.ID         `json:"epoch"`
		Controller a.Controller `json:"controller"`
		Binding    a.Binding    `json:"binding"`
		Sequence   uint64       `json:"sequence"`
	}
	staleMust(t, json.Unmarshal(before, &marker))
	if marker.Version != 1 || marker.Epoch != evidence.Hello.Epoch || marker.Controller != evidence.Controller || marker.Binding != evidence.Hello.Binding || marker.Sequence != nativeServiceFaultSequence {
		t.Fatal("persisted DATA obligation differs from exact child target")
	}
	cfg := nativeServiceFaultConfig(t, root, evidence.Hello.Binding.Store)
	reopened, err := s.ReopenLifecycle(cfg, evidence.Reopen.Identity, evidence.Reopen.Current, evidence.Reopen.Expected)
	if reopened != nil || !errors.Is(err, a.ErrRepairRequired) {
		t.Fatalf("poisoned reopen: want ErrRepairRequired, got %v", err)
	}
	after, err := os.ReadFile(markerPath)
	staleMust(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("failed reopen changed persisted poison marker")
	}
}

func nativeServiceFaultRun(t *testing.T, stage a.NativeFaultStage, errno a.NativeFaultError) {
	root, report := os.NewFile(3, "owned-root"), os.NewFile(4, "owned-evidence")
	if root == nil || report == nil {
		t.Fatal("missing owned descriptors")
	}
	defer root.Close()
	defer report.Close()
	var fs unix.Statfs_t
	staleMust(t, unix.Fstatfs(int(root.Fd()), &fs))
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Fatal("owned root must be ext4")
	}
	cfg := nativeServiceFaultConfig(t, root, staleID(t))
	controllerKey, err := p.NewControllerKey()
	staleMust(t, err)
	current := staleLifecycleGrant(t, nativeServiceFaultRootKey(), cfg.Store, controllerKey)
	service, err := s.InitializeLifecycle(cfg, current)
	staleMust(t, err)
	// Intentionally NO LifecycleService.Close/Barrier cleanup: poison retains resources.
	// Only this owned child's joined exit releases those kernel descriptors.
	ready, err := service.Ready()
	staleMust(t, err)
	// Capture the live-open anchor before any poison makes Scope fail closed.
	predecessor := staleLifecyclePredecessor(t, service, current)
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	staleMust(t, err)
	pin, err := key.Fingerprint()
	staleMust(t, err)
	hello := a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: staleID(t), Attachment: staleID(t), Container: a.ContainerID(strings.Repeat("b", 64)), Launch: staleID(t), Key: a.Fingerprint(pin.String()), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	plan := a.NativeFaultPlan{Stage: stage, Error: errno, Store: hello.Binding.Store, Epoch: hello.Epoch, Volume: hello.Binding.Volume, Attachment: hello.Binding.Attachment, Sequence: nativeServiceFaultSequence}
	if stage >= a.NativeRetireIntent {
		plan.RetireOperation = staleID(t)
		plan.Sequence = 0
	}
	for _, mismatch := range []a.NativeFaultPlan{
		func() a.NativeFaultPlan { bad := plan; bad.Epoch = staleID(t); return bad }(),
		func() a.NativeFaultPlan { bad := plan; bad.Store = staleID(t); return bad }(),
	} {
		if _, err := service.InstallNativeFault(mismatch); !errors.Is(err, a.ErrConflict) {
			t.Fatalf("wrong S/E install: %v", err)
		}
	}
	counter, err := service.InstallNativeFault(plan)
	staleMust(t, err)
	if _, err := service.InstallNativeFault(plan); !errors.Is(err, a.ErrConflict) {
		t.Fatalf("duplicate install: %v", err)
	}
	controller, control, closeControl := nativeServiceFaultControl(t, service, ready, controllerKey, counter)
	staleCall(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: staleID(t), Store: plan.Store, Volume: plan.Volume, Name: "data"}})
	staleCall(t, control, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: staleID(t), Binding: hello.Binding}})
	binding, err := d.AttachmentBinding(hello)
	staleMust(t, err)
	csr, err := key.CSR(binding)
	staleMust(t, err)
	raw, csrJoin := staleTCP(t, service.ServeAttachmentCSR)
	cert, err := s.RequestLifecycleAttachmentCertificate(context.Background(), raw, controller, ready, predecessor.Identity, hello, csr)
	staleMust(t, err)
	staleMust(t, csrJoin())
	identity, err := cert.WithKey(key)
	staleMust(t, err)
	conn, dataJoin := staleDataTLS(t, service, ready, identity, false)
	staleAdmit(t, conn, hello)
	// Unselected create/write/fsync are real positive controls at sequences 1/2/3.
	create := nativeServiceFaultReply(t, conn, staleCreateRequest(1, "positive"), 0)
	opened, ok := create.Body.(w.CreateReply)
	if !ok {
		t.Fatal("missing actual CREATE handle")
	}
	nativeServiceFaultReply(t, conn, w.Request{Sequence: 2, Auth: w.Auth{Kind: w.OpenGrantAuth}, Body: w.WriteRequest{Node: opened.Entry.Node, Handle: opened.Opened.Handle, Data: []byte("real service DATA before fault")}}, 0)
	fsync := w.Request{Sequence: 3, Auth: w.Auth{Kind: w.OpenGrantAuth}, Body: w.FsyncRequest{Node: opened.Entry.Node, Handle: opened.Opened.Handle}}
	nativeServiceFaultReply(t, conn, fsync, 0)
	if counter.Count() != 0 {
		t.Fatal("fault fired before exact target sequence")
	}
	if stage >= a.NativeRetireIntent {
		// Another exact A on the same V retires through its REAL barrier without
		// consuming this target's operation-scoped injection or counters.
		otherHello, otherIdentity, retireOther := staleAttachment(t, service, ready, controller, control, plan.Volume)
		other, otherJoin := staleDataTLS(t, service, ready, otherIdentity, false)
		staleAdmit(t, other, otherHello)
		staleCreate(t, other, 1, "unselected-retire")
		retireOther()
		staleMust(t, other.NetConn().Close())
		otherJoin()
		if counter.Observation() != (a.NativeFaultObservation{}) {
			t.Fatal("unselected A consumed target fault/retirement counters")
		}
		staleMust(t, conn.NetConn().Close())
		dataJoin() // transport loss leaves real retained resources; never drains
		receipt := nativeServiceRetire(t, service, ready, controllerKey, counter, control, closeControl, plan, hello.Binding.Launch)
		staleMust(t, json.NewEncoder(report).Encode(nativeServiceFaultEvidence{Hello: hello, Controller: ready.Controller, Reopen: predecessor, Count: counter.Count(), Plan: plan, Observation: counter.Observation(), Receipt: receipt}))
		staleMust(t, report.Sync())
		return
	}
	target := staleCreateRequest(nativeServiceFaultSequence, "post-namespace")
	if stage == a.NativeDataFsync {
		target = fsync
		target.Sequence = nativeServiceFaultSequence
	}
	want := unix.EIO
	if errno == a.NativeENOSPC {
		want = unix.ENOSPC
	}
	// The real server delivers its terminal errno reply and partial-mutation
	// events before closing DATA. Require that exact failure, never success.
	nativeServiceFaultReply(t, conn, target, uint32(want))
	staleRejectRead(t, conn)
	if err := dataJoin(); !errors.Is(err, want) {
		t.Fatalf("joined DATA error: want %v, got %v", want, err)
	}
	if counter.Count() != 1 {
		t.Fatalf("fault count=%d", counter.Count())
	}
	if stage == a.NativePostCreateNamespace {
		staleExists(t, "/proc/self/fd/3", "post-namespace")
	}
	staleExists(t, "/proc/self/fd/3", "positive")
	contents, err := os.ReadFile("/proc/self/fd/3/volumes/data/positive")
	staleMust(t, err)
	if string(contents) != "real service DATA before fault" {
		t.Fatal("real DATA write not visible on backing ext4")
	}
	request := c.Request{Retire: &a.RetireRequest{Operation: staleID(t), Store: plan.Store, Volume: plan.Volume, Attachment: plan.Attachment, Launch: hello.Binding.Launch}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := control.Call(ctx, request)
	var remote *c.RemoteError
	if !errors.As(err, &remote) || remote.Code != c.Blocked || response.Receipt != nil {
		t.Fatalf("poison manufactured retirement: %+v %v", response, err)
	}
	closeControl()
	if err := service.Close(); !errors.Is(err, a.ErrBusy) {
		t.Fatalf("retained resource Close: %v", err)
	}
	staleMust(t, json.NewEncoder(report).Encode(nativeServiceFaultEvidence{Hello: hello, Controller: ready.Controller, Reopen: predecessor, Count: counter.Count(), Plan: plan, Observation: counter.Observation()}))
	staleMust(t, report.Sync())
}

// Every connection still traverses the actual controller CSR and mutual TLS.
func nativeServiceFaultControl(t *testing.T, service *s.LifecycleService, ready s.Ready, key p.Key, fault *s.NativeFault) (p.Identity, *c.Client, func() error) {
	t.Helper()
	binding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	staleMust(t, err)
	csr, err := key.CSR(binding)
	staleMust(t, err)
	cert, err := service.IssueController(csr)
	staleMust(t, err)
	identity, err := cert.WithKey(key)
	staleMust(t, err)
	root, _ := staleTrust(t, ready)
	meta, err := service.Scope()
	staleMust(t, err)
	raw, join := staleTCP(t, fault.ServeControl)
	client, err := c.NewPKILifecycleWorkloadClient(context.Background(), raw, c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: root, ServerKey: ready.ServerKey, LifecycleIdentity: meta.Identity, ServiceEpoch: ready.ServiceEpoch, CurrentController: ready.Controller})
	staleMust(t, err)
	return identity, client, func() error { staleMust(t, client.Close()); return join() }
}

func nativeServiceRetire(t *testing.T, service *s.LifecycleService, ready s.Ready, key p.Key, fault *s.NativeFault, control *c.Client, closeControl func() error, plan a.NativeFaultPlan, launch a.ID) *a.Receipt {
	t.Helper()
	request := c.Request{Retire: &a.RetireRequest{Operation: plan.RetireOperation, Store: plan.Store, Volume: plan.Volume, Attachment: plan.Attachment, Launch: launch}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := control.Call(ctx, request)
	if plan.Stage == a.NativeRetireLostReply {
		if response.Receipt != nil || !(errors.Is(err, io.EOF) || errors.Is(err, unix.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF)) {
			t.Fatalf("lost durable reply: want EOF/reset without receipt, got %+v %v", response, err)
		}
		if err := closeControl(); !errors.Is(err, unix.EIO) {
			t.Fatalf("lost-reply server join: %v", err)
		}
		_, retry, closeRetry := nativeServiceFaultControl(t, service, ready, key, fault)
		before := staleCall(t, retry, c.Request{Query: &c.Empty{}}).Snapshot
		record := before.Attachments[plan.Attachment]
		if record.Phase != a.Drained || record.Retirement != plan.RetireOperation || record.Receipt == nil {
			t.Fatal("lost response did not follow real durable retirement")
		}
		for i := 0; i < 2; i++ {
			receipt := staleCall(t, retry, request).Receipt
			if receipt == nil || *receipt != *record.Receipt {
				t.Fatal("authenticated exact-op retry changed immutable receipt")
			}
		}
		after := staleCall(t, retry, c.Request{Query: &c.Empty{}}).Snapshot
		if after.Revision != before.Revision || after.Attachments[plan.Attachment].Receipt == nil || *after.Attachments[plan.Attachment].Receipt != *record.Receipt {
			t.Fatal("retry/query rewrote durable receipt or revision")
		}
		closeRetry()
		nativeServiceRetireCounts(t, plan.Stage, fault.Observation())
		staleMust(t, service.Close()) // only real completed retirement released owners
		return record.Receipt
	}
	var remote *c.RemoteError
	if !errors.As(err, &remote) || remote.Code != c.Blocked || response.Receipt != nil {
		t.Fatalf("retirement failure minted usable receipt: %+v %v", response, err)
	}
	// Even barrier-clear failure, whose state.json already says DRAINED, must
	// refuse both exact-op retry and authenticated query on the live endpoint.
	for _, q := range []c.Request{request, {Query: &c.Empty{}}} {
		response, err := control.Call(ctx, q)
		if !errors.As(err, &remote) || remote.Code != c.Blocked || response.Receipt != nil || response.Snapshot != nil {
			t.Fatalf("poisoned authenticated retry/query succeeded: %+v %v", response, err)
		}
	}
	closeControl()
	nativeServiceRetireCounts(t, plan.Stage, fault.Observation())
	if plan.Stage == a.NativeRetireIntent || plan.Stage == a.NativeRetireFinalSyncfs {
		if err := service.Close(); !errors.Is(err, a.ErrBusy) {
			t.Fatalf("failed retirement lost retained resource accounting: %v", err)
		}
	}
	// Receipt/barrier-clear faults may have really closed all resources. Keep the
	// poisoned authority until the owned child's joined exit anyway; no repair.
	return nil
}

func nativeServiceRetireCounts(t *testing.T, stage a.NativeFaultStage, got a.NativeFaultObservation) {
	t.Helper()
	want := a.NativeFaultObservation{Fired: 1}
	if stage != a.NativeRetireIntent {
		want.BarrierCalls, want.FinalSyncCalls = 1, 1
		if stage != a.NativeRetireFinalSyncfs {
			want.BarrierSucceeded = 1
		}
	}
	if got != want {
		t.Fatalf("real retirement boundary counts: got %+v want %+v", got, want)
	}
}

func nativeServiceRetireEvidence(t *testing.T, path string, root *os.File, evidence nativeServiceFaultEvidence) {
	t.Helper()
	plan := evidence.Plan
	nativeServiceRetireCounts(t, plan.Stage, evidence.Observation)
	journal := filepath.Join(path, ".cengine-storage-authority")
	stateBytes, err := os.ReadFile(filepath.Join(journal, "state.json"))
	staleMust(t, err)
	var state struct {
		Revision    uint64                `json:"revision"`
		Store       a.Store               `json:"store"`
		Epoch       a.ID                  `json:"epoch"`
		Controller  a.Controller          `json:"controller"`
		Attachments map[a.ID]a.Attachment `json:"attachments"`
	}
	staleMust(t, json.Unmarshal(stateBytes, &state))
	if state.Epoch != plan.Epoch || state.Store.ID != plan.Store || state.Controller != evidence.Controller {
		t.Fatal("persisted retirement state has different service tuple")
	}
	record := state.Attachments[plan.Attachment]
	if record.Binding != evidence.Hello.Binding {
		t.Fatal("persisted retirement binding changed")
	}
	phase := a.Retiring
	if plan.Stage == a.NativeRetireIntent {
		phase = a.Active
	}
	if plan.Stage == a.NativeRetireBarrierClear || plan.Stage == a.NativeRetireLostReply {
		phase = a.Drained
	}
	if record.Phase != phase {
		t.Fatalf("persisted phase=%s want %s", record.Phase, phase)
	}
	if phase == a.Active {
		if record.Retirement != "" {
			t.Fatal("failed intent published retirement operation")
		}
	} else if record.Retirement != plan.RetireOperation {
		t.Fatal("persisted retirement operation changed")
	}
	if phase == a.Drained {
		want := a.Receipt{Schema: a.SchemaVersion, Store: plan.Store, Volume: plan.Volume, Attachment: plan.Attachment, Launch: evidence.Hello.Binding.Launch, Prepare: plan.Prepare, Revision: state.Revision}
		if record.Receipt == nil || *record.Receipt != want {
			t.Fatal("serialized DRAINED has wrong receipt")
		}
	} else if record.Receipt != nil {
		t.Fatal("failure before receipt persistence serialized a receipt")
	}
	markers := map[string][]byte{}
	for _, name := range []string{"data-uncertain", "uncertain", "io-quarantined", "barrier-uncertain"} {
		data, err := os.ReadFile(filepath.Join(journal, name))
		want := (name == "uncertain" || name == "io-quarantined") && plan.Stage != a.NativeRetireLostReply || name == "barrier-uncertain" && (plan.Stage == a.NativeRetireFinalSyncfs || plan.Stage == a.NativeRetireReceipt)
		if want {
			staleMust(t, err)
			if name == "barrier-uncertain" && plan.Stage == a.NativeRetireReceipt {
				// The full barrier succeeded before receipt state-sync failed. Its
				// version-1 completion certificate replaces the pending text marker;
				// this runtime attachment has no PREPARE root-only retry proof.
				candidates, err := filepath.Glob(filepath.Join(journal, "state-*.tmp"))
				staleMust(t, err)
				if len(candidates) != 1 {
					t.Fatalf("receipt fault retained %d state candidates, want one", len(candidates))
				}
				candidate, err := os.ReadFile(candidates[0])
				staleMust(t, err)
				staleMust(t, nativeServiceRetirementProof(data, stateBytes, candidate, evidence.Hello.Binding, plan.RetireOperation))
				markers[filepath.Base(candidates[0])] = candidate
				meta, err := os.ReadFile(filepath.Join(journal, "commit-proof"))
				staleMust(t, err)
				markers["commit-proof"] = meta
			} else if string(data) != "Uncertain authority IO or barrier: offline repair required.\n" {
				t.Fatalf("wrong persisted %s marker", name)
			}
			markers[name] = data
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected %s marker: %v", name, err)
		}
	}
	cfg := nativeServiceFaultConfig(t, root, plan.Store)
	reopened, err := s.ReopenLifecycle(cfg, evidence.Reopen.Identity, evidence.Reopen.Current, evidence.Reopen.Expected)
	if plan.Stage == a.NativeRetireLostReply {
		staleMust(t, err)
		defer reopened.Close()
		ready, err := reopened.Ready()
		staleMust(t, err)
		if ready.ServiceEpoch == plan.Epoch || evidence.Receipt == nil || record.Receipt == nil || *record.Receipt != *evidence.Receipt {
			t.Fatal("lost-reply receipt/reopen mismatch")
		}
		staleMust(t, reopened.Close())
		return
	}
	// A returned EIO/ENOSPC is not a clean crash cut: quarantine takes precedence
	// even over a certified barrier and exact receipt candidate. Never reopen or
	// promote that candidate to a receipt, nor consume any retained evidence.
	if evidence.Receipt != nil || reopened != nil || !errors.Is(err, a.ErrRepairRequired) {
		t.Fatalf("poisoned retirement reopen: want ErrRepairRequired, got %v", err)
	}
	for name, before := range markers {
		after, err := os.ReadFile(filepath.Join(journal, name))
		staleMust(t, err)
		if !bytes.Equal(before, after) {
			t.Fatal("reopen altered retained uncertainty marker")
		}
	}
	after, err := os.ReadFile(filepath.Join(journal, "state.json"))
	staleMust(t, err)
	if !bytes.Equal(stateBytes, after) {
		t.Fatal("poisoned reopen rewrote state")
	}
}

func nativeServiceFaultReply(t *testing.T, conn io.ReadWriter, request w.Request, expectedErrno uint32) w.Reply {
	t.Helper()
	staleMust(t, w.WriteFrame(conn, &request))
	for i := 0; i < 16; i++ {
		frame, err := w.ReadServerFrame(conn)
		staleMust(t, err)
		if _, ok := frame.(*w.Event); ok {
			continue
		}
		reply, ok := frame.(*w.Reply)
		if !ok {
			t.Fatalf("unexpected DATA frame: %T", frame)
		}
		staleMust(t, w.ValidateReplyFor(request, *reply))
		if reply.Errno != expectedErrno {
			t.Fatalf("DATA request: errno=%d, want %d", reply.Errno, expectedErrno)
		}
		return *reply
	}
	t.Fatal("unbounded invalidations before reply")
	return w.Reply{}
}

func TestNativeServiceFaultPlanClosed(t *testing.T) {
	plan := a.NativeFaultPlan{Stage: a.NativeDataFsync, Error: a.NativeEIO, Store: staleID(t), Epoch: staleID(t), Volume: staleID(t), Attachment: staleID(t), Sequence: 3}
	staleMust(t, plan.Validate())
	for stage := a.NativeRetireIntent; stage <= a.NativeRetireLostReply; stage++ {
		retire := plan
		retire.Stage = stage
		retire.Sequence = 0
		retire.RetireOperation = staleID(t)
		if stage == a.NativeRetireLostReply {
			retire.Error = a.NativeDropReply
		}
		staleMust(t, retire.Validate())
		for _, mutate := range []func(*a.NativeFaultPlan){
			func(p *a.NativeFaultPlan) { p.RetireOperation = "" },
			func(p *a.NativeFaultPlan) { p.Sequence = 1 },
			func(p *a.NativeFaultPlan) {
				if p.Error == a.NativeDropReply {
					p.Error = a.NativeEIO
				} else {
					p.Error = a.NativeDropReply
				}
			},
		} {
			bad := retire
			mutate(&bad)
			if !errors.Is(bad.Validate(), a.ErrInvalid) {
				t.Fatal("invalid retirement/lost-reply plan accepted")
			}
		}
	}
	for _, mutate := range []func(*a.NativeFaultPlan){
		func(p *a.NativeFaultPlan) { p.Stage = 0 }, func(p *a.NativeFaultPlan) { p.Stage = 255 },
		func(p *a.NativeFaultPlan) { p.Error = 0 }, func(p *a.NativeFaultPlan) { p.Error = 255 },
		func(p *a.NativeFaultPlan) { p.Error = a.NativeDropReply }, func(p *a.NativeFaultPlan) { p.RetireOperation = staleID(t) },
		func(p *a.NativeFaultPlan) { p.Store = "" }, func(p *a.NativeFaultPlan) { p.Epoch = "" },
		func(p *a.NativeFaultPlan) { p.Volume = "" }, func(p *a.NativeFaultPlan) { p.Attachment = "" },
		func(p *a.NativeFaultPlan) { p.Prepare = staleID(t) }, func(p *a.NativeFaultPlan) { p.Sequence = 0 },
		func(p *a.NativeFaultPlan) { p.Sequence = 17 },
	} {
		bad := plan
		mutate(&bad)
		if !errors.Is(bad.Validate(), a.ErrInvalid) {
			t.Fatal("open-ended fault plan accepted")
		}
	}
}
