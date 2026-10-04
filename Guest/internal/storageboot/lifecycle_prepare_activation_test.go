package storageboot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	s "dev.cengine/guest/internal/storageservice"
	"dev.cengine/guest/internal/storageworker"
)

var _ lifecycleCompatibilityService = (*s.LifecycleService)(nil)

// The fixture uses actual lifecycle workload TLS and the lifecycle CSR endpoint;
// neither the issued-certificate registry nor the authority is injected.
func lifecycleIssuedPrepareArm(t *testing.T, service *s.LifecycleService, key p.Key, worker, stage string) pc.StorageArm {
	t.Helper()
	ctx := context.Background()
	ready, err := service.Ready()
	must(t, err)
	scope, err := service.Scope()
	must(t, err)
	binding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	cert, err := service.IssueController(csr)
	must(t, err)
	identity, err := cert.WithKey(key)
	must(t, err)
	root, err := p.ParseRootDER(ready.TLSRootDER)
	must(t, err)
	raw, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- service.ServeControl(ctx, server) }()
	client, err := c.NewPKILifecycleWorkloadClient(ctx, raw, c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: root, ServerKey: ready.ServerKey, LifecycleIdentity: scope.Identity, ServiceEpoch: ready.ServiceEpoch, CurrentController: ready.Controller})
	must(t, err)
	defer func() { client.Close(); <-done }()
	call := func(request c.Request) { t.Helper(); _, err := client.Call(ctx, request); must(t, err) }
	id := func() a.ID { return a.ID(lifecycleTestID(t)) }
	volume := id()
	call(c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(), Store: ready.Store.ID, Volume: volume, Name: "prepare"}})
	attachmentKey, err := p.NewAttachmentKey(p.PrepareRole)
	must(t, err)
	finger, err := p.PublicKeyFingerprint(attachmentKey.PublicKey())
	must(t, err)
	b := a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: id(), Prepare: id(), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: a.ID(lifecycleTestBinding().ShimLaunchUUID), Key: a.Fingerprint(finger.String()), Role: a.PrepareRole, Mode: a.ReadWrite}
	call(c.Request{ReservePrepare: &a.ReserveRequest{Operation: id(), Prepare: b.Prepare, Attachments: []a.Binding{b}}})
	call(c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(), Binding: b}})
	hello := a.DataHello{Epoch: ready.ServiceEpoch, Binding: b}
	attachmentBinding, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err = attachmentKey.CSR(attachmentBinding)
	must(t, err)
	raw, server = net.Pipe()
	issued := make(chan error, 1)
	go func() { issued <- service.ServeAttachmentCSR(ctx, server) }()
	cert, err = s.RequestLifecycleAttachmentCertificate(ctx, raw, identity, ready, scope.Identity, hello, csr)
	must(t, err)
	must(t, <-issued)
	sum := sha256.Sum256(cert.DER())
	arm := pc.Arm{Version: 3, Profile: pc.FullProfile, RequestID: string(id()), CaseName: stage, TargetAttachment: string(b.Attachment), Binding: pc.BootBinding{ShimLaunchUUID: lifecycleTestBinding().ShimLaunchUUID, GuestBootNonce: lifecycleTestBinding().GuestBootNonce}, Scope: pc.Scope{Intent: string(id()), Store: string(b.Store), ServiceEpoch: string(ready.ServiceEpoch), ControllerEpoch: ready.Controller.Epoch, ControllerKey: string(ready.Controller.Key), Container: string(b.Container), ContainerInstance: string(id()), Launch: string(b.Launch), Prepare: string(b.Prepare), SpecificationDigest: strings.Repeat("b", 64)}, Mounts: []pc.MountBinding{{Index: 0, Volume: string(volume), Destination: "/data", Mode: "read-write"}}, Slots: []pc.Slot{{Volume: string(volume), Attachment: string(b.Attachment), Role: "prepare", Mode: "read-write"}, {Volume: string(volume), Attachment: string(id()), Role: "runtime", Mode: "read-write"}}, Credentials: []pc.Credential{{Attachment: string(b.Attachment), Key: string(b.Key), CertificateSHA256: hex.EncodeToString(sum[:])}}}
	return pc.StorageArm{Arm: arm, WorkerUUID: worker}
}

func lifecycleActivationRequest(arm pc.StorageArm, command string) *LifecycleFrame {
	f := lifecycleFrame("command", lifecycleTestBinding())
	sequence := uint64(1)
	f.Sequence, f.ServiceEpoch, f.WorkerUUID, f.Command = &sequence, arm.Arm.Scope.ServiceEpoch, arm.WorkerUUID, command
	return &f
}

func TestLifecyclePrepareActivationActualOwner(t *testing.T) {
	root, err := os.Open(t.TempDir())
	must(t, err)
	defer root.Close()
	cfg, key := lifecycleTestConfig(t)
	cfg.NowUnixSeconds = uint64(time.Now().Add(-time.Minute).Unix())
	service, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { return nil })
	must(t, err)
	defer func() { must(t, service.Close()) }()
	worker := lifecycleTestID(t)
	arm := lifecycleIssuedPrepareArm(t, service, key, worker, "admitted-queued")
	bindErr := service.BindPrepareCompatibilityWorker(worker)
	request := lifecycleActivationRequest(arm, "prepare-compatibility-arm")
	request.PrepareCompatibilityArm = &arm
	if pc.CurrentProfile() != pc.FullProfile {
		if bindErr == nil {
			t.Fatal("normal profile bound compatibility worker")
		}
		if _, err = service.ArmPrepareCompatibility(arm); err == nil {
			t.Fatal("normal profile armed")
		}
		if reply := lifecycleWorkerCommand(service, request); reply.Code != "command" || reply.PrepareCompatibilityStatus != nil {
			t.Fatal("normal dispatcher activated")
		}
		return
	}
	must(t, bindErr)
	for name, mutate := range map[string]func(*pc.StorageArm){
		"worker":         func(v *pc.StorageArm) { v.WorkerUUID = lifecycleTestID(t) },
		"controller":     func(v *pc.StorageArm) { v.Arm.Scope.ControllerEpoch++ },
		"controller-key": func(v *pc.StorageArm) { v.Arm.Scope.ControllerKey = strings.Repeat("c", 64) },
		"epoch":          func(v *pc.StorageArm) { v.Arm.Scope.ServiceEpoch = lifecycleTestID(t) },
		"certificate":    func(v *pc.StorageArm) { v.Arm.Credentials[0].CertificateSHA256 = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := arm
			bad.Arm.Credentials = append([]pc.Credential(nil), arm.Arm.Credentials...)
			mutate(&bad)
			f := lifecycleActivationRequest(bad, "prepare-compatibility-arm")
			f.PrepareCompatibilityArm = &bad
			if reply := lifecycleWorkerCommand(service, f); reply.Code != "command" || reply.PrepareCompatibilityStatus != nil {
				t.Fatal("mismatched arm accepted")
			}
		})
	}
	reply := lifecycleWorkerCommand(service, request)
	if reply.Code != "" || reply.PrepareCompatibilityStatus == nil || reply.PrepareCompatibilityStatus.State != "armed" {
		t.Fatal("actual owner did not arm", reply.Code)
	}
	query, err := pc.StorageQueryForArm(arm)
	must(t, err)
	observe := lifecycleActivationRequest(arm, "prepare-compatibility-observe")
	observe.PrepareCompatibilityQuery = &query
	reply = lifecycleWorkerCommand(service, observe)
	if reply.Code != "" || reply.PrepareCompatibilityStatus == nil || reply.PrepareCompatibilityStatus.Query != query || reply.PrepareCompatibilityStatus.Observation != nil {
		t.Fatal("observation did not select installed witness")
	}
	if lifecycleWorkerCommand(service, request).Code != "command" {
		t.Fatal("rearm accepted")
	}
	release := pc.StorageRelease{Query: query, Stage: arm.Arm.CaseName, Token: strings.Repeat("e", 64)}
	for _, command := range []string{"prepare-compatibility-release", "prepare-compatibility-worker-exit"} {
		f := lifecycleActivationRequest(arm, command)
		if command == "prepare-compatibility-release" {
			f.PrepareCompatibilityRelease = &release
		} else {
			f.PrepareCompatibilityWorkerExit = &release
		}
		if lifecycleWorkerCommand(service, f).Code != "command" {
			t.Fatal("unobserved cut accepted", command)
		}
	}
}

func lifecycleNormalCheckpoint(t *testing.T, arm pc.StorageArm) pc.WorkerCheckpointExit {
	t.Helper()
	request, _ := checkpointExitFrames(t)
	claim := *request.PrepareCompatibilityCheckpointExit
	observation := *claim.Checkpoint
	digest, err := pc.ArmDigest(arm.Arm)
	must(t, err)
	observation.ArmDigest, observation.RequestID, observation.TargetAttachment = digest, arm.Arm.RequestID, arm.Arm.TargetAttachment
	claim.Arm, claim.WorkerUUID, claim.Checkpoint = arm.Arm, arm.WorkerUUID, &observation
	must(t, pc.ValidateWorkerCheckpointExit(claim))
	return claim
}

// Portable process fixture: production worker loop, real lifecycle authority,
// actual TLS issuance, ACK then self-exit and sole exec.Cmd.Wait. This does not
// claim native Linux FD3 credentials, namespace or pidfd qualification.
func TestLifecyclePrepareActivationChildSelfExit(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile only")
	}
	if directory := os.Getenv("CENGINE_LIFECYCLE_PREPARE_CHILD"); directory != "" {
		root, err := os.Open(directory)
		must(t, err)
		cfg, key := lifecycleTestConfig(t)
		cfg.NowUnixSeconds = uint64(time.Now().Add(-time.Minute).Unix())
		h := lifecycleTestStart(t)
		h.Configuration = cfg
		err = serveLifecycleWorker(root, &h, func(service *s.LifecycleService) (func() error, error) {
			arm := lifecycleIssuedPrepareArm(t, service, key, h.WorkerUUID, "normal")
			claim := lifecycleNormalCheckpoint(t, arm)
			raw, err := json.Marshal(claim)
			must(t, err)
			must(t, os.WriteFile(filepath.Join(directory, "claim.json"), raw, 0600))
			return func() error { _ = os.WriteFile(filepath.Join(directory, "stopped"), nil, 0600); return nil }, nil
		}, func(raw []byte) error {
			frame, err := readLifecycleFramePacket(raw)
			if err != nil {
				return err
			}
			return WriteLifecycleFrame(os.Stdout, frame)
		}, func() ([]byte, error) {
			frame, err := ReadLifecycleFrame(os.Stdin)
			if err != nil {
				return nil, err
			}
			return lifecycleFramePacket(frame)
		})
		t.Fatal("worker returned instead of self-exiting", err)
	}
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecyclePrepareActivationChildSelfExit$")
	command.Env = append(os.Environ(), "CENGINE_LIFECYCLE_PREPARE_CHILD="+directory)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	input, err := command.StdinPipe()
	must(t, err)
	defer input.Close()
	output, err := command.StdoutPipe()
	must(t, err)
	must(t, command.Start())
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready, err := ReadLifecycleFrame(output)
	if err != nil {
		var remaining bytes.Buffer
		_, _ = remaining.ReadFrom(output)
		waitErr := command.Wait()
		waited = true
		t.Fatalf("worker ready: %v; wait: %v; output: %s; stderr: %s", err, waitErr, remaining.String(), stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(directory, "claim.json"))
	must(t, err)
	var claim pc.WorkerCheckpointExit
	must(t, json.Unmarshal(raw, &claim))
	request := lifecycleActivationRequest(pc.StorageArm{Arm: claim.Arm, WorkerUUID: claim.WorkerUUID}, "prepare-compatibility-checkpoint-exit")
	request.PrepareCompatibilityCheckpointExit = &claim
	if ready.Ready == nil || ready.Ready.ServiceEpoch != request.ServiceEpoch || ready.Ready.WorkerUUID != request.WorkerUUID {
		t.Fatal("wrong worker scope")
	}
	must(t, WriteLifecycleFrame(input, request))
	reply, err := ReadLifecycleFrame(output)
	must(t, err)
	_, err = lifecycleExitACK(request, reply)
	must(t, err)
	err = command.Wait()
	waited = true
	if command.ProcessState == nil || command.ProcessState.ExitCode() != 74 {
		t.Fatalf("not self-exit 74: %v %s", err, stderr.String())
	}
	wait, err := projectCheckpointWait(claim, command.Process.Pid, storageworker.WaitResult{Reaped: true, State: command.ProcessState, Err: err}, true)
	must(t, err)
	if !wait.Reaped || wait.WorkerPID != uint32(command.Process.Pid) {
		t.Fatal("not actual worker Wait")
	}
	if _, err := os.Stat(filepath.Join(directory, "stopped")); !os.IsNotExist(err) {
		t.Fatal("self-exit ran stop/drain defer", err)
	}
}
