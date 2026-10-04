//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"context"
	"crypto/sha256"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	"encoding/hex"
	"testing"
)

func fullServicePrepare(t *testing.T, f *fixture, stage string, issue bool) pc.StorageArm {
	t.Helper()
	client, wait := f.connect(t)
	defer func() { client.Close(); wait() }()
	volume := id(t)
	call(t, client, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.ready.Store.ID, Volume: volume, Name: "prepare"}})
	key, err := p.NewAttachmentKey(p.PrepareRole)
	must(t, err)
	b := a.Binding{Store: f.ready.Store.ID, Volume: volume, Attachment: id(t), Prepare: id(t), Container: a.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Launch: id(t), Key: fingerprint(t, key), Role: a.PrepareRole, Mode: a.ReadWrite}
	call(t, client, c.Request{ReservePrepare: &a.ReserveRequest{Operation: id(t), Prepare: b.Prepare, Attachments: []a.Binding{b}}})
	call(t, client, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: b}})
	hello := a.DataHello{Epoch: f.ready.ServiceEpoch, Binding: b}
	binding, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	var cert p.Certificate
	if issue {
		raw, join := serve(t, f.s.ServeAttachmentCSR)
		cert, err = RequestLifecycleAttachmentCertificate(context.Background(), raw, f.identity, f.ready, f.s.current.Grant.Identity, hello, csr)
		must(t, err)
		must(t, join())
	} else {
		cert, err = f.s.issuer.IssueAttachment(csr, binding, f.cfg.Now, f.cfg.Lifetime)
		must(t, err)
	}
	sum := sha256.Sum256(cert.DER())
	worker := string(id(t))
	must(t, f.s.BindPrepareCompatibilityWorker(worker))
	arm := pc.Arm{Version: 3, Profile: pc.FullProfile, RequestID: string(id(t)), CaseName: stage, TargetAttachment: string(b.Attachment), Binding: pc.BootBinding{ShimLaunchUUID: string(b.Launch), GuestBootNonce: string(id(t))}, Scope: pc.Scope{Intent: string(id(t)), Store: string(b.Store), ServiceEpoch: string(f.ready.ServiceEpoch), ControllerEpoch: f.ready.Controller.Epoch, ControllerKey: string(f.ready.Controller.Key), Container: string(b.Container), ContainerInstance: string(id(t)), Launch: string(b.Launch), Prepare: string(b.Prepare), SpecificationDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, Mounts: []pc.MountBinding{{Index: 0, Volume: string(b.Volume), Destination: "/data", Mode: "read-write"}}, Slots: []pc.Slot{{Volume: string(b.Volume), Attachment: string(b.Attachment), Role: "prepare", Mode: "read-write"}, {Volume: string(b.Volume), Attachment: string(id(t)), Role: "runtime", Mode: "read-write"}}, Credentials: []pc.Credential{{Attachment: string(b.Attachment), Key: string(b.Key), CertificateSHA256: hex.EncodeToString(sum[:])}}}
	return pc.StorageArm{Arm: arm, WorkerUUID: worker}
}
func TestStorageCompatibilityServiceActualIssuanceAndRegistry(t *testing.T) {
	for _, kind := range []string{"ok", "not-issued", "leaf", "key", "worker", "controller", "replay"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			arm := fullServicePrepare(t, f, "full-frame-before-admit", kind != "not-issued")
			switch kind {
			case "leaf":
				arm.Arm.Credentials[0].CertificateSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			case "key":
				arm.Arm.Credentials[0].Key = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			case "worker":
				arm.WorkerUUID = string(id(t))
			case "controller":
				arm.Arm.Scope.ControllerEpoch++
			}
			status, err := f.s.ArmPrepareCompatibility(arm)
			if kind != "ok" && kind != "replay" {
				if err == nil {
					t.Fatal("accepted mismatch")
				}
				return
			}
			must(t, err)
			must(t, pc.ValidateStorageStatusForArm(status, arm))
			if kind == "replay" {
				if _, err = f.s.ArmPrepareCompatibility(arm); err == nil {
					t.Fatal("arm replay")
				}
				return
			}
			query, _ := pc.StorageQueryForArm(arm)
			observed, err := f.s.ObservePrepareCompatibility(query)
			must(t, err)
			if observed.State != "armed" || observed.Observation != nil {
				t.Fatal("manufactured evidence")
			}
			query.WorkerUUID = string(id(t))
			if _, err = f.s.ObservePrepareCompatibility(query); err == nil {
				t.Fatal("foreign observation")
			}
		})
	}
}
