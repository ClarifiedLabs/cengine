//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

// Use the real authenticated control and CSR services, not a fabricated issuance
// registry. unissued selects a valid signed leaf that bypasses the CSR service.
func twoVolumeServicePrepare(t *testing.T, f *fixture, unissued int) (pc.StorageArm, []a.Binding) {
	t.Helper()
	client, wait := f.connect(t)
	defer func() { client.Close(); wait() }()
	prepare, launch := id(t), id(t)
	bindings := make([]a.Binding, 2)
	keys := make([]p.Key, 2)
	for i := range bindings {
		volume := id(t)
		call(t, client, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.ready.Store.ID, Volume: volume, Name: fmt.Sprintf("prepare-%d", i)}})
		key, err := p.NewAttachmentKey(p.PrepareRole)
		must(t, err)
		keys[i] = key
		bindings[i] = a.Binding{Store: f.ready.Store.ID, Volume: volume, Attachment: id(t), Prepare: prepare, Container: a.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Launch: launch, Key: fingerprint(t, key), Role: a.PrepareRole, Mode: a.ReadWrite}
	}
	call(t, client, c.Request{ReservePrepare: &a.ReserveRequest{Operation: id(t), Prepare: prepare, Attachments: bindings}})
	b := bindings[0]
	arm := pc.Arm{Version: 3, Profile: pc.FullProfile, RequestID: string(id(t)), CaseName: "vm-two-volume-drain-reply-gap", TargetAttachment: string(bindings[1].Attachment), Binding: pc.BootBinding{ShimLaunchUUID: string(launch), GuestBootNonce: string(id(t))}, Scope: pc.Scope{Intent: string(id(t)), Store: string(b.Store), ServiceEpoch: string(f.ready.ServiceEpoch), ControllerEpoch: f.ready.Controller.Epoch, ControllerKey: string(f.ready.Controller.Key), Container: string(b.Container), ContainerInstance: string(id(t)), Launch: string(launch), Prepare: string(prepare), SpecificationDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
	for i, b := range bindings {
		call(t, client, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: b}})
		hello := a.DataHello{Epoch: f.ready.ServiceEpoch, Binding: b}
		binding, err := d.AttachmentBinding(hello)
		must(t, err)
		csr, err := keys[i].CSR(binding)
		must(t, err)
		var cert p.Certificate
		if i == unissued {
			cert, err = f.s.issuer.IssueAttachment(csr, binding, f.cfg.Now, f.cfg.Lifetime)
		} else {
			raw, join := serve(t, f.s.ServeAttachmentCSR)
			cert, err = RequestLifecycleAttachmentCertificate(context.Background(), raw, f.identity, f.ready, f.s.current.Grant.Identity, hello, csr)
			must(t, err)
			must(t, join())
		}
		must(t, err)
		sum := sha256.Sum256(cert.DER())
		arm.Mounts = append(arm.Mounts, pc.MountBinding{Index: uint32(i), Volume: string(b.Volume), Destination: fmt.Sprintf("/data-%d", i), Mode: "read-write"})
		arm.Slots = append(arm.Slots, pc.Slot{Volume: string(b.Volume), Attachment: string(b.Attachment), Role: "prepare", Mode: "read-write"}, pc.Slot{Volume: string(b.Volume), Attachment: string(id(t)), Role: "runtime", Mode: "read-write"})
		arm.Credentials = append(arm.Credentials, pc.Credential{Attachment: string(b.Attachment), Key: string(b.Key), CertificateSHA256: hex.EncodeToString(sum[:])})
	}
	worker := string(id(t))
	must(t, f.s.BindPrepareCompatibilityWorker(worker))
	wrapper := pc.StorageArm{Arm: arm, WorkerUUID: worker}
	must(t, pc.ValidateStorageArm(wrapper))
	return wrapper, bindings
}

func TestTwoVolumeServiceActualIssuedCertificatesArm(t *testing.T) {
	for _, kind := range []string{"ok", "not-issued-0", "not-issued-1", "leaf-0", "leaf-1", "key-0", "key-1", "swapped-leaves"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			unissued := -1
			if kind == "not-issued-0" {
				unissued = 0
			}
			if kind == "not-issued-1" {
				unissued = 1
			}
			arm, bindings := twoVolumeServicePrepare(t, f, unissued)
			for i := range arm.Arm.Credentials {
				if kind == fmt.Sprintf("leaf-%d", i) {
					arm.Arm.Credentials[i].CertificateSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
				}
				if kind == fmt.Sprintf("key-%d", i) {
					arm.Arm.Credentials[i].Key = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
				}
			}
			if kind == "swapped-leaves" {
				arm.Arm.Credentials[0].CertificateSHA256, arm.Arm.Credentials[1].CertificateSHA256 = arm.Arm.Credentials[1].CertificateSHA256, arm.Arm.Credentials[0].CertificateSHA256
			}
			// These negatives are structurally valid: rejection must come from
			// service issuance/binding checks, not from malformed DTOs.
			must(t, pc.ValidateStorageArm(arm))
			status, err := f.s.ArmPrepareCompatibility(arm)
			if kind != "ok" {
				if err == nil || f.s.compatibility != nil || f.s.compatibilityInstalling {
					t.Fatal("accepted or partially installed mismatched credentials", err)
				}
				return
			}
			must(t, err)
			must(t, pc.ValidateStorageStatusForArm(status, arm))
			if len(f.s.issuedPrepare) != 2 || f.s.issuedPrepare[bindings[0].Attachment].hello.Binding != bindings[0] || f.s.issuedPrepare[bindings[1].Attachment].hello.Binding != bindings[1] {
				t.Fatal("missing real issuance records")
			}
			query, err := pc.StorageQueryForArm(arm)
			must(t, err)
			status, err = f.s.ObservePrepareCompatibility(query)
			must(t, err)
			must(t, pc.ValidateStorageStatusForArm(status, arm))
			if status.State != "armed" || status.Observation != nil {
				t.Fatal("arm manufactured held evidence")
			}
			if _, err := f.s.ArmPrepareCompatibility(arm); err == nil {
				t.Fatal("accepted arm replay")
			}
		})
	}
}
