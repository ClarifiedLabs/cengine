//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package workloadstorage

import (
	"bytes"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/binary"
	"strings"
	"testing"
)

func TestIOActualSessionCheckpointPrecedesFailedPrepare(t *testing.T) {
	h, workload, arm := compatibilityHarness(t)
	arm.Version = 3
	arm.Profile = pc.FullProfile
	arm.CaseName = "io-eio-root-fsync"
	h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
	h.success("mount-phase", Payload{Role: ptr("prepare")})
	slot := pc.Slot{}
	credential := pc.Credential{}
	for _, s := range arm.Slots {
		if s.Attachment == arm.TargetAttachment {
			slot = s
		}
	}
	for _, c := range arm.Credentials {
		if c.Attachment == arm.TargetAttachment {
			credential = c
		}
	}
	root := a.Ext4ObjectV1{Inode: 1, Generation: 1, FileType: 16384, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(root.Handle[:4], 1)
	binary.LittleEndian.PutUint32(root.Handle[4:], 1)
	owner := a.Binding{Store: a.ID(arm.Scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Prepare: a.ID(arm.Scope.Prepare), Container: a.ContainerID(arm.Scope.Container), Launch: a.ID(arm.Scope.Launch), Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.ReadWrite}
	intent := a.CopyIntent{ID: a.ID(arm.Scope.Intent), Owner: owner, Epoch: a.ID(arm.Scope.ServiceEpoch), Root: a.CopyRootV1{Store: owner.Store, Volume: owner.Volume, BackingUUID: [16]byte{1}, Root: root}, Phase: a.CopySealed}
	// Exercise the actual Session observer and its joined write, not filesystem IO.
	done := make(chan error, 1)
	go func() { done <- workload.witness.InjectIO("root-fsync", intent) }()
	frame, err := ReadFrame(h.client)
	if err != nil || frame.Operation != "prepare-checkpoint" || frame.Data.CompatibilityIOObservation == nil {
		t.Fatal(err)
	}
	if <-done == nil || workload.witness.NormalObservationWritten() {
		t.Fatal("fault success")
	}
	var wire bytes.Buffer
	if WriteFrame(&wire, frame) != nil {
		t.Fatal("wire")
	}
	raw := wire.Bytes()[4:]
	bad := strings.Replace(string(raw), `"occurrence":1`, `"occurrence":1,"errnoNumber":5`, 1)
	if _, err := Decode([]byte(bad)); err == nil {
		t.Fatal("open IO payload")
	}
	reply := h.exchange("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("claim")})
	if reply.Data.Code == nil || *reply.Data.Code != "prepare" || h.finish() == nil {
		t.Fatal("IO became success")
	}
}
func TestIOMissedCutCannotPrepareSuccessfully(t *testing.T) {
	for _, name := range []string{"io-eio-root-fsync", "io-enospc-seal-persist"} {
		h, _, arm := compatibilityHarness(t)
		arm.Version = 3
		arm.Profile = pc.FullProfile
		arm.CaseName = name
		h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
		h.success("mount-phase", Payload{Role: ptr("prepare")})
		reply := h.exchange("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("claim")})
		if reply.Data.Code == nil || h.finish() == nil {
			t.Fatal("missed cut succeeded")
		}
	}
}
