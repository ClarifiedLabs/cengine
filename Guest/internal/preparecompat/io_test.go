package preparecompat

import (
	"strings"
	"testing"
)

func TestIOClosedInventoryAndStorageEvidence(t *testing.T) {
	points := []string{"copy-operation-write", "copy-operation-sync", "provision-rename", "provision-parent-sync", "child-data-fsync", "manifest-write", "manifest-fsync", "manifest-rename-parent-sync", "seal-persist", "public-child-rename", "public-directory-sync", "root-metadata", "root-fsync", "cleaning-persist", "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs", "finish-persist", "retire-intent-persist", "retire-barrier-persist", "retire-receipt-persist", "retire-barrier-clear-persist"}
	authority, workload := 0, 0
	for _, point := range points {
		for _, errno := range []string{"EIO", "ENOSPC"} {
			stage := "io-" + strings.ToLower(errno) + "-" + point
			arm := fullArm(t, stage)
			if ValidateArm(arm) != nil {
				t.Fatal(stage)
			}
			for _, profile := range []string{Profile, EarlyProfile} {
				bad := arm
				bad.Profile = profile
				if profile == Profile {
					bad.Version = 1
				} else {
					bad.Version = 2
				}
				if ValidateArm(bad) == nil {
					t.Fatal("IO escaped full profile")
				}
			}
			_, _, guest, ok := ioCase(stage)
			if !ok {
				t.Fatal(stage)
			}
			if guest {
				workload++
				continue
			}
			authority++
			storage := fullStorageArm(t, stage)
			q, err := StorageQueryForArm(storage)
			if err != nil {
				t.Fatal(err)
			}
			cut := &IOCut{Point: point, Errno: errno, Occurrence: 1, RequestSequence: 42}
			if strings.HasPrefix(point, "retire-") {
				cut.RequestSequence = 0
				cut.RetireOperation = arm.Scope.Intent
			}
			o := StorageObservation{Version: 3, Profile: FullProfile, RequestID: q.RequestID, ArmDigest: q.ArmDigest, WorkerUUID: q.WorkerUUID, Stage: stage, Count: 1, TargetAttachment: arm.TargetAttachment, IO: cut}
			status := StorageStatus{Query: q, State: "observed", Observation: &o}
			if ValidateStorageStatusForArm(status, storage) != nil {
				t.Fatal(stage)
			}
			raw, _ := CanonicalJSON(status)
			if _, err := DecodeStorageStatus(raw); err != nil {
				t.Fatal(err)
			}
			cut.Occurrence = 2
			if ValidateStorageStatus(status) == nil {
				t.Fatal("second occurrence")
			}
			cut.Occurrence = 1
			cut.Errno = "5"
			if ValidateStorageStatus(status) == nil {
				t.Fatal("numeric errno")
			}
			cut.Errno = errno
			cut.Point = "unowned"
			if ValidateStorageStatus(status) == nil {
				t.Fatal("point")
			}
			cut.Point = point
			status.State = "finished"
			if ValidateStorageStatus(status) == nil {
				t.Fatal("IO became drain")
			}
			status.State = "observed"
			o.TargetAttachment = arm.Scope.Intent
			if ValidateStorageStatusForArm(status, storage) == nil {
				t.Fatal("foreign target")
			}
			o.TargetAttachment = arm.TargetAttachment
			for _, malformed := range []string{strings.Replace(string(raw), `"occurrence":1,`, "", 1), strings.Replace(string(raw), `"occurrence":1`, `"occurrence":null`, 1), strings.Replace(string(raw), `"occurrence":1`, `"occurrence":1,"invented":1`, 1)} {
				if _, err := DecodeStorageStatus([]byte(malformed)); err == nil {
					t.Fatal("malformed IO accepted")
				}
			}
			if ValidateStorageRelease(StorageRelease{Query: q, Stage: stage, Token: strings.Repeat("a", 64)}) == nil {
				t.Fatal("IO release")
			}
		}
	}
	if authority != 30 || workload != 16 {
		t.Fatal(authority, workload)
	}
	for _, stage := range []string{"io-eio-any", "io-eperm-root-fsync", "io-EIO-root-fsync", "io-eio-root-fsync-extra"} {
		if ValidateArm(fullArm(t, stage)) == nil {
			t.Fatal(stage)
		}
	}
}
