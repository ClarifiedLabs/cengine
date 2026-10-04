package preparecompat

import (
	"encoding/binary"
	"fmt"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func vmArm(t *testing.T, stage string) Arm {
	arm := normalize(fullArm(t, stage))
	arm.Mounts, arm.Slots, arm.Credentials = arm.Mounts[:1], arm.Slots[:2], arm.Credentials[:1]
	return arm
}
func TestVMClosedSingleVolumeCarrier(t *testing.T) {
	for _, stage := range []string{"vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed"} {
		arm := vmArm(t, stage)
		if ValidateArm(arm) != nil {
			t.Fatal(stage)
		}
		witness, err := NewWitness(arm)
		enabled := CurrentProfile() == FullProfile
		if (err == nil) != enabled || (witness != nil) != enabled {
			t.Fatal("VM profile isolation", stage)
		}
		bad := fullArm(t, stage)
		if ValidateArm(bad) == nil {
			t.Fatal("multi-volume admitted")
		}
		for _, profile := range []string{Profile, EarlyProfile} {
			bad = arm
			bad.Profile = profile
			if ValidateArm(bad) == nil {
				t.Fatal("wrong profile")
			}
		}
		arm.CaseName += "-extra"
		if ValidateArm(arm) == nil {
			t.Fatal("open selector")
		}
	}
}
func TestVMStorageProjectionAndScope(t *testing.T) {
	for _, stage := range []string{"vm-private-bound", "vm-cleaning-transaction-removed"} {
		arm := StorageArm{Arm: vmArm(t, stage), WorkerUUID: fullArm(t, "normal").Binding.GuestBootNonce}
		base := arm
		base.Arm.CaseName = "transaction-published-bind-reply-lost"
		o := fullStorageObservation(t, base)
		q, _ := StorageQueryForArm(arm)
		o.Stage, o.ArmDigest = stage, q.ArmDigest
		if stage == "vm-cleaning-transaction-removed" {
			i := &o.Bound.Intent
			i.Phase = a.CopyCleaning
			i.ManifestSize = 100
			i.ManifestDigest[0] = 1
			i.Cleanup = i.Initial
			i.Cleanup.Manifest = object(3, 32768)
			i.Cleanup.Staging = object(4, 16384)
		}
		if ValidateStorageObservationForArm(o, arm) != nil {
			t.Fatal(stage)
		}
		raw, _ := CanonicalJSON(o)
		if _, err := DecodeStorageObservation(raw); err != nil {
			t.Fatal(err)
		}
		bad := o
		bad.Count = 2
		if ValidateStorageObservationForArm(bad, arm) == nil {
			t.Fatal("duplicate")
		}
		bad = o
		bad.WorkerUUID = arm.Arm.RequestID
		if ValidateStorageObservationForArm(bad, arm) == nil {
			t.Fatal("wrong worker")
		}
		status := StorageStatus{Query: q, State: "observed", AcceptedInFlight: 2, Observation: &o}
		if ValidateStorageStatusForArm(status, arm) != nil {
			t.Fatal("actual held status rejected")
		}
		for _, mutate := range []func(*StorageStatus){
			func(s *StorageStatus) { s.AcceptedInFlight = 0 },
			func(s *StorageStatus) { s.RetirementStarted = true },
			func(s *StorageStatus) { s.State = "released" },
			func(s *StorageStatus) { s.State = "finished" },
		} {
			bad := status
			mutate(&bad)
			raw, err := CanonicalJSON(bad)
			if err != nil {
				t.Fatal(err)
			}
			if ValidateStorageStatus(bad) == nil || ValidateStorageStatusForArm(bad, arm) == nil {
				t.Fatal("invalid held status accepted", bad)
			}
			if _, err := DecodeStorageStatus(raw); err == nil {
				t.Fatal("invalid held status decoded")
			}
		}
		if stage == "vm-cleaning-transaction-removed" {
			original := o.Bound.Intent
			for left := 0; left < 4; left++ {
				for right := left + 1; right < 4; right++ {
					t.Run(fmt.Sprintf("inode-alias-%d-%d", left, right), func(t *testing.T) {
						i := original
						objects := []*a.Ext4ObjectV1{&i.Root.Root, &i.Transaction, &i.Cleanup.Manifest, &i.Cleanup.Staging}
						// Preserve valid type and handle linkage while aliasing the inode,
						// including different generations (full-object equality is insufficient).
						objects[right].Inode = objects[left].Inode
						objects[right].Generation++
						binary.LittleEndian.PutUint32(objects[right].Handle[:4], uint32(objects[right].Inode))
						binary.LittleEndian.PutUint32(objects[right].Handle[4:], objects[right].Generation)
						for _, obj := range objects {
							if _, err := ObjectFromAuthority(*obj); err != nil {
								t.Fatal("invalid alias fixture", err)
							}
						}
						bad := o
						bad.Bound = &BoundCut{RequestSequence: o.Bound.RequestSequence, Intent: i}
						if ValidateStorageObservationForArm(bad, arm) == nil {
							t.Fatal("inode alias accepted")
						}
						raw, err := CanonicalJSON(bad)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := DecodeStorageObservation(raw); err == nil {
							t.Fatal("inode alias decoded")
						}
					})
				}
			}
		}
		o.Bound.Intent.Epoch = a.ID(arm.Arm.RequestID)
		if ValidateStorageObservationForArm(o, arm) == nil {
			t.Fatal("wrong epoch")
		}
	}
}
