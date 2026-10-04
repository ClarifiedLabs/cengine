package preparecompat

import "testing"

func TestTwoVolumeClosedArmAndHeldStatus(t *testing.T) {
	const stage = "vm-two-volume-drain-reply-gap"
	arm := fullStorageArm(t, stage)
	for i := range arm.Arm.Mounts {
		arm.Arm.Mounts[i].Mode = "read-write"
		arm.Arm.Mounts[i].NoCopy = false
	}
	for i := range arm.Arm.Slots {
		arm.Arm.Slots[i].Mode = "read-write"
	}
	if ValidateStorageArm(arm) != nil {
		t.Fatal("two-volume arm rejected")
	}
	for _, mutate := range []func(*Arm){
		func(a *Arm) { a.Mounts = a.Mounts[:1] },
		func(a *Arm) { a.Mounts[1].Volume = a.Mounts[0].Volume },
		func(a *Arm) { a.Mounts[1].Destination = a.Mounts[0].Destination },
		func(a *Arm) { a.Mounts[1].NoCopy = true },
		func(a *Arm) { a.Mounts[1].Subpath = "child" },
		func(a *Arm) { a.Mounts[1].Mode = "read-only" },
		func(a *Arm) {
			for i := range a.Slots {
				a.Slots[i].Role = "prepare"
			}
		},
		func(a *Arm) { a.Slots = a.Slots[:2] },
		func(a *Arm) { a.Credentials = a.Credentials[:1] },
		func(a *Arm) { a.Profile = EarlyProfile },
		func(a *Arm) { a.CaseName += "-other" },
	} {
		bad := normalize(arm.Arm)
		mutate(&bad)
		if ValidateArm(bad) == nil {
			t.Fatal("open arm")
		}
	}
	base := arm
	base.Arm.CaseName = "drain-durable-reply-lost"
	o := fullStorageObservation(t, base)
	q, err := StorageQueryForArm(arm)
	if err != nil {
		t.Fatal(err)
	}
	o.Stage, o.ArmDigest = stage, q.ArmDigest
	status := StorageStatus{Query: q, State: "held", RetirementStarted: true, Observation: &o}
	if ValidateStorageStatusForArm(status, arm) != nil {
		t.Fatal("held receipt rejected")
	}
	raw, err := CanonicalJSON(status)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeStorageStatus(raw); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*StorageStatus){
		func(s *StorageStatus) { s.State = "observed" },
		func(s *StorageStatus) { s.State = "released" },
		func(s *StorageStatus) { s.State = "finished" },
		func(s *StorageStatus) { s.RetirementStarted = false },
		func(s *StorageStatus) { s.AcceptedInFlight = 1 },
		func(s *StorageStatus) { s.ReceiptReplayCount = 1 },
		func(s *StorageStatus) { s.LateAdmissionRejected = true },
		func(s *StorageStatus) { s.Query.WorkerUUID = arm.Arm.RequestID },
	} {
		bad := status
		mutate(&bad)
		if ValidateStorageStatusForArm(bad, arm) == nil {
			t.Fatal("false drain accepted", bad)
		}
	}
	o.Count = 2
	if ValidateStorageStatusForArm(status, arm) == nil {
		t.Fatal("duplicate checkpoint")
	}
}
