package preparecompat

import "testing"

func TestFullProfileClosedAndIsolated(t *testing.T) {
	for _, name := range []string{"normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "first-child-published", "drain-durable-reply-lost"} {
		arm := fullArm(t, name)
		if ValidateArm(arm) != nil {
			t.Fatal(name)
		}
		witness, err := NewWitness(arm)
		enabled := CurrentProfile() == FullProfile
		if (err == nil) != enabled || (witness != nil) != enabled {
			t.Fatal("profile isolation", name)
		}
		arm.Version = 2
		if ValidateArm(arm) == nil {
			t.Fatal("mixed version")
		}
	}
	for _, name := range []string{"unknown", "drain", "BOUND", "normal-extra"} {
		if ValidateArm(fullArm(t, name)) == nil {
			t.Fatal("unknown case")
		}
	}
}
func TestPhysicalArmReturnAndPrepareSuccessAreClosed(t *testing.T) {
	for _, profile := range []string{Profile, EarlyProfile, FullProfile, "unknown"} {
		for _, name := range []string{"normal", "first-child-published", "drain-durable-reply-lost", "vm-two-volume-drain-reply-gap", "vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed", "vm-cleaning-transaction-removed-extra", "unknown"} {
			arm := Arm{Profile: profile, CaseName: name}
			normal := profile != "unknown" && name == "normal"
			drain := profile == FullProfile && (name == "drain-durable-reply-lost" || name == "vm-two-volume-drain-reply-gap")
			cleaning := profile == FullProfile && name == "vm-cleaning-transaction-removed"
			hold := (profile == Profile || profile == FullProfile) && name == "first-child-published" || profile == FullProfile && name == "vm-root-synced-before-cleanup"
			if physicalArm(arm) != (normal || drain || cleaning || hold) || returningPhysicalArm(arm) != (normal || drain || cleaning) || prepareSuccessPhysicalArm(arm) != (normal || drain) {
				t.Fatalf("physical/return/success gating: %s/%s", profile, name)
			}
		}
	}
}
func TestFullConflictingProfilesFailClosed(t *testing.T) {
	count := 0
	for _, v := range []bool{Enabled(), EarlyEnabled(), FullEnabled()} {
		if v {
			count++
		}
	}
	if count < 2 {
		t.Skip("conflicting build tags only")
	}
	if CurrentProfile() != "" {
		t.Fatal("conflicting profiles negotiated")
	}
	for _, arm := range []Arm{vectorArm(t), earlyArm(t, "normal"), fullArm(t, "normal")} {
		if SupportsArm(arm) {
			t.Fatal("conflicting arm enabled")
		}
		if _, err := NewWitness(arm); err == nil {
			t.Fatal("conflicting witness")
		}
	}
	if SupportsStorageArm(fullStorageArm(t, "admitted-queued")) {
		t.Fatal("conflicting storage profile enabled")
	}
}
