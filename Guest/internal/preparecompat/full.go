package preparecompat

const FullProfile = "rtm096-full-nine-v3"
const MaximumStorageFrameBytes = 65536

func fullCase(name string) bool {
	switch name {
	case "normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "first-child-published", "drain-durable-reply-lost", "vm-two-volume-drain-reply-gap":
		return true
	}
	return isIOCase(name) || isVMCase(name)
}
func storageCase(name string) bool {
	switch name {
	case "full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "drain-durable-reply-lost", "vm-two-volume-drain-reply-gap":
		return true
	}
	return isStorageIOCase(name) || name == "vm-private-bound" || name == "vm-cleaning-transaction-removed"
}
func earlyCase(name string) bool {
	return name == "before-prepare-send" || name == "guest-accepted-before-prepare" || name == "data-partial-frame"
}
func physicalArm(arm Arm) bool {
	if arm.Profile == Profile {
		return arm.CaseName == "normal" || arm.CaseName == "first-child-published"
	}
	if arm.Profile == EarlyProfile {
		return arm.CaseName == "normal"
	}
	return arm.Profile == FullProfile && (arm.CaseName == "normal" || arm.CaseName == "first-child-published" || (arm.CaseName == "drain-durable-reply-lost" || arm.CaseName == "vm-two-volume-drain-reply-gap") || arm.CaseName == "vm-root-synced-before-cleanup" || arm.CaseName == "vm-cleaning-transaction-removed")
}
func returningPhysicalArm(arm Arm) bool {
	return prepareSuccessPhysicalArm(arm) || arm.Profile == FullProfile && arm.CaseName == "vm-cleaning-transaction-removed"
}

// Returning a physical witness only permits continued publication. CLEANING must
// still reach its storage-owned hold; missing that hold can never pass PREPARE.
func prepareSuccessPhysicalArm(arm Arm) bool {
	switch arm.Profile {
	case Profile, EarlyProfile:
		return arm.CaseName == "normal"
	case FullProfile:
		return arm.CaseName == "normal" || arm.CaseName == "drain-durable-reply-lost" || arm.CaseName == "vm-two-volume-drain-reply-gap"
	}
	return false
}

// RequiresGuestObservation distinguishes A4-A6 storage-owned cuts. It never
// converts missing guest evidence into successful PREPARE for those fault arms.
func (w *Witness) RequiresGuestObservation() bool {
	return w != nil && (physicalArm(w.arm) || earlyCase(w.arm.CaseName) || w.IsWorkloadIO())
}
func (w *Witness) UsesPartialData() bool {
	return w != nil && (w.arm.Profile == EarlyProfile || w.arm.Profile == FullProfile) && w.arm.CaseName == "data-partial-frame"
}
