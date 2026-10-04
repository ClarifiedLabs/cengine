package storageauthority

// ExpectedStartup is the exact durable predecessor identity reconciled by the
// trusted caller. Epoch is the service epoch; Controller includes both C and its
// public-key fingerprint. This tuple is a guard, not authentication or a receipt.
type ExpectedStartup struct {
	Store      ID
	Epoch      ID
	Controller Controller
}
