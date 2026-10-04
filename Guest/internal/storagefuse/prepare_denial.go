package storagefuse

import (
	"sync"

	w "dev.cengine/guest/internal/storagewire"
)

// EACCES denial origins are a closed diagnostic vocabulary. They distinguish a
// local prepare-gate rejection from a storage-side DATA errno so an ambiguous
// managed-copy-up EACCES can be attributed without logging request data,
// credentials, paths or error strings. Recording is diagnostic-only: admission,
// grant, retirement and reply behavior are unchanged.
type denialOrigin uint8

const (
	denialOther          denialOrigin = iota
	denialGateCredential              // captured request credential state was not present
	denialGateProcess                 // credential present but the TID is not the pinned prepare owner
	denialGateFlush                   // forced-flush NONE credential reused for a non-flush body
	denialGateOrder                   // prepare-gate begun/role ordering rejected the request
	denialStorage                     // storage DATA reply carried errno EACCES (server-side DAC)
)

func (d denialOrigin) name() string {
	switch d {
	case denialGateCredential:
		return "gate-credential"
	case denialGateProcess:
		return "gate-process"
	case denialGateFlush:
		return "gate-flush"
	case denialGateOrder:
		return "gate-order"
	case denialStorage:
		return "storage"
	default:
		return "other"
	}
}

// PrepareDenialDetails is one coherent, diagnostic-only snapshot. Action is
// "none" for non-PREPARE, unknown actions, or rejection before body construction.
// Operation uses the existing failureOperation vocabulary ("other" if absent).
// Begun and ReadOnly are captured at denial, not queried at reporting time;
// both are false when no prepare gate exists. ProcessStage/ProcessCategory
// capture only the original gate-process failure; other origins use
// none/unavailable, never a stale match from an earlier request.
type PrepareDenialDetails struct {
	Origin          string
	Count           uint64
	Action          string
	Operation       string
	Begun           bool
	ReadOnly        bool
	ProcessStage    string
	ProcessCategory string
}

func deniedPrepareAction(body w.RequestBody) string {
	b, ok := body.(w.PrepareRequest)
	if !ok {
		return "none"
	}
	switch b.Action {
	case w.BeginCopy:
		return "begin"
	case w.BindCopyTransaction:
		return "bind"
	case w.SealManifest:
		return "seal"
	case w.AuthenticateManifest:
		return "authenticate"
	case w.IdentityAt:
		return "identity"
	case w.StartCleanup:
		return "cleanup"
	case w.FinishCopy:
		return "finish"
	default:
		return "none"
	}
}

// All fields and the count are published together; no observer can combine
// state from one denial with another denial's origin or count.
type denialTracker struct {
	mu   sync.Mutex
	last PrepareDenialDetails
}

func (t *denialTracker) record(d denialOrigin, opcode uint32, body w.RequestBody, begun, readOnly bool, failures ...processMatchFailure) {
	t.mu.Lock()
	defer t.mu.Unlock()
	failure := processMatchFailure{}
	if d == denialGateProcess && len(failures) != 0 {
		failure = failures[0]
	}
	stage, category := failure.diagnostic()
	t.last = PrepareDenialDetails{Origin: d.name(), Count: t.last.Count + 1,
		Action: deniedPrepareAction(body), Operation: failureOperation(opcode), Begun: begun, ReadOnly: readOnly, ProcessStage: stage, ProcessCategory: category}
}

func (t *denialTracker) details() PrepareDenialDetails {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last.Count == 0 {
		return PrepareDenialDetails{Origin: "none", Action: "none", Operation: failureOperation(0), ProcessStage: "none", ProcessCategory: "unavailable"}
	}
	return t.last
}

func (t *denialTracker) diagnostic() (string, uint64) {
	d := t.details()
	return d.Origin, d.Count
}

// Ordinary prepare calls already hold prepare.mu. Lifecycle calls bypass gate
// admission, but must acquire the same mutex to read its mutable state. Always
// acquire prepare.mu before denials.mu; readers only acquire denials.mu.
func (f *rawFS) recordDenial(d denialOrigin, opcode uint32, body w.RequestBody, gateLocked bool) {
	var begun, readOnly bool
	var failure processMatchFailure
	if f.prepare != nil {
		if !gateLocked {
			f.prepare.mu.Lock()
			defer f.prepare.mu.Unlock()
		}
		begun, readOnly = f.prepare.begun, f.prepare.readOnly
		if d == denialGateProcess {
			failure = f.prepare.lastFailure
		}
	}
	f.denials.record(d, opcode, body, begun, readOnly, failure)
}
