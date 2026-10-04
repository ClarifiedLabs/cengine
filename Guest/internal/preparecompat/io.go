package preparecompat

import (
	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
	"strings"
)

// RTM-100 is a closed extension of the signed full profile, not an errno API.
func ioCase(stage string) (point, errno string, workload bool, ok bool) {
	switch {
	case strings.HasPrefix(stage, "io-eio-"):
		point, errno = strings.TrimPrefix(stage, "io-eio-"), "EIO"
	case strings.HasPrefix(stage, "io-enospc-"):
		point, errno = strings.TrimPrefix(stage, "io-enospc-"), "ENOSPC"
	default:
		return
	}
	switch point {
	case "child-data-fsync", "manifest-write", "manifest-fsync", "manifest-rename-parent-sync", "public-child-rename", "public-directory-sync", "root-metadata", "root-fsync":
		workload, ok = true, true
	case "copy-operation-write", "copy-operation-sync", "provision-rename", "provision-parent-sync", "seal-persist", "cleaning-persist", "child-unlink-parent-sync", "manifest-unlink-parent-sync", "transaction-unlink-parent-sync", "root-restoration-syncfs", "finish-persist", "retire-intent-persist", "retire-barrier-persist", "retire-receipt-persist", "retire-barrier-clear-persist":
		ok = true
	}
	return
}
func isIOCase(stage string) bool        { _, _, _, ok := ioCase(stage); return ok }
func isStorageIOCase(stage string) bool { _, _, workload, ok := ioCase(stage); return ok && !workload }
func (w *Witness) IsIO() bool {
	return w != nil && w.arm.Profile == FullProfile && isIOCase(w.arm.CaseName)
}
func (w *Witness) IsWorkloadIO() bool {
	if !w.IsIO() {
		return false
	}
	_, _, workload, _ := ioCase(w.arm.CaseName)
	return workload
}

// Only actual retirement cuts need successful PREPARE to reach their operation.
func (w *Witness) AllowsIORetirePrepare() bool {
	if !w.IsIO() {
		return false
	}
	point, _, _, _ := ioCase(w.arm.CaseName)
	return strings.HasPrefix(point, "retire-")
}

type IOCut struct {
	Point           string `json:"point"`
	Errno           string `json:"errno"`
	Occurrence      uint32 `json:"occurrence"`
	RequestSequence uint64 `json:"requestSequence"`
	RetireOperation string `json:"retireOperation"`
}
type IOObservation struct {
	Version          uint32 `json:"version"`
	Profile          string `json:"profile"`
	RequestID        string `json:"requestID"`
	ArmDigest        string `json:"armDigest"`
	Stage            string `json:"stage"`
	Count            uint32 `json:"count"`
	TargetAttachment string `json:"targetAttachment"`
	CopyIntent       string `json:"copyIntent"`
	Point            string `json:"point"`
	Errno            string `json:"errno"`
	Occurrence       uint32 `json:"occurrence"`
}

func ValidateIOObservation(o IOObservation) error {
	point, errno, workload, ok := ioCase(o.Stage)
	if !ok || !workload || o.Version != 3 || o.Profile != FullProfile || !id(o.RequestID) || !pin(o.ArmDigest) || !id(o.TargetAttachment) || !id(o.CopyIntent) || o.Count != 1 || o.Occurrence != 1 || o.Point != point || o.Errno != errno {
		return ErrInvalidFrame
	}
	return nil
}
func DecodeIOObservation(raw []byte) (IOObservation, error) {
	var o IOObservation
	if decode(raw, &o, MaximumObservationBytes) != nil || ValidateIOObservation(o) != nil {
		return IOObservation{}, ErrInvalidFrame
	}
	return o, nil
}
func (w *Witness) IOObservations() <-chan IOObservation { return w.ioEvents }

// The exact FIRST owned cut returns only after the authenticated observer write
// joins. Unmatched operations do not consume the one-shot. ACK is not a release.
func (w *Witness) InjectIO(point string, intent a.CopyIntent) error {
	if !w.IsWorkloadIO() {
		return nil
	}
	selected, errno, _, _ := ioCase(w.arm.CaseName)
	if point != selected {
		return nil
	}
	if !SupportsArm(w.arm) || w.ValidateIntent(intent) != nil {
		return ErrInvalidFrame
	}
	if !w.emitted.CompareAndSwap(false, true) {
		return nil
	}
	o := IOObservation{Version: 3, Profile: FullProfile, RequestID: w.arm.RequestID, ArmDigest: w.digest, Stage: w.arm.CaseName, Count: 1, TargetAttachment: w.arm.TargetAttachment, CopyIntent: string(intent.ID), Point: selected, Errno: errno, Occurrence: 1}
	w.ioEvents <- o
	if err := <-w.writeResult; err != nil {
		return err
	}
	w.delivered.Store(true)
	if errno == "EIO" {
		return unix.EIO
	}
	return unix.ENOSPC
}
