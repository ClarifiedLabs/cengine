package preparecompat

import (
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/hex"
	"sync/atomic"
)

// Witness is installed only by the authenticated Session after comparing every
// actual issued PREPARE credential. It carries no private key or callable hook.
// The observer channel is independent of PREPARE's synchronous command/reply.
type Witness struct {
	arm            Arm
	digest         string
	events         chan Observation
	earlyEvents    chan EarlyObservation
	ioEvents       chan IOObservation
	accepted       atomic.Bool
	partialClaimed atomic.Bool
	emitted        atomic.Bool
	writeResult    chan error // bounded, one-way completion; never an A7 release
	acknowledged   atomic.Bool
	delivered      atomic.Bool
}

func (w *Witness) Arm() Arm                         { return normalize(w.arm) }
func (w *Witness) Digest() string                   { return w.digest }
func (w *Witness) Observations() <-chan Observation { return w.events }

// ObservationWritten is called only by the Session observer after its write has
// returned and its worker is joined. It conveys no authority or release token.
// Failed/canceled writes may complete before publication; successful ones may not.
func (w *Witness) ObservationWritten(err error) bool {
	if w == nil || !SupportsArm(w.arm) || w.writeResult == nil || err == nil && !w.emitted.Load() || !w.acknowledged.CompareAndSwap(false, true) {
		return false
	}
	if err != nil {
		err = ErrInvalidFrame
	}
	w.writeResult <- err
	return true
}
func (w *Witness) NormalObservationWritten() bool {
	return w != nil && prepareSuccessPhysicalArm(w.arm) && w.delivered.Load()
}
func (w *Witness) Selected(attachment string) bool {
	return w != nil && w.arm.TargetAttachment == attachment
}
func (w *Witness) ValidateIntent(i a.CopyIntent) error {
	if w == nil {
		return nil
	}
	var slot Slot
	var credential Credential
	for _, s := range w.arm.Slots {
		if s.Attachment == w.arm.TargetAttachment {
			slot = s
		}
	}
	for _, c := range w.arm.Credentials {
		if c.Attachment == slot.Attachment {
			credential = c
		}
	}
	scope := w.arm.Scope
	expected := a.Binding{Store: a.ID(scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Prepare: a.ID(scope.Prepare), Container: a.ContainerID(scope.Container), Launch: a.ID(scope.Launch), Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.ReadWrite}
	if i.Owner != expected || i.Epoch != a.ID(scope.ServiceEpoch) || i.Root.Store != expected.Store || i.Root.Volume != expected.Volume || i.Root.BackingUUID == [16]byte{} || !id(string(i.ID)) {
		return ErrInvalidFrame
	}
	root, err := ObjectFromAuthority(i.Root.Root)
	if err != nil || root.FileType != 16384 {
		return ErrInvalidFrame
	}
	return nil
}
func ObjectFromAuthority(o a.Ext4ObjectV1) (ObjectIdentity, error) {
	result := ObjectIdentity{Inode: o.Inode, Generation: o.Generation, FileType: o.FileType, Handle: hex.EncodeToString(o.Handle[:])}
	if o.HandleType != 1 || o.HandleSize != 8 || !result.Valid() {
		return ObjectIdentity{}, ErrInvalidFrame
	}
	return result, nil
}
func (w *Witness) Observation(i a.CopyIntent, root, transaction, published, staged a.Ext4ObjectV1, sourceAtimes SourceAtimes) (Observation, error) {
	if w == nil || !physicalArm(w.arm) || w.ValidateIntent(i) != nil || i.Phase != a.CopySealed || root != i.Root.Root || transaction != i.Transaction {
		return Observation{}, ErrInvalidFrame
	}
	r, e1 := ObjectFromAuthority(root)
	t, e2 := ObjectFromAuthority(transaction)
	p, e3 := ObjectFromAuthority(published)
	s, e4 := ObjectFromAuthority(staged)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return Observation{}, ErrInvalidFrame
	}
	o := Observation{SourceAtimes: sourceAtimes, Version: w.arm.Version, Profile: w.arm.Profile, RequestID: w.arm.RequestID, ArmDigest: w.digest, Stage: physicalStage(w.arm), Count: 1, TargetAttachment: w.arm.TargetAttachment, CopyIntent: string(i.ID), FilesystemUUID: hex.EncodeToString(i.Root.BackingUUID[:]), ManifestDigest: hex.EncodeToString(i.ManifestDigest[:]), ManifestSize: i.ManifestSize, Root: r, Transaction: t, Published: p, Staged: s}
	return o, ValidateObservation(o)
}
