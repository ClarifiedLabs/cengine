package preparecompat

import (
	"crypto/sha256"
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/hex"
)

func NewWitness(arm Arm) (*Witness, error) {
	if !SupportsArm(arm) {
		return nil, ErrInvalidFrame
	}
	digest, err := ArmDigest(arm)
	if err != nil {
		return nil, err
	}
	return &Witness{arm: normalize(arm), digest: digest, events: make(chan Observation, 1), ioEvents: make(chan IOObservation, 1), earlyEvents: make(chan EarlyObservation, 1), writeResult: make(chan error, 1)}, nil
}
func (w *Witness) PublishAndHold(o Observation) error {
	if w == nil || !SupportsArm(w.arm) || ValidateObservation(o) != nil || o.Version != w.arm.Version || o.Profile != w.arm.Profile || !physicalArm(w.arm) || o.Stage != physicalStage(w.arm) || o.RequestID != w.arm.RequestID || o.ArmDigest != w.digest || o.TargetAttachment != w.arm.TargetAttachment {
		return ErrInvalidFrame
	}
	if !w.emitted.CompareAndSwap(false, true) {
		return ErrInvalidFrame
	}
	w.events <- o
	if returningPhysicalArm(w.arm) {
		if err := <-w.writeResult; err != nil {
			return err
		}
		w.delivered.Store(true)
		return nil
	}
	select {}
}
func (w *Witness) EarlyObservations() <-chan EarlyObservation { return w.earlyEvents }
func (w *Witness) earlyObservation(sequence uint64) EarlyObservation {
	return EarlyObservation{Version: w.arm.Version, Profile: w.arm.Profile, RequestID: w.arm.RequestID, ArmDigest: w.digest, Stage: w.arm.CaseName, Count: 1, TargetAttachment: w.arm.TargetAttachment, RequestSequence: sequence, PrepareCommandsSent: 1, PrepareCommandsAccepted: 1}
}

// acceptPrepare is the one-shot emission primitive; tests never park a goroutine.
func (w *Witness) acceptPrepare(sequence uint64) (bool, error) {
	if w == nil || (w.arm.Profile != EarlyProfile && w.arm.Profile != FullProfile) || !earlyCase(w.arm.CaseName) {
		return false, nil
	}
	if !SupportsArm(w.arm) || sequence == 0 || w.arm.CaseName == "before-prepare-send" || !w.accepted.CompareAndSwap(false, true) {
		return false, ErrInvalidFrame
	}
	if w.arm.CaseName == "data-partial-frame" {
		return false, nil
	}
	o := w.earlyObservation(sequence)
	if ValidateEarlyObservation(o) != nil || !w.emitted.CompareAndSwap(false, true) {
		return false, ErrInvalidFrame
	}
	w.earlyEvents <- o
	return true, nil
}

// Called only after Session's actual PREPARE validation. There is no release,
// timer, EOF, context or observer-ACK path from the accepted A2 park.
func (w *Witness) AcceptPrepare(sequence uint64) error {
	hold, err := w.acceptPrepare(sequence)
	if err != nil {
		return err
	}
	if hold {
		select {}
	}
	return nil
}

// ValidateDataAuthority compares the complete TLS-backed DATA owner and exact
// issued leaf, not merely the selected attachment or claimed key fingerprint.
func (w *Witness) ValidateDataAuthority(h a.DataHello, certificateDER []byte) error {
	if w == nil || !SupportsArm(w.arm) || !w.UsesPartialData() {
		return ErrInvalidFrame
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
	sum := sha256.Sum256(certificateDER)
	if h.Binding != expected || h.Epoch != a.ID(scope.ServiceEpoch) || hex.EncodeToString(sum[:]) != credential.CertificateSHA256 {
		return ErrInvalidFrame
	}
	return nil
}

// No sequence or callback is configured on a client. execute owns the request.
func (w *Witness) ClaimPartialData(h a.DataHello, certificateDER []byte) error {
	if w.ValidateDataAuthority(h, certificateDER) != nil || !w.accepted.Load() || !w.partialClaimed.CompareAndSwap(false, true) {
		return ErrInvalidFrame
	}
	return nil
}
func (w *Witness) PartialDataWritten(sequence uint64) error {
	if w == nil || !w.partialClaimed.Load() {
		return ErrInvalidFrame
	}
	o := w.earlyObservation(sequence)
	o.DataBytesWritten = 5
	if ValidateEarlyObservation(o) != nil || !w.emitted.CompareAndSwap(false, true) {
		return ErrInvalidFrame
	}
	w.earlyEvents <- o
	// Join the independent observer before our DATA close can trigger retirement.
	// Even a successful observation can never yield a successful DATA request.
	<-w.writeResult
	return ErrInvalidFrame
}
