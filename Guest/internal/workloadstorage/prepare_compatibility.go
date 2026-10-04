package workloadstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"

	"dev.cengine/guest/internal/preparecompat"
)

// Only supervisorWorkload implements this private production installation seam.
type compatibilityFactory interface {
	installPrepareCompatibility(*preparecompat.Witness) error
}

type compatibilityWorkload interface {
	installPrepareCompatibility(*preparecompat.Witness) error
}

func (s *Session) armPrepareCompatibility(ctx context.Context, arm *preparecompat.Arm) (Payload, string) {
	if arm == nil || !preparecompat.SupportsArm(*arm) || s.compatibility != nil || s.phase != "certificates-installed" || s.activeRole != "prepare" {
		return Payload{}, "phase"
	}
	if preparecompat.ValidateArm(*arm) != nil || arm.Binding != preparecompat.BootBinding(s.binding) || arm.Scope != preparecompat.Scope(s.scope) {
		return Payload{}, "scope-mismatch"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || ctx.Err() != nil {
		return Payload{}, "terminal"
	}
	live := *arm
	live.Mounts = compatibilityMounts(s.mounts)
	live.Slots = compatibilitySlots(s.slots)
	live.Credentials = []preparecompat.Credential{}
	for _, slot := range s.slots {
		e := s.entries[slot.Attachment]
		if slot.Role != "prepare" {
			if e != nil {
				return Payload{}, "phase"
			}
			continue
		}
		if e == nil || !e.installed || e.mounted || e.attachment != nil || e.slot != slot {
			return Payload{}, "phase"
		}
		b, err := sessionBinding(s.scope, slot)
		if err != nil || b != e.binding || e.identity.Certificate().Binding() != b {
			return Payload{}, "certificate"
		}
		pin, err := e.key.Fingerprint()
		if err != nil {
			return Payload{}, "certificate"
		}
		der := e.identity.Certificate().DER()
		leaf, err := verifySessionChain(der, s.root, false)
		if err != nil {
			return Payload{}, "certificate"
		}
		leafPin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if hex.EncodeToString(leafPin[:]) != pin.String() {
			return Payload{}, "certificate"
		}
		sum := sha256.Sum256(der)
		live.Credentials = append(live.Credentials, preparecompat.Credential{Attachment: slot.Attachment, Key: pin.String(), CertificateSHA256: hex.EncodeToString(sum[:])})
	}
	wanted, err := preparecompat.CanonicalArmData(*arm)
	if err != nil {
		return Payload{}, "configuration"
	}
	actual, err := preparecompat.CanonicalArmData(live)
	if err != nil || !bytes.Equal(wanted, actual) {
		return Payload{}, "scope-mismatch"
	}
	workload, ok := s.workload.(compatibilityWorkload)
	if !ok {
		return Payload{}, "configuration"
	}
	witness, err := preparecompat.NewWitness(live)
	if err != nil {
		return Payload{}, "configuration"
	}
	if workload.installPrepareCompatibility(witness) != nil {
		return Payload{}, "configuration"
	}
	if witness.UsesPartialData() {
		factory, ok := s.factory.(compatibilityFactory)
		if !ok || factory.installPrepareCompatibility(witness) != nil {
			return Payload{}, "configuration"
		}
	}
	s.compatibility = witness
	// A4-A6 are observed at the real storage-owned cut. Never start an observer
	// waiting for a guest event that cannot exist; Session's success guard remains.
	if !witness.RequiresGuestObservation() {
		digest := witness.Digest()
		return Payload{CompatibilityDigest: &digest}, ""
	}
	// No serial command lock: PREPARE can remain in the supervisor indefinitely.
	s.workers.Add(1)
	go func() {
		var err error
		defer func() {
			// Join the complete write before allowing normal copy-up to return.
			// This ACK is never read by A7 and cannot cancel/release the owner.
			s.workers.Done()
			witness.ObservationWritten(err)
		}()
		select {
		case observation := <-witness.Observations():
			if err = ctx.Err(); err == nil {
				err = s.write(s.conn, NewFrame("prepare-checkpoint", s.binding, s.scope, Payload{CompatibilityObservation: &observation}))
				if err == nil {
					err = ctx.Err()
				}
			}
		case observation := <-witness.IOObservations():
			if err = ctx.Err(); err == nil {
				err = s.write(s.conn, NewFrame("prepare-checkpoint", s.binding, s.scope, Payload{CompatibilityIOObservation: &observation}))
				if err == nil {
					err = ctx.Err()
				}
			}
		case observation := <-witness.EarlyObservations():
			if err = ctx.Err(); err == nil {
				err = s.write(s.conn, NewFrame("prepare-early-checkpoint", s.binding, s.scope, Payload{CompatibilityEarlyObservation: &observation}))
				if err == nil {
					err = ctx.Err()
				}
			}
		case <-ctx.Done():
			err = ctx.Err()
		}
	}()
	digest := witness.Digest()
	return Payload{CompatibilityDigest: &digest}, ""
}

func compatibilityMounts(mounts []MountBinding) []preparecompat.MountBinding {
	result := make([]preparecompat.MountBinding, len(mounts))
	for i, m := range mounts {
		result[i] = preparecompat.MountBinding(m)
	}
	return result
}
func compatibilitySlots(slots []Slot) []preparecompat.Slot {
	result := make([]preparecompat.Slot, len(slots))
	for i, s := range slots {
		result[i] = preparecompat.Slot(s)
	}
	return result
}
