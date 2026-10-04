//go:build linux && cengine_prepare_full_compat

package supervisor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Reuse the signed carrier's closed full-profile vector; only the selected case
// changes. This exercises real Witness binding, not the syscall-boundary spy.
func managedIOWitnessFixture(t *testing.T, stage string) (*managedCopyFixture, *preparecompat.Witness) {
	t.Helper()
	raw, err := os.ReadFile("../preparecompat/testdata/full-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ Arm preparecompat.Arm }
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors) == 0 {
		t.Fatal("full vectors", err)
	}
	arm := vectors[0].Arm
	arm.CaseName = stage
	if stage == "vm-private-bound" || stage == "vm-root-synced-before-cleanup" || stage == "vm-cleaning-transaction-removed" {
		for _, mount := range arm.Mounts {
			for _, slot := range arm.Slots {
				if slot.Attachment == arm.TargetAttachment && slot.Volume == mount.Volume {
					arm.Mounts = []preparecompat.MountBinding{mount}
				}
			}
		}
		slots := arm.Slots[:0]
		for _, slot := range arm.Slots {
			if slot.Volume == arm.Mounts[0].Volume {
				slots = append(slots, slot)
			}
		}
		arm.Slots = slots
		for _, credential := range arm.Credentials {
			if credential.Attachment == arm.TargetAttachment {
				arm.Credentials = []preparecompat.Credential{credential}
				break
			}
		}
	}
	witness, err := preparecompat.NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	f := newManagedCopyFixture(t)
	for _, slot := range arm.Slots {
		if slot.Attachment != arm.TargetAttachment {
			continue
		}
		f.copy.scope = managedCopyScope{Store: arm.Scope.Store, Volume: slot.Volume, Prepare: arm.Scope.Prepare, Attachment: slot.Attachment}
		f.intent.Root.Store, f.intent.Root.Volume = a.ID(arm.Scope.Store), a.ID(slot.Volume)
		f.intent.Owner = a.Binding{Store: f.intent.Root.Store, Volume: f.intent.Root.Volume, Prepare: a.ID(arm.Scope.Prepare), Attachment: a.ID(slot.Attachment), Container: a.ContainerID(arm.Scope.Container), Launch: a.ID(arm.Scope.Launch), Role: a.PrepareRole, Mode: a.ReadWrite}
		for _, credential := range arm.Credentials {
			if credential.Attachment == slot.Attachment {
				f.intent.Owner.Key = a.Fingerprint(credential.Key)
			}
		}
	}
	f.intent.Epoch = a.ID(arm.Scope.ServiceEpoch)
	f.copy.compatibility = witness
	f.copy.io = f.copy.compatibilityIO()
	return f, witness
}

func TestManagedIOWitnessActualSixteenCuts(t *testing.T) {
	for _, point := range managedIOPoints {
		for _, code := range []string{"eio", "enospc"} {
			t.Run(point+"/"+code, func(t *testing.T) {
				f, witness := managedIOWitnessFixture(t, "io-"+code+"-"+point)
				_, source := managedIOSource(t)
				if f.copy.io == nil || f.copy.control(w.BeginCopy) != nil {
					t.Fatal("selected signed witness not bound")
				}
				// Wrong signed owners fail without emitting or spending FIRST.
				owner := f.copy.intent.Owner
				f.copy.intent.Owner.Key = "wrong"
				if err := f.copy.io.before(point); !errors.Is(err, preparecompat.ErrInvalidFrame) {
					t.Fatal("foreign signed owner accepted", err)
				}
				f.copy.intent.Owner = owner
				select {
				case <-witness.IOObservations():
					t.Fatal("foreign owner checkpoint")
				default:
				}
				returned := make(chan error, 1)
				go func() { returned <- f.copy.copyDirectory(source) }()
				select {
				case observation := <-witness.IOObservations():
					if preparecompat.ValidateIOObservation(observation) != nil || observation.Point != point || observation.CopyIntent != string(f.intent.ID) || observation.ArmDigest != witness.Digest() {
						t.Fatal("unauthenticated or wrong checkpoint", observation)
					}
					// Witness is blocked before syscall until this authenticated write ACK.
					assertManagedIOBoundary(t, f, point)
					if !witness.ObservationWritten(nil) {
						t.Fatal("checkpoint ACK rejected")
					}
				case err := <-returned:
					t.Fatal("returned before selected checkpoint", err)
				case <-time.After(5 * time.Second):
					t.Fatal("IO arm held at A7 or missed filesystem cut")
				}
				want := error(unix.EIO)
				if code == "enospc" {
					want = unix.ENOSPC
				}
				select {
				case err := <-returned:
					if !errors.Is(err, want) {
						t.Fatal("errno lost", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("errno did not return after checkpoint")
				}
				if err := f.copy.io.before(point); err != nil {
					t.Fatal("FIRST injected twice", err)
				}
				select {
				case <-witness.IOObservations():
					t.Fatal("duplicate IO checkpoint")
				case <-witness.Observations():
					t.Fatal("IO arm emitted A7 physical checkpoint")
				default:
				}
			})
		}
	}
}

func TestManagedIOForeignAttachmentHasNoCallback(t *testing.T) {
	f, _ := managedIOWitnessFixture(t, "io-eio-root-fsync")
	f.copy.scope.Attachment = "00000015-0000-4000-8000-000000000001"
	if f.copy.compatibilityIO() != nil {
		t.Fatal("foreign attachment armed")
	}
}

func TestManagedStorageIOPublicationBypassKeepsIdentityValidation(t *testing.T) {
	for _, stage := range []string{"io-eio-cleaning-persist", "io-enospc-retire-barrier-persist"} {
		t.Run(stage, func(t *testing.T) {
			f, _ := managedIOWitnessFixture(t, stage)
			if f.copy.io != nil {
				t.Fatal("storage-owned cut installed in supervisor")
			}
			manifest := f.journal(t)
			staged := confinedCopyTransactionName + "/" + confinedCopyStagingName + "/z"
			if err := os.Rename(filepath.Join(f.base, "z"), filepath.Join(f.base, staged)); err != nil {
				t.Fatal(err)
			}
			f.identities[staged] = manifest.Entries[1].Identity
			f.copy.sourceAtimes = &preparecompat.SourceAtimes{}
			if err := f.copy.compatibilityPublished(manifest, "a"); err != nil {
				t.Fatal("storage IO rejected prematurely", err)
			}
			f.identities[""] = managedTestObject(123, 1, unix.S_IFDIR)
			if err := f.copy.compatibilityPublished(manifest, "a"); !errors.Is(err, preparecompat.ErrInvalidFrame) {
				t.Fatal("IO bypass waived physical root identity", err)
			}
		})
	}
}
