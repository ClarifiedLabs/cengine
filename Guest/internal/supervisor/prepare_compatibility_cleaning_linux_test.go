//go:build linux && cengine_prepare_full_compat

package supervisor

import (
	"context"
	"encoding/hex"
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

// The existing sideband fixture keeps real copy, persisted manifest validation,
// and filesystem mutations. It does not claim a native storage-owned hold.
func TestManagedCleaningPhysicalWritePrecedesContinuedPublication(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "written", true: "failed-write"}[failed], func(t *testing.T) {
			f, witness := managedIOWitnessFixture(t, "vm-cleaning-transaction-removed")
			_, source := managedIOSource(t)
			current := preparecompat.SourceAtimes{Root: 1_800_000_000_000_000_404, A: 1_800_000_001_000_000_505, Z: 1_800_000_002_000_000_606}
			setCompatibilitySourceAtimes(t, source, current)
			// A prior attempt's cached values cannot substitute for this source.
			f.copy.sourceAtimes = &preparecompat.SourceAtimes{Root: 1, A: 2, Z: 3}
			if err := f.copy.control(w.BeginCopy); err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() { returned <- f.copy.copyDirectory(source) }()
			select {
			case observation := <-witness.Observations():
				root, _ := preparecompat.ObjectFromAuthority(f.copy.intent.Root.Root)
				transaction, _ := preparecompat.ObjectFromAuthority(f.copy.intent.Transaction)
				if preparecompat.ValidateObservationForArm(observation, witness.Arm()) != nil || observation.Stage != "first-child-published" || observation.SourceAtimes != current || observation.CopyIntent != string(f.copy.intent.ID) || observation.Root != root || observation.Transaction != transaction || observation.ManifestDigest != hex.EncodeToString(f.copy.intent.ManifestDigest[:]) || observation.ManifestSize != f.copy.intent.ManifestSize || f.copy.intent.Phase != a.CopySealed {
					t.Fatal("wrong attempt, identity, or sealed manifest", observation)
				}
				for _, name := range []string{"a", confinedCopyTransactionName + "/" + confinedCopyStagingName + "/z"} {
					if _, err := os.Stat(filepath.Join(f.base, name)); err != nil {
						t.Fatal("first-child boundary", err)
					}
				}
				if _, err := os.Stat(filepath.Join(f.base, "z")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("z published before observer write", err)
				}
				select {
				case err := <-returned:
					t.Fatal("copy returned before observer write", err)
				default:
				}
				var writeErr error
				if failed {
					writeErr = context.Canceled
				}
				if !witness.ObservationWritten(writeErr) {
					t.Fatal("observer result rejected")
				}
			case err := <-returned:
				t.Fatal("copy skipped physical proof", err)
			case <-time.After(5 * time.Second):
				t.Fatal("missing physical observation")
			}
			select {
			case err := <-returned:
				if (err == nil) == failed || witness.NormalObservationWritten() {
					t.Fatal("CLEANING continuation/prepare eligibility", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("first-child witness held instead of continuing")
			}
			startedCleanup := false
			for _, action := range f.calls {
				startedCleanup = startedCleanup || action == w.StartCleanup
			}
			if startedCleanup == failed {
				t.Fatal("observer result did not gate storage cleanup")
			}
			_, err := os.Stat(filepath.Join(f.base, "z"))
			if !failed && err != nil || failed && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("observer result did not gate remaining publication", err)
			}
		})
	}
}

func TestManagedCleaningRejectsMissingPhysicalProof(t *testing.T) {
	for _, fault := range []string{"source", "name", "unsealed", "manifest", "root", "transaction", "a", "z", "owner"} {
		t.Run(fault, func(t *testing.T) {
			f, witness := managedIOWitnessFixture(t, "vm-cleaning-transaction-removed")
			manifest := f.journal(t)
			staged := confinedCopyTransactionName + "/" + confinedCopyStagingName + "/z"
			if err := os.Rename(filepath.Join(f.base, "z"), filepath.Join(f.base, staged)); err != nil {
				t.Fatal(err)
			}
			f.identities[staged] = manifest.Entries[1].Identity
			_, source := managedIOSource(t)
			if err := f.copy.compatibilitySource(source); err != nil {
				t.Fatal(err)
			}
			name := "a"
			switch fault {
			case "source":
				f.copy.sourceAtimes = nil
			case "name":
				name = "z"
			case "unsealed":
				f.copy.intent.Phase = a.CopyBound
			case "manifest":
				manifest.Entries = manifest.Entries[:1]
			case "root":
				f.identities[""] = managedTestObject(123, 1, unix.S_IFDIR)
			case "transaction":
				f.identities[confinedCopyTransactionName] = managedTestObject(123, 1, unix.S_IFDIR)
			case "a":
				f.identities["a"] = managedTestObject(123, 1, unix.S_IFREG)
			case "z":
				f.identities[staged] = managedTestObject(123, 1, unix.S_IFREG)
			case "owner":
				f.copy.intent.Owner.Key = "wrong"
			}
			if err := f.copy.compatibilityPublished(manifest, name); !errors.Is(err, preparecompat.ErrInvalidFrame) {
				t.Fatal("missing physical proof accepted", err)
			}
			select {
			case <-witness.Observations():
				t.Fatal("invalid physical event")
			default:
			}
		})
	}
}

func TestManagedPrivateAndRootVMKeepFirstPublicationBypass(t *testing.T) {
	for _, stage := range []string{"vm-private-bound", "vm-root-synced-before-cleanup"} {
		f, witness := managedIOWitnessFixture(t, stage)
		manifest := f.journal(t)
		if err := f.copy.compatibilityPublished(manifest, "a"); err != nil {
			t.Fatal("separate VM checkpoint path rejected", stage, err)
		}
		select {
		case <-witness.Observations():
			t.Fatal("private/root VM emitted first-child evidence")
		default:
		}
	}
}
