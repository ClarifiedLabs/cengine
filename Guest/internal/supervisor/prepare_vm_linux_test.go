//go:build linux && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package supervisor

import (
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

// Real copyDirectory publication, metadata and fsync; only sideband identity
// acquisition is supplied by the existing invocation-local component fixture.
func TestVMRootPhysicalHook(t *testing.T) {
	for _, fault := range []string{"", "root-metadata", "root-fsync"} {
		t.Run(fault, func(t *testing.T) {
			f, witness := managedIOWitnessFixture(t, "vm-root-synced-before-cleanup")
			_, source := managedIOSource(t)
			managedCleanupMust(t, unix.UtimesNanoAt(source.fd, "", []unix.Timespec{{Sec: 123, Nsec: 456}, {Sec: 789, Nsec: 123}}, unix.AT_EMPTY_PATH))
			expected, err := managedFixtureMetadata(source.fd)
			managedCleanupMust(t, err)
			managedCleanupMust(t, f.copy.control(w.BeginCopy))
			syncReached := false
			f.copy.io = func(point string) error {
				if point == "root-fsync" {
					syncReached = true
				}
				if point == fault {
					return unix.EIO
				}
				return nil
			}
			returned := make(chan error, 1)
			go func() { returned <- f.copy.copyDirectory(source) }()
			if fault != "" {
				select {
				case err := <-returned:
					if !errors.Is(err, unix.EIO) {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("failure held")
				}
				select {
				case <-witness.Observations():
					t.Fatal("false final checkpoint")
				default:
				}
				return
			}
			select {
			case o := <-witness.Observations():
				if o.Stage != "vm-root-synced-before-cleanup" || !syncReached || f.intent.Phase != a.CopySealed {
					t.Fatal("wrong boundary", o)
				}
			case err := <-returned:
				t.Fatal("returned before hold", err)
			case <-time.After(5 * time.Second):
				t.Fatal("missing root checkpoint")
			}
			got, err := managedFixtureMetadata(f.copy.root.fd)
			managedCleanupMust(t, err)
			if got != expected {
				t.Fatal("not final root metadata", got, expected)
			}
			for _, name := range []string{"a", "z"} {
				data, err := os.ReadFile(filepath.Join(f.base, name))
				if err != nil || string(data) != "data-"+name {
					t.Fatal("incomplete public tree", name, err)
				}
			}
			for _, action := range f.calls {
				if action == w.StartCleanup || action == w.FinishCopy {
					t.Fatal("cleanup before hold")
				}
			}
			if !witness.ObservationWritten(errors.New("observer gone")) {
				t.Fatal("observer ACK")
			}
			select {
			case err := <-returned:
				t.Fatal("observer loss released hook", err)
			default:
			}
		})
	}
}

func TestVMRootHookRejectsFalseManifestAndMetadata(t *testing.T) {
	for _, kind := range []string{"missing-a", "missing-z", "duplicate", "wrong-identity", "missing-public", "mode", "uid", "gid", "atime", "mtime", "xattrs", "no-source"} {
		t.Run(kind, func(t *testing.T) {
			f, witness := managedIOWitnessFixture(t, "vm-root-synced-before-cleanup")
			m := f.journal(t)
			f.copy.sourceAtimes = &preparecompat.SourceAtimes{}
			expected, err := confinedRootMetadata(f.copy.root.fd)
			managedCleanupMust(t, err)
			var times unix.Stat_t
			managedCleanupMust(t, unix.Fstat(f.copy.root.fd, &times))
			switch kind {
			case "missing-a":
				m.Entries = m.Entries[1:]
			case "missing-z":
				m.Entries = m.Entries[:1]
			case "duplicate":
				m.Entries[1] = m.Entries[0]
			case "wrong-identity":
				m.Entries[1].Identity.Generation++
			case "missing-public":
				managedCleanupMust(t, os.Rename(filepath.Join(f.base, "z"), filepath.Join(f.base, confinedCopyTransactionName, confinedCopyStagingName, "z")))
			case "mode":
				expected.Mode ^= 1
			case "uid":
				expected.UID++
			case "gid":
				expected.GID++
			case "atime":
				times.Atim.Sec++
			case "mtime":
				times.Mtim.Sec++
			case "xattrs":
				expected.Xattrs = nil
			case "no-source":
				f.copy.sourceAtimes = nil
			}
			if err := f.copy.compatibilityRootSynced(m, expected, times); !errors.Is(err, preparecompat.ErrInvalidFrame) {
				t.Fatal("false checkpoint accepted", err)
			}
			select {
			case <-witness.Observations():
				t.Fatal("false observation")
			default:
			}
		})
	}
}
