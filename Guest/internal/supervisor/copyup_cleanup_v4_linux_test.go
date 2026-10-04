//go:build linux

package supervisor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"dev.cengine/guest/internal/protocol"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func managedCleanupMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func managedCleanupTimes(t *testing.T, f *managedCopyFixture) {
	t.Helper()
	managedCleanupMust(t, unix.UtimesNanoAt(f.copy.root.fd, "", []unix.Timespec{{Sec: 123456789, Nsec: 123456789}, {Sec: 234567890, Nsec: 987654321}}, unix.AT_EMPTY_PATH))
}
func managedCleanupExpectRoot(t *testing.T, f *managedCopyFixture, want a.CopyCleanupV1) {
	t.Helper()
	got, err := managedFixtureMetadata(f.copy.root.fd)
	managedCleanupMust(t, err)
	want.Manifest, want.Staging = a.Ext4ObjectV1{}, a.Ext4ObjectV1{}
	if got != want {
		t.Fatalf("root metadata changed: got %+v want %+v", got, want)
	}
}
func managedCleanupBound(t *testing.T, f *managedCopyFixture, present bool) []byte {
	t.Helper()
	managedCleanupTimes(t, f)
	managedCleanupMust(t, f.copy.control(w.BeginCopy))
	managedCleanupMust(t, f.copy.control(w.BindCopyTransaction))
	transaction := filepath.Join(f.base, confinedCopyTransactionName)
	managedCleanupMust(t, os.Mkdir(filepath.Join(transaction, confinedCopyStagingName), 0700))
	managedCleanupMust(t, os.WriteFile(filepath.Join(transaction, confinedCopyStagingName, "unsealed"), []byte("private staged data"), 0600))
	// Deliberately malformed and dangerous: neither validity nor version may grant
	// or prevent private Bound recovery; no bytes can authorize public deletion.
	raw := []byte(`{"version":3,"root":null,"entries":[{"path":"survivor"}],BROKEN`)
	if present {
		managedCleanupMust(t, os.WriteFile(filepath.Join(transaction, confinedCopyManifestName), raw, 0600))
	}
	return raw
}

func TestManagedV4BoundRecoveryIgnoresPresentOrMissingUnsealedManifest(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "present-unsealed"}[present], func(t *testing.T) {
			f := newManagedCopyFixture(t)
			managedCleanupMust(t, os.WriteFile(filepath.Join(f.base, "survivor"), []byte("user-owned"), 0600))
			raw := managedCleanupBound(t, f, present)
			initial := f.intent.Initial
			recovered, err := f.copy.recover()
			managedCleanupMust(t, err)
			if !recovered || f.intent.Phase != a.CopyCleaning {
				t.Fatal("Bound recovery did not durably start cleanup")
			}
			managedCleanupExpectRoot(t, f, initial)
			// StartCleanup must leave all transaction contents for the server Finish.
			_, err = os.Stat(filepath.Join(f.base, confinedCopyTransactionName, confinedCopyStagingName, "unsealed"))
			managedCleanupMust(t, err)
			if present {
				got, err := os.ReadFile(filepath.Join(f.base, confinedCopyTransactionName, confinedCopyManifestName))
				managedCleanupMust(t, err)
				if !bytes.Equal(got, raw) {
					t.Fatal("supervisor changed unsealed bytes")
				}
			}
			managedCleanupMust(t, f.copy.finish())
			if _, err := os.Stat(filepath.Join(f.base, confinedCopyTransactionName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("authority did not remove private transaction", err)
			}
			got, err := os.ReadFile(filepath.Join(f.base, "survivor"))
			managedCleanupMust(t, err)
			if string(got) != "user-owned" {
				t.Fatal("unsealed deletion instructions were trusted")
			}
			managedCleanupExpectRoot(t, f, initial)
		})
	}
}

func TestManagedV4CleaningResumesAbsentTransactionWithoutOrdinaryProbe(t *testing.T) {
	f := newManagedCopyFixture(t)
	managedCleanupBound(t, f, true)
	_, err := f.copy.recover()
	managedCleanupMust(t, err)
	cleanup := f.intent.Cleanup
	// Model death after authority deletion, before its root restore/complete.
	managedCleanupMust(t, os.RemoveAll(filepath.Join(f.base, confinedCopyTransactionName)))
	f.copy.intent = a.CopyIntent{}
	f.calls = nil
	f.identityErrors[""] = unix.EIO
	f.identityErrors[confinedCopyTransactionName] = unix.ENOENT
	managedCleanupMust(t, f.copy.initialize("/absent", protocol.Mount{Destination: "/seed", NoCopy: true}))
	if want := []w.PrepareAction{w.BeginCopy, w.FinishCopy, w.BeginCopy, w.FinishCopy}; !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("cleanup performed ordinary probe or duplicate completion: %v", f.calls)
	}
	managedCleanupExpectRoot(t, f, cleanup)
}

func TestManagedV4CleanupControlFailuresRetainWholePrivateTransaction(t *testing.T) {
	for _, action := range []w.PrepareAction{w.StartCleanup, w.FinishCopy} {
		t.Run(map[w.PrepareAction]string{w.StartCleanup: "start", w.FinishCopy: "finish"}[action], func(t *testing.T) {
			f := newManagedCopyFixture(t)
			raw := managedCleanupBound(t, f, true)
			f.failure[action] = unix.EIO
			_, err := f.copy.recover()
			if action == w.FinishCopy {
				managedCleanupMust(t, err)
				err = f.copy.finish()
			}
			if !errors.Is(err, unix.EIO) {
				t.Fatal("failed cleanup control lost", err)
			}
			if f.intent.Phase == a.CopyCompleted {
				t.Fatal("failure released fence")
			}
			got, err := os.ReadFile(filepath.Join(f.base, confinedCopyTransactionName, confinedCopyManifestName))
			managedCleanupMust(t, err)
			if !bytes.Equal(got, raw) {
				t.Fatal("failed control discarded evidence")
			}
			_, err = os.Stat(filepath.Join(f.base, confinedCopyTransactionName, confinedCopyStagingName, "unsealed"))
			managedCleanupMust(t, err)
			managedCleanupExpectRoot(t, f, f.intent.Initial)
			if action == w.StartCleanup {
				for _, call := range f.calls {
					if call == w.FinishCopy {
						t.Fatal("Finish called after failed Start")
					}
				}
			}
		})
	}
}

func TestManagedV4LatePrivateAuthorityErrorPropagatesWithoutLocalMutation(t *testing.T) {
	f := newManagedCopyFixture(t)
	f.journal(t)
	late := confinedCopyTransactionName + "/" + confinedCopyStagingName + "/zz-late"
	managedCleanupMust(t, os.WriteFile(filepath.Join(f.base, late), []byte("uncertain"), 0600))
	// Model the service's late private preflight refusal, not supervisor traversal.
	f.failure[w.RollbackCopy] = unix.EOPNOTSUPP
	assertManagedRollbackDelegation(t, f, f.copy.intent, unix.EOPNOTSUPP, late)
}

func TestManagedV4RollbackRetryAdoptsAuthorityReplyWithoutRestoringLocalRoot(t *testing.T) {
	f := newManagedCopyFixture(t)
	managedCleanupTimes(t, f)
	f.journal(t)
	// Distinct current times make an accidental local restore observable.
	managedCleanupMust(t, unix.UtimesNanoAt(f.copy.root.fd, "", []unix.Timespec{{Sec: 345678901, Nsec: 123}, {Sec: 456789012, Nsec: 456}}, unix.AT_EMPTY_PATH))
	f.failure[w.RollbackCopy] = unix.EIO
	assertManagedRollbackDelegation(t, f, f.copy.intent, unix.EIO)
	delete(f.failure, w.RollbackCopy)
	reply := managedRollbackCleaningReply(t, f)
	f.rollbackReply = &reply
	assertManagedRollbackDelegation(t, f, reply.Intent, nil)
	// No fake Finish: the response-only authority has not performed any cleanup.
}

func TestManagedV4ManifestRejectsEmptyPathWithoutPanic(t *testing.T) {
	f := newManagedCopyFixture(t)
	manifest := f.journal(t)
	for _, name := range []string{"", ".", "..", "/absolute", "a//b"} {
		manifest.Entries[0].Path = name
		if err := validateManagedManifest(manifest); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestManagedV4AuthorityProvisionAndSuccessCleanupPreserveSourceMetadata(t *testing.T) {
	f := newManagedCopyFixture(t)
	rootfs := t.TempDir()
	seed := filepath.Join(rootfs, "seed")
	managedCleanupMust(t, os.Mkdir(seed, 0750))
	managedCleanupMust(t, os.WriteFile(filepath.Join(seed, "data"), []byte("copied"), 0600))
	fd, err := unix.Open(seed, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	managedCleanupMust(t, err)
	defer unix.Close(fd)
	managedCleanupMust(t, unix.UtimesNanoAt(fd, "", []unix.Timespec{{Sec: 123456789, Nsec: 246813579}, {Sec: 234567890, Nsec: 135792468}}, unix.AT_EMPTY_PATH))
	want, err := managedFixtureMetadata(fd)
	managedCleanupMust(t, err)
	managedCleanupMust(t, f.copy.initialize(rootfs, protocol.Mount{Destination: "/seed"}))
	managedCleanupExpectRoot(t, f, want)
	var controls []w.PrepareAction
	for _, action := range f.calls {
		if action != w.IdentityAt {
			controls = append(controls, action)
		}
	}
	if expected := []w.PrepareAction{w.BeginCopy, w.BindCopyTransaction, w.SealManifest, w.AuthenticateManifest, w.StartCleanup, w.FinishCopy}; !reflect.DeepEqual(controls, expected) {
		t.Fatal("unexpected copy lifecycle", controls)
	}
	if _, err := os.Stat(filepath.Join(f.base, confinedCopyTransactionName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("transaction retained", err)
	}
	got, err := os.ReadFile(filepath.Join(f.base, "data"))
	managedCleanupMust(t, err)
	if string(got) != "copied" {
		t.Fatal("missing published data")
	}
}

func TestManagedV4FailedBindDoesNotProvisionPublicTransaction(t *testing.T) {
	f := newManagedCopyFixture(t)
	rootfs := t.TempDir()
	managedCleanupMust(t, os.Mkdir(filepath.Join(rootfs, "seed"), 0755))
	f.failure[w.BindCopyTransaction] = unix.EIO
	if err := f.copy.initialize(rootfs, protocol.Mount{Destination: "/seed"}); !errors.Is(err, unix.EIO) {
		t.Fatal("failed Bind was not propagated", err)
	}
	if _, err := os.Lstat(filepath.Join(f.base, confinedCopyTransactionName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("supervisor provisioned transaction before authority Bind", err)
	}
	for _, action := range f.calls {
		if action == w.StartCleanup || action == w.FinishCopy {
			t.Fatal("failed Bind released ownership fence")
		}
	}
}

func TestManagedV4EmptyProbePreservesOriginalAtime(t *testing.T) {
	f := newManagedCopyFixture(t)
	managedCleanupTimes(t, f)
	before, err := managedFixtureMetadata(f.copy.root.fd)
	managedCleanupMust(t, err)
	empty, err := f.copy.isEmpty()
	managedCleanupMust(t, err)
	if !empty {
		t.Fatal("new volume not empty")
	}
	managedCleanupExpectRoot(t, f, before)
}
