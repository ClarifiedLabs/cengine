//go:build linux

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/protocol"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

var managedIOPoints = []string{
	"child-data-fsync", "manifest-write", "manifest-fsync", "manifest-rename-parent-sync",
	"public-child-rename", "public-directory-sync", "root-metadata", "root-fsync",
}

func managedIOSource(t *testing.T) (string, *confinedRoot) {
	t.Helper()
	rootfs := t.TempDir()
	dir := filepath.Join(rootfs, "source")
	if err := os.Mkdir(dir, 0751); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0751); err != nil { // independent of the test runner's umask
		t.Fatal(err)
	}
	// Deliberately create z first: selected staging must still reach a first.
	for _, name := range []string{"z", "a"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data-"+name), 0640); err != nil {
			t.Fatal(err)
		}
	}
	root, err := openConfinedRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.close() })
	return rootfs, root
}

func assertManagedIOBoundary(t *testing.T, f *managedCopyFixture, point string) {
	t.Helper()
	transaction := filepath.Join(f.base, confinedCopyTransactionName)
	staging := filepath.Join(transaction, confinedCopyStagingName)
	exists := func(path string, want bool) {
		t.Helper()
		_, err := os.Stat(path)
		if want && err != nil || !want && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s at %s: exists=%v err=%v", point, path, want, err)
		}
	}
	contents := func(path, want string) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s contents %s = %q, %v", point, path, got, err)
		}
	}
	switch point {
	case "child-data-fsync":
		contents(filepath.Join(staging, "a"), "data-a")
		exists(filepath.Join(staging, "z"), false)
		exists(filepath.Join(transaction, confinedCopyManifestTemporary), false)
	case "manifest-write":
		contents(filepath.Join(transaction, confinedCopyManifestTemporary), "")
		exists(filepath.Join(transaction, confinedCopyManifestName), false)
	case "manifest-fsync":
		raw, err := os.ReadFile(filepath.Join(transaction, confinedCopyManifestTemporary))
		if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
			t.Fatal("manifest not written before fsync", err)
		}
		exists(filepath.Join(transaction, confinedCopyManifestName), false)
	case "manifest-rename-parent-sync":
		exists(filepath.Join(transaction, confinedCopyManifestTemporary), false)
		exists(filepath.Join(transaction, confinedCopyManifestName), true)
	case "public-child-rename":
		exists(filepath.Join(staging, "a"), true)
		exists(filepath.Join(f.base, "a"), false)
	case "public-directory-sync":
		exists(filepath.Join(staging, "a"), false)
		contents(filepath.Join(f.base, "a"), "data-a")
		exists(filepath.Join(staging, "z"), true)
		exists(filepath.Join(f.base, "z"), false)
	case "root-metadata", "root-fsync":
		contents(filepath.Join(f.base, "a"), "data-a")
		contents(filepath.Join(f.base, "z"), "data-z")
		var st unix.Stat_t
		if err := unix.Fstat(f.copy.root.fd, &st); err != nil {
			t.Fatal(err)
		}
		want := f.intent.Initial.Mode
		if point == "root-fsync" {
			want = 0751
		}
		if st.Mode&07777 != want {
			t.Fatalf("%s root mode = %o, want %o", point, st.Mode&07777, want)
		}
	default:
		t.Fatal("unexpected IO point", point)
	}
}

// Copies, opens, writes, renames and Bound recovery use real Linux IO. Sealed
// recovery only delegates to the response-only fixture authority. The IO spy
// returns errno at the same bound callback used by the authenticated witness.
func TestManagedIOActualBoundariesAndRecoveryOwnership(t *testing.T) {
	for index, point := range managedIOPoints {
		for _, errno := range []error{unix.EIO, unix.ENOSPC} {
			t.Run(point+"/"+errno.Error(), func(t *testing.T) {
				f := newManagedCopyFixture(t)
				rootfs, source := managedIOSource(t)
				if err := f.copy.control(w.BeginCopy); err != nil {
					t.Fatal(err)
				}
				var reached []string
				f.copy.io = func(actual string) error {
					reached = append(reached, actual)
					assertManagedIOBoundary(t, f, actual)
					if actual == point {
						return errno
					}
					return nil
				}
				if err := f.copy.copyDirectory(source); !errors.Is(err, errno) {
					t.Fatalf("lost injected errno: %v", err)
				}
				if !reflect.DeepEqual(reached, managedIOPoints[:index+1]) {
					t.Fatal("wrong operation order or foreign operation", reached)
				}
				wantPhase := a.CopyBound
				if index >= 4 {
					wantPhase = a.CopySealed
				}
				if f.intent.Phase != wantPhase {
					t.Fatal("failure advanced transaction", f.intent.Phase)
				}
				for _, action := range f.calls {
					if action == w.StartCleanup || action == w.FinishCopy {
						t.Fatal("failed copy falsely completed")
					}
				}
				if wantPhase == a.CopySealed {
					f.failure[w.RollbackCopy] = unix.ESTALE
					assertManagedRollbackDelegation(t, f, f.copy.intent, unix.ESTALE)
					delete(f.failure, w.RollbackCopy)
					f.copy.io = nil
					reply := managedRollbackCleaningReply(t, f)
					f.rollbackReply = &reply
					assertManagedRollbackDelegation(t, f, reply.Intent, nil)
					// The fake reply performs no service rollback/Finish or fresh retry.
					return
				}
				// Bound recovery remains real; uncertain identity grants no waiver.
				f.identityErrors[""] = unix.ESTALE
				if _, err := f.copy.recover(); !errors.Is(err, unix.ESTALE) {
					t.Fatal("uncertainty waived", err)
				}
				delete(f.identityErrors, "")
				f.copy.io = nil
				if recovered, err := f.copy.recover(); err != nil || !recovered {
					t.Fatal("ordinary recovery", recovered, err)
				}
				if err := f.copy.finish(); err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(f.base)
				if err != nil || len(entries) != 0 {
					t.Fatal("Bound recovery left partial output", entries, err)
				}
				f.copy.intent = a.CopyIntent{} // a fresh ordinary prepare owner
				if err := f.copy.initialize(rootfs, protocol.Mount{Destination: "/source"}); err != nil {
					t.Fatal("ordinary retry", err)
				}
				for _, name := range []string{"a", "z"} {
					raw, err := os.ReadFile(filepath.Join(f.base, name))
					if err != nil || string(raw) != "data-"+name {
						t.Fatal("retry output", err)
					}
				}
			})
		}
	}
}

func TestManagedIOUnselectedOperationsStillExecute(t *testing.T) {
	f := newManagedCopyFixture(t)
	_, source := managedIOSource(t)
	if err := f.copy.control(w.BeginCopy); err != nil {
		t.Fatal(err)
	}
	var reached []string
	f.copy.io = func(point string) error {
		reached = append(reached, point)
		return nil
	}
	if err := f.copy.copyDirectory(source); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reached, managedIOPoints) {
		t.Fatal("missed or extra cuts", reached)
	}
	if err := f.copy.finish(); err != nil {
		t.Fatal(err)
	}
	if f.intent.Phase != a.CopyCompleted {
		t.Fatal("not completed")
	}
	for _, name := range []string{"a", "z"} {
		raw, err := os.ReadFile(filepath.Join(f.base, name))
		if err != nil || string(raw) != "data-"+name {
			t.Fatal("unselected operation was faked", name, err)
		}
	}
}

func TestManagedIOBindingAndPrerequisites(t *testing.T) {
	copy := &managedCopy{}
	if copy.compatibilityIO() != nil {
		t.Fatal("ordinary copy armed")
	}
	copy.compatibility = &preparecompat.Witness{}
	if copy.compatibilityIO() != nil {
		t.Fatal("invalid witness armed")
	}
	calls := 0
	cut := managedCopyIO(func(string) error { calls++; return unix.EIO })
	if err := cut.syncDirectory(-1, "root-fsync"); !errors.Is(err, unix.EBADF) || calls != 0 {
		t.Fatal("cut before real directory open", err, calls)
	}
	for _, foreign := range []string{"z", "nested/a", "aa", ""} {
		if err := cut.childSync()(foreign); err != nil || calls != 0 {
			t.Fatal("foreign child cut", foreign, err)
		}
	}
	if err := cut.childSync()("a"); !errors.Is(err, unix.EIO) || calls != 1 {
		t.Fatal("selected child missed", err)
	}
	calls = 0
	if err := writeManagedManifestWithIO(-1, []byte("{}"), cut); !errors.Is(err, unix.EBADF) || calls != 0 {
		t.Fatal("cut before manifest open", err)
	}
	metadata := confinedCopyRootMetadata{Xattrs: &confinedXattrSnapshot{State: "invalid"}}
	if err := applyConfinedRootMetadataBeforeChown(-1, metadata, confinedXattrSyscalls(), func() error { calls++; return unix.EIO }); err == nil || calls != 0 {
		t.Fatal("cut before metadata validation", err)
	}
}
