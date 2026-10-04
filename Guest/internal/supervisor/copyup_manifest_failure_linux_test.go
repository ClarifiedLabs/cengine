//go:build linux

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"dev.cengine/guest/internal/preparecompat"
	"golang.org/x/sys/unix"
)

func TestManifestFailureActualOperations(t *testing.T) {
	for _, tc := range []struct {
		point string
		cause error
		stage manifestFailureStage
	}{
		{"manifest-write", unix.ENOSPC, manifestWriteCut},
		{"manifest-fsync", unix.EIO, manifestSyncCut},
		{"manifest-rename-parent-sync", preparecompat.ErrInvalidFrame, manifestDirectoryCut},
		{"manifest-rename-parent-sync", unix.EIO, manifestDirectoryCut},
	} {
		t.Run(tc.point+"/"+manifestFailureCategory(tc.cause), func(t *testing.T) {
			dir := t.TempDir()
			fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			calls := 0
			err = writeManagedManifestWithIO(fd, []byte("{}"), func(point string) error {
				if point == tc.point {
					calls++
					return tc.cause
				}
				return nil
			})
			var failure *manifestFailure
			if calls != 1 || !errors.As(err, &failure) || failure.stage != tc.stage || !errors.Is(err, tc.cause) {
				t.Fatalf("wrong failure: %v calls=%d", err, calls)
			}
			name := confinedCopyManifestTemporary
			if tc.stage == manifestDirectoryCut {
				name = confinedCopyManifestName
			}
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatal("failure removed evidence", err)
			}
		})
	}
	t.Run("directory-reopen-before-cut", func(t *testing.T) {
		called := false
		cut := managedCopyIO(func(string) error { called = true; return nil })
		err := cut.syncDirectory(-1, "manifest-rename-parent-sync")
		var failure *manifestFailure
		if called || !errors.As(err, &failure) || failure.stage != manifestDirectoryReopen || !errors.Is(err, unix.EBADF) {
			t.Fatalf("wrong reopen result: %v", err)
		}
	})
	t.Run("rename", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, confinedCopyManifestName), []byte("existing"), 0600); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		err = writeManagedManifest(fd, []byte("{}"))
		var failure *manifestFailure
		if !errors.As(err, &failure) || failure.stage != manifestRename || !errors.Is(err, unix.EEXIST) {
			t.Fatalf("wrong rename result: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, confinedCopyManifestName))
		if err != nil || string(raw) != "existing" {
			t.Fatal("replaced existing manifest", err)
		}
	})
}
