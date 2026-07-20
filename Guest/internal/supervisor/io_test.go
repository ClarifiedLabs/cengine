//go:build linux

package supervisor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPinnedProcessIORejectsSymlinkForContainerAndExec(t *testing.T) {
	for _, prefix := range []string{"", "exec-test-"} {
		t.Run(prefix, func(t *testing.T) {
			directory := t.TempDir()
			createProcessIOFiles(t, directory, prefix)
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(directory, prefix+"stdout")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(directory, prefix+"stdout")); err != nil {
				t.Fatal(err)
			}

			if processIO, err := openPinnedProcessIO(directory, prefix, "claim"); err == nil {
				processIO.close()
				t.Fatal("pinned I/O followed a symbolic link")
			}
		})
	}
}

func TestPinnedProcessIOClaimExposesPreOpenReplacement(t *testing.T) {
	for _, prefix := range []string{"", "exec-test-"} {
		t.Run(prefix, func(t *testing.T) {
			directory := t.TempDir()
			createProcessIOFiles(t, directory, prefix)
			stdoutPath := filepath.Join(directory, prefix+"stdout")
			original := fileIdentity(t, stdoutPath)
			if err := os.Rename(stdoutPath, stdoutPath+".detached"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stdoutPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			processIO, err := openPinnedProcessIO(directory, prefix, "claim")
			if err != nil {
				t.Fatal(err)
			}
			defer processIO.close()
			claim := fileIdentity(t, filepath.Join(directory, ioClaimName("claim", 0)))
			if claim.Dev == original.Dev && claim.Ino == original.Ino {
				t.Fatal("claim hid a replacement that occurred before the guest open")
			}
		})
	}
}

func TestPinnedInputIgnoresLiveNameAndMarkerReplacement(t *testing.T) {
	for _, prefix := range []string{"", "exec-test-"} {
		t.Run(prefix, func(t *testing.T) {
			directory := t.TempDir()
			createProcessIOFiles(t, directory, prefix)
			processIO, err := openPinnedProcessIO(directory, prefix, "claim")
			if err != nil {
				t.Fatal(err)
			}
			defer processIO.close()

			stdinPath := filepath.Join(directory, prefix+"stdin")
			retainedStdinPath := stdinPath + ".retained"
			if err := os.Rename(stdinPath, retainedStdinPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stdinPath, []byte("replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(retainedStdinPath, []byte("retained"), 0o600); err != nil {
				t.Fatal(err)
			}

			markerPath := filepath.Join(directory, prefix+"stdin.closed")
			retainedMarkerPath := markerPath + ".retained"
			if err := os.Rename(markerPath, retainedMarkerPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(markerPath, []byte{1}, 0o600); err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			closed, err := pumpInputStep(processIO.stdin, processIO.stdinClosed, &output)
			if err != nil {
				t.Fatal(err)
			}
			if closed {
				t.Fatal("replacement marker prematurely closed pinned input")
			}
			if output.String() != "retained" {
				t.Fatalf("input = %q, want retained", output.String())
			}
			if err := os.WriteFile(retainedMarkerPath, []byte{1}, 0o600); err != nil {
				t.Fatal(err)
			}
			closed, err = pumpInputStep(processIO.stdin, processIO.stdinClosed, &output)
			if err != nil {
				t.Fatal(err)
			}
			if !closed {
				t.Fatal("pinned EOF marker did not close input")
			}
		})
	}
}

func TestPinnedInputUsesEmptyAndNonemptyEOFStates(t *testing.T) {
	for _, prefix := range []string{"", "exec-test-"} {
		t.Run(prefix, func(t *testing.T) {
			directory := t.TempDir()
			createProcessIOFiles(t, directory, prefix)
			processIO, err := openPinnedProcessIO(directory, prefix, "claim")
			if err != nil {
				t.Fatal(err)
			}
			defer processIO.close()

			closed, err := pumpInputStep(processIO.stdin, processIO.stdinClosed, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			if closed {
				t.Fatal("empty EOF marker closed attached input")
			}
			if _, err := processIO.stdinClosed.WriteAt([]byte{1}, 0); err == nil {
				t.Fatal("guest EOF descriptor unexpectedly permits writes")
			}
			if err := os.WriteFile(filepath.Join(directory, prefix+"stdin.closed"), []byte{1}, 0o600); err != nil {
				t.Fatal(err)
			}
			closed, err = pumpInputStep(processIO.stdin, processIO.stdinClosed, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			if !closed {
				t.Fatal("nonempty EOF marker did not close nonattached input")
			}
		})
	}
}

func createProcessIOFiles(t *testing.T, directory, prefix string) {
	t.Helper()
	for _, suffix := range []string{"stdout", "stderr", "stdin", "stdin.closed"} {
		if err := os.WriteFile(filepath.Join(directory, prefix+suffix), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func fileIdentity(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var identity unix.Stat_t
	if err := unix.Lstat(path, &identity); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		t.Fatal(err)
	}
	return identity
}
