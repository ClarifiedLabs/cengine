package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"dev.cengine/guest/internal/preparecompat"
	"golang.org/x/sys/unix"
)

type manifestPrivateError struct{}

func (*manifestPrivateError) Error() string { panic("must not format private error") }

func TestManifestFailureClosedStagesAndCauses(t *testing.T) {
	stages := []string{"manifest-open", "manifest-write-cut", "manifest-write", "manifest-fsync-cut", "manifest-file-sync", "manifest-file-close", "manifest-rename", "manifest-directory-reopen", "manifest-directory-cut", "manifest-directory-sync"}
	for n := 0; n < 256; n++ {
		stage := manifestFailureStage(n)
		wantStage := "other"
		if n < len(stages) {
			wantStage = stages[n]
		}
		for _, tc := range []struct {
			cause    error
			category string
		}{
			{unix.EIO, "EIO"}, {unix.ENOSPC, "ENOSPC"}, {unix.EBADF, "EBADF"},
			{preparecompat.ErrInvalidFrame, "invalid-frame"}, {&manifestPrivateError{}, "other"},
			{&os.PathError{Op: "secret", Path: "private-path", Err: unix.EACCES}, "EACCES"},
		} {
			err := wrapManifestFailure(stage, tc.cause)
			if !errors.Is(err, tc.cause) {
				t.Fatal("lost cause")
			}
			want := "managed copy-up: stage=" + wantStage + " category=" + tc.category
			if err.Error() != want {
				t.Fatalf("got %q want %q", err.Error(), want)
			}
			if wrapManifestFailure(manifestRename, err) != err {
				t.Fatal("lost precise stage")
			}
			var got *manifestFailure
			if !errors.As(fmt.Errorf("outer: %w", err), &got) || got.cause != tc.cause {
				t.Fatal("lost typed cause")
			}
		}
		if wrapManifestFailure(stage, nil) != nil {
			t.Fatal("changed success")
		}
	}
}

type manifestFailedSink struct{ writes int }

func (s *manifestFailedSink) Write(p []byte) (int, error) {
	s.writes++
	return 0, unix.ENOSPC
}

func TestManifestFailureReportClosedAndBestEffort(t *testing.T) {
	var output bytes.Buffer
	for _, err := range []error{nil, &manifestPrivateError{}} {
		reportManifestFailure(&output, err)
	}
	if output.Len() != 0 {
		t.Fatal("reported success or unrelated error")
	}
	cause := &manifestPrivateError{}
	err := wrapManifestFailure(manifestRename, cause)
	reportManifestFailure(&output, err)
	if output.String() != "cengine managed-copyup-manifest-failure stage=manifest-rename category=other\n" {
		t.Fatal("unexpected closed report", output.String())
	}
	failed := &manifestFailedSink{}
	reportManifestFailure(failed, err)
	if failed.writes != 1 || !errors.Is(err, cause) {
		t.Fatal("diagnostic write changed failure or retried")
	}
}

// Host-runnable source contract complements the Linux operation tests. In
// particular, file.Sync/Close/rename and directory reopen precede distinct cuts.
func TestManifestFailureOperationWiring(t *testing.T) {
	for file, sequences := range map[string][]string{
		"copyup_managed_identity_linux.go": {
			"stage = manifestWriteCut\n\tif err := cut.before(\"manifest-write\")",
			"stage = manifestWrite\n\tif _, err := file.Write",
			"stage = manifestSyncCut\n\tif err := cut.before(\"manifest-fsync\")",
			"stage = manifestSync\n\tif err := file.Sync()",
			"stage = manifestClose\n\tif err := file.Close()",
			"stage = manifestRename\n\tif err := renameConfinedNoReplace",
			"result = wrapManifestFailure(stage, result)",
			"if cut != nil {\n\t\t\treportManifestFailure(os.Stderr, result)\n\t\t}",
		},
		"copyup_io_linux.go": {
			"stage := manifestDirectoryReopen", "if point == \"manifest-rename-parent-sync\"",
			"stage = manifestDirectoryCut\n\tif err := cut.before(point)",
			"stage = manifestDirectorySync\n\treturn unix.Fsync(fd)",
		},
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, sequence := range sequences {
			if strings.Count(string(raw), sequence) != 1 {
				t.Fatalf("missing/duplicate wiring %s: %s", file, sequence)
			}
		}
	}
}
