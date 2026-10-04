package supervisor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type opaquePrepareError struct{}

func (*opaquePrepareError) Error() string { panic("private prepare error formatted") }

func TestPrepareFailureStagePreservesIdentityAndClosedVocabulary(t *testing.T) {
	opaque := &opaquePrepareError{}
	cause := &os.PathError{Op: "SECRET", Path: "/SECRET\nspoof", Err: errors.Join(unix.EIO, opaque)}
	names := []string{"validation", "root-mount", "managed-copyup", "volume", "io-mount", "io-claim", "commit"}
	for stage := PrepareStage(0); ; stage++ {
		err := WithPrepareFailureStage(stage, cause)
		var path *os.PathError
		if !errors.Is(err, unix.EIO) || !errors.Is(err, opaque) || !errors.As(err, &path) || path != cause || err.Error() != "supervisor: prepare failure" {
			t.Fatal("error semantics changed")
		}
		want := "other"
		if int(stage) < len(names) {
			want = names[stage]
		}
		if PrepareFailureStage(err) != want || WithPrepareFailureStage(PrepareValidation, err) != err {
			t.Fatal("stage replaced")
		}
		if stage == 255 {
			break
		}
	}
	if WithPrepareFailureStage(PrepareValidation, nil) != nil || PrepareFailureStage(opaque) != "other" {
		t.Fatal("unknown/nil handling")
	}
}

// Host-safe source regression: no rootfs mount, FUSE or guest process is run.
func TestPrepareFailureProductionStageBoundaries(t *testing.T) {
	data, err := os.ReadFile("supervisor.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, boundary := range []struct{ stage, call string }{
		{"PrepareRootMount", "disk.MountExistingExt4("},
		{"PrepareManagedCopyUp", "s.initializeManagedVolume("},
		{"PrepareVolume", "initializeVolume(spec, mount)"},
		{"PrepareIOMount", "os.MkdirAll(\"/run/cengine/io\""},
		{"PrepareIOClaim", "openPinnedProcessIO(ioDirectoryPath"},
	} {
		assignment := strings.Index(source, "stage = "+boundary.stage)
		call := strings.Index(source, boundary.call)
		if assignment < 0 || call < assignment || call-assignment > 150 {
			t.Fatal("missing stage before production call", boundary.stage)
		}
	}
	if !strings.Contains(source, "result = WithPrepareFailureStage(stage, result)") {
		t.Fatal("production result not wrapped")
	}
}

func TestPrepareFailureCancellationKeepsStepNotOverriddenCause(t *testing.T) {
	previous := WithPrepareFailureStage(PrepareManagedCopyUp, unix.EIO)
	err := replacePrepareFailureCause(previous, context.Canceled)
	if PrepareFailureStage(err) != "managed-copyup" || !errors.Is(err, context.Canceled) || errors.Is(err, unix.EIO) {
		t.Fatal("cancellation cause/step changed")
	}
	if replacePrepareFailureCause(nil, context.Canceled) != context.Canceled {
		t.Fatal("unwrapped cancellation changed")
	}
}
