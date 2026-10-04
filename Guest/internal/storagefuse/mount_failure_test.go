package storagefuse

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// Any accidental raw formatting fails the test instead of exposing its contents.
type unprintableMountError struct{}

func (unprintableMountError) Error() string { panic("raw mount error was formatted") }

func TestMountFailureDiagnosticClosedStagesAndCategories(t *testing.T) {
	stages := []struct {
		stage mountStage
		name  string
	}{
		{stagePreflight, "preflight"}, {stageData, "data"}, {stageRoot, "root"},
		{stageNamespace, "namespace"}, {stageDevice, "device"}, {stageMount, "mount"},
		{stageMountIdentity, "mount-identity"}, {stageFusectl, "fusectl"},
		{stageInit, "init"}, {stageActive, "active"}, {stageOther, "other"}, {mountStage(999), "other"},
	}
	causes := []struct {
		err  error
		name string
	}{
		{unix.EINVAL, "EINVAL"}, {unix.EPERM, "EPERM"}, {unix.EACCES, "EACCES"},
		{unix.EOPNOTSUPP, "EOPNOTSUPP"}, {unix.ENOENT, "ENOENT"}, {unix.ENOTDIR, "ENOTDIR"},
		{unix.ELOOP, "ELOOP"}, {unix.EEXIST, "EEXIST"}, {unix.EBUSY, "EBUSY"},
		{unix.EIO, "EIO"}, {unix.ENODEV, "ENODEV"}, {unix.ENOSYS, "ENOSYS"},
		{unix.EMFILE, "EMFILE"}, {unix.ENFILE, "ENFILE"}, {unix.ENOMEM, "ENOMEM"},
		{unix.ENOSPC, "ENOSPC"}, {unix.EROFS, "EROFS"}, {unix.ECONNRESET, "ECONNRESET"},
		{unix.ECONNREFUSED, "ECONNREFUSED"}, {unix.EPIPE, "EPIPE"}, {unix.ETIMEDOUT, "ETIMEDOUT"},
		{unix.ENOTCONN, "ENOTCONN"}, {unix.EINTR, "EINTR"}, {unix.Errno(9999), "other"},
		{io.ErrShortWrite, "short-write"}, {c.ErrGrant, "grant"}, {errTranslation, "translation"},
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{errMountInitDeadline, "deadline"}, {ErrProfile, "profile"},
		{c.ErrCapacity, "capacity"}, {c.ErrProtocol, "protocol"}, {w.ErrInvalid, "protocol"},
		{c.ErrCredentials, "credentials"}, {c.ErrUnsupported, "unsupported"},
		{io.EOF, "eof"}, {io.ErrUnexpectedEOF, "eof"}, {c.ErrClosed, "closed"},
		{os.ErrDeadlineExceeded, "io-deadline"}, {net.ErrClosed, "net-closed"}, {io.ErrClosedPipe, "closed-pipe"}, {c.ErrIncomplete, "incomplete"},
		{unprintableMountError{}, "other"},
	}
	for _, stage := range stages {
		for _, cause := range causes {
			t.Run(stage.name+"/"+cause.name, func(t *testing.T) {
				// Path, operation, joined error text and arbitrary underlying errors
				// must never be included in either diagnostic field.
				wrapped := &mountFailure{stage: stage.stage, cause: &os.PathError{
					Op: "SECRET operation", Path: "/SECRET/path\nspoof", Err: errors.Join(unprintableMountError{}, cause.err),
				}}
				gotStage, gotCategory := MountFailureDiagnostic(wrapped)
				if gotStage != stage.name || gotCategory != cause.name {
					t.Fatalf("diagnostic = %q/%q, want %q/%q", gotStage, gotCategory, stage.name, cause.name)
				}
				if wrapped.Error() != "storagefuse: mount failure" {
					t.Fatal("wrapper text is not fixed")
				}
			})
		}
	}
	for _, err := range []error{nil, unprintableMountError{}} {
		if stage, category := MountFailureDiagnostic(err); stage != "other" || category != "other" {
			t.Fatalf("unknown diagnostic = %q/%q", stage, category)
		}
	}
}

func TestMountFailureTrackerKeepsFirstCauseAndErrorIdentity(t *testing.T) {
	tracker := &mountFailureTracker{}
	tracker.enter(stageData)
	original := &os.PathError{Op: "SECRET", Path: "/SECRET", Err: unix.EPERM}
	first := tracker.wrap(original)
	tracker.enter(stageNamespace)
	last := tracker.wrap(errors.Join(first, unix.EIO))
	if stage, category := MountFailureDiagnostic(last); stage != "data" || category != "EPERM" {
		t.Fatalf("first failure replaced: %q/%q", stage, category)
	}
	var pathError *os.PathError
	if !errors.Is(last, unix.EPERM) || !errors.Is(last, unix.EIO) || !errors.As(last, &pathError) || pathError != original {
		t.Fatal("wrapping lost original or cleanup error identity")
	}
	if tracker.wrap(nil) != nil {
		t.Fatal("successful construction became failure")
	}
}

func TestMountFailureTrackerConcurrentRetirementKeepsFirstFailure(t *testing.T) {
	tracker := &mountFailureTracker{}
	tracker.enter(stageInit)
	tracker.wrap(errMountInitDeadline)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			tracker.enter(stageActive)
			err := tracker.wrap(c.ErrClosed)
			if stage, category := MountFailureDiagnostic(err); stage != "init" || category != "deadline" {
				t.Errorf("first failure changed: %q/%q", stage, category)
			}
		}()
	}
	workers.Wait()
}

func TestMountFailureDiagnosticRetainsInitProfileRejection(t *testing.T) {
	tracker := &mountFailureTracker{}
	tracker.enter(stageInit)
	raw, client := fixture()
	var retired error
	raw.retire = func(err error) { retired = tracker.wrap(err) }
	// These are the real validator and reply observer used by native construction.
	// Validation must not itself retire; the EINVAL delivery remains the trigger.
	if err := tracker.validateInit(raw, fuse.InitOut{}); err != ErrProfile || retired != nil || client.aborted != 0 {
		t.Fatal("validation or retirement ordering changed")
	}
	raw.observeReply(fuse.ReplyDelivery{Opcode: 26, Status: fuse.EINVAL})
	if client.aborted != 1 || retired == nil {
		t.Fatal("rejected INIT did not retire through reply observation")
	}
	if stage, category := MountFailureDiagnostic(retired); stage != "init" || category != "profile" {
		t.Fatalf("INIT profile cause was lost: %q/%q", stage, category)
	}
}

func TestMountFailureDiagnosticUsesRealConstructorValidation(t *testing.T) {
	mounted, err := Mount(Config{Mountpoint: "/SECRET/path", Retire: func(error) { t.Fatal("validation retired attachment") }})
	if mounted != nil || !errors.Is(err, ErrProfile) {
		t.Fatal("unexpected constructor result")
	}
	if stage, category := MountFailureDiagnostic(err); stage != "preflight" || category != "profile" {
		t.Fatalf("constructor diagnostic = %q/%q", stage, category)
	}
}

func TestMountFailureDiagnosticNewCausesPreservePrecedence(t *testing.T) {
	for _, cause := range []error{os.ErrDeadlineExceeded, net.ErrClosed, io.ErrClosedPipe, c.ErrIncomplete} {
		for _, primary := range []struct {
			err      error
			category string
		}{
			{unix.EIO, "EIO"}, {unix.EPIPE, "EPIPE"}, {context.DeadlineExceeded, "deadline"},
			{context.Canceled, "canceled"}, {c.ErrProtocol, "protocol"}, {io.EOF, "eof"},
		} {
			_, got := MountFailureDiagnostic(errors.Join(c.ErrClosed, cause, primary.err))
			if got != primary.category {
				t.Fatal("existing precedence changed", got)
			}
		}
	}
}
