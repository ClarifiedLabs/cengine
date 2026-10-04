package supervisor

import (
	"errors"
	"fmt"
	"io"

	"dev.cengine/guest/internal/preparecompat"
	"golang.org/x/sys/unix"
)

// Closed diagnostics for actual returned errors, never progress/stall inference.
// Preserve the cause for Is/As without formatting paths or private payloads.
type manifestFailureStage uint8

const (
	manifestOpen manifestFailureStage = iota
	manifestWriteCut
	manifestWrite
	manifestSyncCut
	manifestSync
	manifestClose
	manifestRename
	manifestDirectoryReopen
	manifestDirectoryCut
	manifestDirectorySync
)

func (s manifestFailureStage) name() string {
	switch s {
	case manifestOpen:
		return "manifest-open"
	case manifestWriteCut:
		return "manifest-write-cut"
	case manifestWrite:
		return "manifest-write"
	case manifestSyncCut:
		return "manifest-fsync-cut"
	case manifestSync:
		return "manifest-file-sync"
	case manifestClose:
		return "manifest-file-close"
	case manifestRename:
		return "manifest-rename"
	case manifestDirectoryReopen:
		return "manifest-directory-reopen"
	case manifestDirectoryCut:
		return "manifest-directory-cut"
	case manifestDirectorySync:
		return "manifest-directory-sync"
	default:
		return "other"
	}
}

type manifestFailure struct {
	stage manifestFailureStage
	cause error
}

func (e *manifestFailure) Error() string {
	return "managed copy-up: stage=" + e.stage.name() + " category=" + manifestFailureCategory(e.cause)
}
func (e *manifestFailure) Unwrap() error { return e.cause }

func wrapManifestFailure(stage manifestFailureStage, err error) error {
	if err == nil {
		return nil
	}
	var existing *manifestFailure
	if errors.As(err, &existing) {
		return err // Preserve the more precise directory stage through the writer.
	}
	return &manifestFailure{stage: stage, cause: err}
}

// The private Session intentionally reduces Prepare errors to a closed code.
// Emit only our closed projection at the selected workload-IO writer, before
// that boundary discards detail. A failed diagnostic write never changes results.
func reportManifestFailure(out io.Writer, err error) {
	var failure *manifestFailure
	if errors.As(err, &failure) {
		fmt.Fprintf(out, "cengine managed-copyup-manifest-failure stage=%s category=%s\n", failure.stage.name(), manifestFailureCategory(failure.cause))
	}
}

func manifestFailureCategory(err error) string {
	for _, entry := range []struct {
		err  error
		name string
	}{
		{preparecompat.ErrInvalidFrame, "invalid-frame"},
		{unix.EIO, "EIO"}, {unix.ENOSPC, "ENOSPC"}, {unix.EBADF, "EBADF"},
		{unix.EINVAL, "EINVAL"}, {unix.EPERM, "EPERM"}, {unix.EACCES, "EACCES"},
		{unix.ENOENT, "ENOENT"}, {unix.ENOTDIR, "ENOTDIR"}, {unix.EEXIST, "EEXIST"},
		{unix.ELOOP, "ELOOP"}, {unix.EROFS, "EROFS"}, {unix.EOPNOTSUPP, "EOPNOTSUPP"},
		{unix.ESTALE, "ESTALE"}, {unix.EINTR, "EINTR"},
	} {
		if errors.Is(err, entry.err) {
			return entry.name
		}
	}
	return "other"
}
