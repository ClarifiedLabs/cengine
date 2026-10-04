package storagefuse

import (
	"errors"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// Failure sites describe code branches, never request data or kernel identities.
type failureSite uint8

const (
	siteOther failureSite = iota
	siteAdmission
	siteCapture
	sitePresentLifecycle
	siteNoneCaller
	siteCredentialKind
	siteWritebackProvenance
	siteClientDo
	siteClientGrant
	siteReplyErrno
	siteReplyEntryKind
	siteReplyEntryAttr
	siteReplyAttrKind
	siteReplyAttr
	siteReplyHandle
	siteReplyReadSize
	siteReplyWriteSize
	siteReplyDirSize
	siteReplyXattrSize
	siteReleaseStatus
	siteForget
	siteReplyDelivery
	siteInterrupted
	siteSuppressed
	siteInitReply
	siteDirectoryAdmission
	siteDirectoryGrant
	siteDirectoryRelease
	siteDirectoryReturn
	siteDirectoryDelivery
	siteDestroy
	siteServeExit
	sitePanic
	siteDataTerminal
)

func (s failureSite) name() string {
	names := [...]string{
		"other", "admission", "capture", "provenance-present-lifecycle", "provenance-none-caller",
		"provenance-kind", "provenance-writeback", "client-do", "client-grant", "reply-errno",
		"reply-entry-kind", "reply-entry-attr", "reply-attr-kind", "reply-attr", "reply-handle",
		"reply-read-size", "reply-write-size", "reply-directory-size", "reply-xattr-size", "release-status",
		"forget", "reply-delivery", "interrupted", "suppressed", "init-reply", "directory-admission",
		"directory-grant", "directory-release", "directory-return", "directory-delivery", "destroy", "serve-exit", "panic", "data-terminal",
	}
	if int(s) >= len(names) {
		return "other"
	}
	return names[s]
}

// Only a known opcode's fixed name may be exposed; never format the numeric input.
func failureOperation(opcode uint32) string {
	switch opcode {
	case 1:
		return "LOOKUP"
	case 2:
		return "FORGET"
	case 3:
		return "GETATTR"
	case 4:
		return "SETATTR"
	case 5:
		return "READLINK"
	case 6:
		return "SYMLINK"
	case 8:
		return "MKNOD"
	case 9:
		return "MKDIR"
	case 10:
		return "UNLINK"
	case 11:
		return "RMDIR"
	case 12:
		return "RENAME"
	case 13:
		return "LINK"
	case 14:
		return "OPEN"
	case 15:
		return "READ"
	case 16:
		return "WRITE"
	case 17:
		return "STATFS"
	case 18:
		return "RELEASE"
	case 20:
		return "FSYNC"
	case 21:
		return "SETXATTR"
	case 22:
		return "GETXATTR"
	case 23:
		return "LISTXATTR"
	case 24:
		return "REMOVEXATTR"
	case 25:
		return "FLUSH"
	case 26:
		return "INIT"
	case 27:
		return "OPENDIR"
	case 28:
		return "READDIR"
	case 29:
		return "RELEASEDIR"
	case 30:
		return "FSYNCDIR"
	case 31:
		return "GETLK"
	case 32:
		return "SETLK"
	case 33:
		return "SETLKW"
	case 34:
		return "ACCESS"
	case 35:
		return "CREATE"
	case 36:
		return "INTERRUPT"
	case 38:
		return "DESTROY"
	case 39:
		return "IOCTL"
	case 41:
		return "NOTIFY_REPLY"
	case 42:
		return "BATCH_FORGET"
	case 43:
		return "FALLOCATE"
	case 44:
		return "READDIRPLUS"
	case 45:
		return "RENAME2"
	case 46:
		return "LSEEK"
	case 47:
		return "COPY_FILE_RANGE"
	case 52:
		return "STATX"
	default:
		return "other"
	}
}

type callbackFailure struct {
	site   failureSite
	opcode uint32
	cause  error
}

func (*callbackFailure) Error() string   { return "storagefuse: callback failure" }
func (e *callbackFailure) Unwrap() error { return e.cause }

func (f *rawFS) stopAt(site failureSite, opcode uint32, err error) {
	f.stop(&callbackFailure{site: site, opcode: opcode, cause: err})
}

// A DATA terminal watcher has no originating request header. Never borrow an
// opcode from a concurrent callback; make this observation point explicit.
func (f *rawFS) terminalFailure(err error) { f.stopAt(siteDataTerminal, 0, err) }

func directoryDeliverySite(r fuse.ReplyDelivery) failureSite {
	if r.Interrupted || r.Status == fuse.EINTR {
		return siteInterrupted
	}
	if r.Suppressed {
		return siteSuppressed
	}
	return siteDirectoryDelivery
}

func (f *rawFS) badAt(site failureSite, opcode uint32) fuse.Status {
	f.stopAt(site, opcode, errTranslation)
	return fuse.EIO
}

// Retain only the opcode across the existing go-fuse panic boundary. Do not log,
// stringify, or retain a panic payload. The existing handler still owns stop/EIO.
type callbackPanic struct{ opcode uint32 }

func markCallbackPanic(opcode uint32) {
	if value := recover(); value != nil {
		if marked, ok := value.(callbackPanic); ok {
			panic(marked)
		}
		panic(callbackPanic{opcode: opcode})
	}
}
func (f *rawFS) panicFailure(value any) fuse.Status {
	var opcode uint32
	if marked, ok := value.(callbackPanic); ok {
		opcode = marked.opcode
	}
	return f.badAt(sitePanic, opcode)
}

// MountFailureDetails extends the original diagnostic with closed callback site
// and opcode names. Select the first construction cause before looking for site
// information, so later cleanup can never supply a misleading callback identity.
func MountFailureDetails(err error) (stage, site, operation, category string) {
	stage, category = MountFailureDiagnostic(err)
	var construction *mountFailure
	if errors.As(err, &construction) && construction != nil {
		err = construction.cause
	}
	site, operation = "other", "other"
	var callback *callbackFailure
	if errors.As(err, &callback) && callback != nil {
		site, operation = callback.site.name(), failureOperation(callback.opcode)
	}
	return
}

func firstOpcode(opcodes []uint32) uint32 {
	if len(opcodes) != 0 {
		return opcodes[0]
	}
	return 0
}
