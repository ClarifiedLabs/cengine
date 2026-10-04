package storagefuse

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// Stages and categories are a closed diagnostic vocabulary, not protocol fields.
// Never derive either from an error string, pathname, credential or request.
type mountStage uint32

const (
	stageOther mountStage = iota
	stagePreflight
	stageData
	stageRoot
	stageNamespace
	stageDevice
	stageMount
	stageMountIdentity
	stageFusectl
	stageInit
	stageActive
)

func (s mountStage) name() string {
	switch s {
	case stagePreflight:
		return "preflight"
	case stageData:
		return "data"
	case stageRoot:
		return "root"
	case stageNamespace:
		return "namespace"
	case stageDevice:
		return "device"
	case stageMount:
		return "mount"
	case stageMountIdentity:
		return "mount-identity"
	case stageFusectl:
		return "fusectl"
	case stageInit:
		return "init"
	case stageActive:
		return "active"
	default:
		return "other"
	}
}

type mountFailure struct {
	stage mountStage
	cause error
}

func (*mountFailure) Error() string   { return "storagefuse: mount failure" }
func (e *mountFailure) Unwrap() error { return e.cause }

// Async INIT/delivery failures can precede the constructor's return or cleanup.
// Preserve their first observed stage/cause without racing stage advancement.
type mountFailureTracker struct {
	stage atomic.Uint32
	once  sync.Once
	first *mountFailure
}

func (t *mountFailureTracker) enter(stage mountStage) { t.stage.Store(uint32(stage)) }
func (t *mountFailureTracker) wrap(err error) error {
	if err == nil {
		return nil
	}
	t.once.Do(func() { t.first = &mountFailure{stage: mountStage(t.stage.Load()), cause: err} })
	// Preserve subsequent cleanup causes for errors.Is/As without replacing the
	// first diagnostic. The formatter selects the private wrapper, not Join.Error.
	return errors.Join(t.first, err)
}

// Capture the original profile rejection before go-fuse turns it into an EINVAL
// reply and ObserveReply retires with a generic translation failure.
func (t *mountFailureTracker) validateInit(f *rawFS, out fuse.InitOut) error {
	err := f.validateInit(out)
	t.wrap(err)
	return err // validation, reply delivery and retirement behavior are unchanged
}

// MountFailureDiagnostic returns only allowlisted constants. It NEVER calls
// Error or formats an error value. Unknown stages/causes deliberately say other.
// The original errors remain available to errors.Is/As for internal decisions.
func MountFailureDiagnostic(err error) (stage, category string) {
	stage = "other"
	var failure *mountFailure
	if errors.As(err, &failure) && failure != nil {
		stage, err = failure.stage.name(), failure.cause
	}
	return stage, mountFailureCategory(err)
}

func mountFailureCategory(err error) string {
	for _, entry := range []struct {
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
		{unix.ENOTCONN, "ENOTCONN"}, {unix.EINTR, "EINTR"},
		{io.ErrShortWrite, "short-write"},
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{errMountInitDeadline, "deadline"}, {ErrProfile, "profile"},
		{c.ErrCapacity, "capacity"}, {c.ErrProtocol, "protocol"}, {w.ErrInvalid, "protocol"},
		{c.ErrCredentials, "credentials"}, {c.ErrUnsupported, "unsupported"},
		{c.ErrGrant, "grant"}, {errTranslation, "translation"},
		{io.EOF, "eof"}, {io.ErrUnexpectedEOF, "eof"},
		// Refine only the former closed/other fallback; existing errno and
		// context/protocol/EOF precedence remains unchanged.
		{os.ErrDeadlineExceeded, "io-deadline"}, {c.ErrIncomplete, "incomplete"},
		{net.ErrClosed, "net-closed"}, {io.ErrClosedPipe, "closed-pipe"}, {c.ErrClosed, "closed"},
	} {
		if errors.Is(err, entry.err) {
			return entry.name
		}
	}
	return "other"
}

var errMountInitDeadline = errors.New("storagefuse: INIT deadline")
