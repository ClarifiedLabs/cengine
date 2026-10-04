//go:build linux || darwin

package workloadstorage

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// This unwired prerequisite is NOT an original-consumer observation. In
// particular, context cancellation cannot interrupt regular-file/FUSE syscalls.
// A native caller needs a separately proven bounded abort-and-join owner before
// using it. No detached goroutine, timeout-as-denial, or forced EBADF is used.
const retainedFDName = "a" // existing RTM096/103 fixture; never create/truncate

var errRetainedFDBusy = errors.New("retained descriptor operation active")

type retainedFDIdentity struct {
	device, inode, mount uint64
}

type retainedFD struct {
	mu                          sync.Mutex
	file                        *os.File
	identity                    retainedFDIdentity
	positive, attempted, closed bool
}

// Results retain actual syscall outcomes, including partial writes and a sync
// failure after a successful write. They deliberately have no "denied" predicate.
// Neither error text nor a context error proves storage-authority rejection.
type retainedFDResult struct {
	readBytes         int
	readErr           error
	readSHA256        string
	identity          retainedFDIdentity
	written           int
	writeErr, syncErr error
	completed         bool
}

func retainedFDContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidFrame
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > originalConsumerBudget {
		return ErrInvalidFrame
	}
	return nil
}

// retainedFDPinRoot takes an owned duplicate while os.File prevents concurrent
// Close/finalization from recycling the borrowed descriptor. All raw syscalls
// below use this duplicate, never an unprotected integer from the borrowed root.
func retainedFDPinRoot(root *os.File) (*os.File, error) {
	if root == nil {
		return nil, ErrInvalidFrame
	}
	raw, err := root.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var duplicateErr error
	if err = raw.Control(func(borrowed uintptr) {
		fd, duplicateErr = unix.FcntlInt(borrowed, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil {
		return nil, err
	}
	if duplicateErr != nil {
		return nil, duplicateErr
	}
	return os.NewFile(uintptr(fd), "original-retained-root"), nil
}

// root must be the live original owner's pinned directory, not a caller path.
// It is borrowed only during open. The helper owns the returned file exclusively.
// Linux verifies mount IDs and disallows mount crossings atomically at open.
// Darwin is only a host-test implementation, not a native mount attestation.
func openRetainedFD(ctx context.Context, root *os.File) (*retainedFD, error) {
	if err := retainedFDContext(ctx); err != nil {
		return nil, err
	}
	pinned, err := retainedFDPinRoot(root)
	if err != nil {
		return nil, err
	}
	defer pinned.Close()
	rootID, err := retainedFDStat(pinned, true)
	if err != nil {
		return nil, err
	}
	fd, err := retainedFDOpen(int(pinned.Fd()))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "original-retained-file")
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	identity, err := retainedFDStat(file, false)
	if err != nil {
		return nil, err
	}
	if identity.device != rootID.device || identity.mount != rootID.mount {
		return nil, ErrInvalidFrame
	}
	if err := retainedFDContext(ctx); err != nil {
		return nil, err
	}
	keep = true
	return &retainedFD{file: file, identity: identity}, nil
}

// positiveWrite and attemptWrite execute the same one-byte WriteAt(0)+Sync
// operation on the same descriptor, with distinguishable fixed bytes. The fresh
// owner must snapshot AFTER positiveWrite and independently verify unchanged
// exact backing after retirement/attempt. This helper cannot establish retirement.
func (r *retainedFD) positiveWrite(ctx context.Context) (retainedFDResult, error) {
	return r.write(ctx, true)
}
func (r *retainedFD) attemptWrite(ctx context.Context) (retainedFDResult, error) {
	return r.write(ctx, false)
}
func (r *retainedFD) write(ctx context.Context, positive bool) (retainedFDResult, error) {
	var result retainedFDResult
	if err := retainedFDContext(ctx); err != nil {
		return result, err
	}
	if !r.mu.TryLock() {
		return result, errRetainedFDBusy
	}
	defer r.mu.Unlock()
	if r.closed || r.attempted || (positive && r.positive) || (!positive && !r.positive) {
		return result, ErrInvalidFrame
	}
	result.identity = r.identity
	// Every actual attempt is single-use, including failed/incomplete positives.
	r.attempted = true
	payload := byte(0xa5)
	if !positive {
		payload = 0x5a
	}
	result.written, result.writeErr = r.file.WriteAt([]byte{payload}, 0)
	if result.writeErr == nil && result.written != 1 {
		result.writeErr = io.ErrShortWrite
	}
	if err := retainedFDContext(ctx); err != nil {
		return result, err
	}
	// Sync is attempted even if WriteAt failed; preserve both actual outcomes.
	result.syncErr = r.file.Sync()
	if err := retainedFDContext(ctx); err != nil {
		return result, err
	}
	result.completed = true
	if positive && result.writeErr == nil && result.syncErr == nil {
		r.positive, r.attempted = true, false
	}
	return result, nil
}

// close never races a syscall to manufacture EBADF. Busy means still owned:
// callers must contain/join the operation and retry, not claim successful release.
func (r *retainedFD) close() error {
	if !r.mu.TryLock() {
		return errRetainedFDBusy
	}
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.file.Close()
}

func retainedFDStat(file *os.File, directory bool) (retainedFDIdentity, error) {
	return retainedStat(file, directory, true)
}

func retainedReadStat(file *os.File, directory bool) (retainedFDIdentity, error) {
	return retainedStat(file, directory, false)
}

func retainedFDStatBasic(file *os.File, directory bool) (unix.Stat_t, error) {
	return retainedStatBasic(file, directory, true)
}

// Readers require no write permission. Keep the writable probe's permission
// check separate; neither path relaxes regular-file, link or size constraints.
func retainedStatBasic(file *os.File, directory, writable bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return stat, err
	}
	if directory {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return stat, ErrInvalidFrame
		}
	} else if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 4096 || (writable && stat.Mode&0222 == 0) {
		return stat, ErrInvalidFrame
	}
	return stat, nil
}
