//go:build linux || darwin

package workloadstorage

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"syscall"
)

// retainedFDOwner owns one syscall worker for the entire open-description lifetime.
// A failed wait never discards that worker or closes a descriptor concurrently.
// abort must only signal the already-owned mount's abort worker (no syscalls).
// mountDone is that mount's actual Serve/client/cleanup join, not a terminal flag.
// This owner is a prerequisite, NOT authority-denial or unchanged-backing proof.
type retainedFDOwner struct {
	mu           sync.Mutex
	requests     chan retainedFDCommand
	done         chan struct{}
	stop         chan struct{}
	abort        func()
	mountDone    <-chan struct{}
	failed       bool
	released     bool
	terminal     error
	closeFailure error // raw close outcome, for finite diagnostics only
}

type retainedFDCommand struct {
	ctx       context.Context
	operation string
	reply     chan retainedFDOutcome
}
type retainedFDOutcome struct {
	result retainedFDResult
	err    error
}

// openRoot must acquire the exact original mount, not a caller-supplied path.
// Ownership is returned before any potentially blocking open/stat/fsync occurs.
func newRetainedFDOwner(openRoot func() (*os.File, error), abort func(), mountDone <-chan struct{}) *retainedFDOwner {
	if openRoot == nil || abort == nil || mountDone == nil {
		return nil
	}
	o := &retainedFDOwner{requests: make(chan retainedFDCommand), done: make(chan struct{}), stop: make(chan struct{}), abort: abort, mountDone: mountDone}
	go o.run(openRoot)
	return o
}

func (o *retainedFDOwner) run(openRoot func() (*os.File, error)) {
	var file *retainedFD
	var readFile *retainedReadFD
	var root *os.File // retain through observation: FUSE RELEASEDIR is asynchronous
	closeAfterMountJoin := false
	defer close(o.done)
	defer func() {
		if readFile != nil {
			err := readFile.close()
			o.mu.Lock()
			o.terminal = errors.Join(o.terminal, retainedCloseResult(err, closeAfterMountJoin, runtime.GOOS == "linux"))
			o.closeFailure = err
			o.mu.Unlock()
		}
		if file != nil {
			err := file.close()
			o.mu.Lock()
			o.terminal = errors.Join(o.terminal, retainedCloseResult(err, closeAfterMountJoin, runtime.GOOS == "linux"))
			o.closeFailure = err
			o.mu.Unlock()
		}
		if root != nil {
			err := root.Close()
			o.mu.Lock()
			o.terminal = errors.Join(o.terminal, retainedCloseResult(err, closeAfterMountJoin, runtime.GOOS == "linux"))
			if o.closeFailure == nil {
				o.closeFailure = err
			}
			o.mu.Unlock()
		}
	}()
	for {
		var command retainedFDCommand
		select {
		case command = <-o.requests:
		case <-o.stop:
			return
		}
		var out retainedFDOutcome
		if err := command.ctx.Err(); err != nil {
			o.fail(err)
			command.reply <- retainedFDOutcome{err: err}
			return
		}
		switch command.operation {
		case "read-open":
			if file != nil || readFile != nil {
				out.err = ErrInvalidFrame
				break
			}
			root, out.err = openRoot()
			if root != nil {
				if out.err == nil {
					readFile, out.err = openRetainedReadFD(command.ctx, root)
					if readFile != nil {
						out.result.identity = readFile.identity
					}
				}
			} else if out.err == nil {
				out.err = ErrInvalidFrame
			}
		case "read":
			if readFile == nil {
				out.err = ErrInvalidFrame
			} else {
				out.result, out.err = readFile.positive(command.ctx)
			}
		case "open":
			if file != nil || readFile != nil {
				out.err = ErrInvalidFrame
				break
			}
			root, out.err = openRoot()
			if root != nil {
				if out.err == nil {
					file, out.err = openRetainedFD(command.ctx, root)
					if file != nil {
						out.result.identity = file.identity
					}
				}
			} else if out.err == nil {
				out.err = ErrInvalidFrame
			}
		case "positive":
			if file == nil {
				out.err = ErrInvalidFrame
			} else {
				out.result, out.err = file.positiveWrite(command.ctx)
			}
		case "attempt":
			if file == nil {
				out.err = ErrInvalidFrame
			} else {
				out.result, out.err = file.attemptWrite(command.ctx)
			}
		case "close":
			// Closure runs on the same worker after every preceding syscall returned.
			// Only a mount joined BEFORE close can explain disconnected FLUSH.
			// A close failure's own abort must never supply that premise.
			select {
			case <-o.mountDone:
				closeAfterMountJoin = true
			default:
			}
		default:
			out.err = ErrInvalidFrame
		}
		o.mu.Lock()
		stop := o.failed || command.ctx.Err() != nil || out.err != nil || command.operation == "close"
		o.mu.Unlock()
		if stop {
			o.mu.Lock()
			o.terminal = errors.Join(o.terminal, out.err)
			o.mu.Unlock()
			command.reply <- out
			return
		}
		command.reply <- out
	}
}

// Linux close(2) releases the descriptor before returning the FUSE FLUSH error.
// After this exact mount has already joined, ENOTCONN is a data-path outcome,
// not an unclosed FD. Preserve it in closeFailure; never retry close, accept
// EBADF, suppress another error, or use this rule for an unjoined mount/worker.
func retainedCloseResult(err error, mountJoined, linux bool) error {
	var errno syscall.Errno
	switch value := err.(type) {
	case syscall.Errno:
		errno = value
	case *os.PathError:
		if value != nil && value.Op == "close" {
			errno, _ = value.Err.(syscall.Errno)
		}
	}
	if linux && mountJoined && errno == syscall.ENOTCONN {
		return nil
	}
	return err
}

// execute is single-caller by construction in the native observation owner.
// TryLock on a separate operation gate is unnecessary: an unbuffered dispatch
// permits only one operation, and concurrent use fails rather than queues.
func (o *retainedFDOwner) execute(ctx context.Context, operation string) (retainedFDResult, error) {
	if err := retainedFDContext(ctx); err != nil {
		return retainedFDResult{}, err
	}
	if operation != "read-open" && operation != "read" && operation != "open" && operation != "positive" && operation != "attempt" && operation != "close" {
		return retainedFDResult{}, ErrInvalidFrame
	}
	o.mu.Lock()
	if o.failed || o.released {
		o.mu.Unlock()
		return retainedFDResult{}, ErrInvalidFrame
	}
	// released also seals the dispatch while it is in flight.
	o.released = true
	o.mu.Unlock()
	command := retainedFDCommand{ctx: ctx, operation: operation, reply: make(chan retainedFDOutcome, 1)}
	select {
	case o.requests <- command:
	case <-ctx.Done():
		o.fail(ctx.Err())
		return retainedFDResult{}, ctx.Err()
	case <-o.done:
		return retainedFDResult{}, ErrInvalidFrame
	}
	select {
	case out := <-command.reply:
		if ctx.Err() != nil {
			o.fail(ctx.Err())
			return retainedFDResult{}, ctx.Err()
		}
		if out.err != nil {
			o.fail(out.err)
			return retainedFDResult{}, out.err
		}
		o.mu.Lock()
		if operation != "close" {
			o.released = false
		}
		o.mu.Unlock()
		if operation == "close" {
			select {
			case <-o.done:
			case <-ctx.Done():
				o.fail(ctx.Err())
				return retainedFDResult{}, ctx.Err()
			}
			o.mu.Lock()
			err := o.terminal
			o.mu.Unlock()
			if err != nil {
				o.fail(err)
				return retainedFDResult{}, err
			}
		}
		return out.result, nil
	case <-ctx.Done():
		o.fail(ctx.Err())
		return retainedFDResult{}, ctx.Err()
	}
}

func (o *retainedFDOwner) fail(cause error) {
	if cause == nil {
		cause = ErrInvalidFrame
	}
	o.mu.Lock()
	o.terminal = errors.Join(o.terminal, cause)
	first := !o.failed
	o.failed = true
	o.mu.Unlock()
	if first {
		close(o.stop)
		o.abort()
	}
}

// joinFailure never fabricates release. Both the syscall worker (including FD
// close) and exact native mount must have joined. On error the caller must keep
// this owner and contain its original guest generation; no retry/new worker.
func (o *retainedFDOwner) joinFailure(ctx context.Context) error {
	if err := retainedFDContext(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	failed := o.failed
	o.mu.Unlock()
	if !failed {
		return ErrInvalidFrame
	}
	select {
	case <-o.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-o.mountDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.terminal
}
