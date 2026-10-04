// Package storageidentity provides the disabled managed-v3 ext4 service's
// caller-identity boundary. Nothing imports it into a listener or activates it.
package storageidentity

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"syscall"

	"dev.cengine/guest/internal/storagewire"
)

// Worker bounds active identity scopes to 64. Its zero value is ready for use.
// A Worker must not be copied after first use. Share one Worker across a service.
// This is an identity boundary, not authentication, admission, or path confinement:
// callers must already be authenticated and authorized by storagewire's policy.
// Open-grant/lifecycle operations must not invent a Caller to use this boundary.
type Worker struct {
	once  sync.Once
	slots chan struct{}
}

// Do copies caller before waiting, then invokes call synchronously on a disposable
// locked OS thread. UID 0 confers no additional capabilities. Umask must fit 0777.
// call must perform all identity-sensitive work synchronously: it must not start
// goroutines, exec programs, unlock the thread, or use process-wide set-ID wrappers.
// Descriptors retained by a higher layer require explicit open-grant authority.
// Do never returns or releases capacity while call is still running, including
// on cancellation elsewhere. Panics and runtime.Goexit fail closed; their values
// are not disclosed. Non-Linux and unsupported architectures fail closed.
// The caller must not mutate its input concurrently with Do's initial copy.
func (w *Worker) Do(caller storagewire.Caller, umask uint32, call func() error) error {
	if call == nil {
		return fmt.Errorf("storageidentity: missing callback: %w", syscall.EINVAL)
	}
	id, err := snapshot(caller, umask)
	if err != nil {
		return err
	}
	w.once.Do(func() { w.slots = make(chan struct{}, 64) })
	w.slots <- struct{}{}
	result := make(chan error, 1)
	go dispatch(func() {
		err := errors.New("storageidentity: worker exited without returning")
		defer func() {
			if recover() != nil {
				err = errors.New("storageidentity: worker panicked")
			}
			<-w.slots
			result <- err
		}()
		if setupErr := install(id, umask); setupErr != nil {
			err = fmt.Errorf("storageidentity: install: %w", setupErr)
			return
		}
		err = call()
	})
	return <-result
}

// dispatch reserves a disposable non-leader thread before any identity/fs change.
// Go's mexit parks m0 rather than terminating it, so mutating the thread-group
// leader would permanently change /proc/self's canonical credentials and fs state.
func dispatch(call func()) {
	// This also starts Go's clean template thread before any mutation.
	runtime.LockOSThread()
	if !isLeader() {
		call()
		return // NEVER unlock a disposable thread, including after setup failure.
	}
	locked, proceed := make(chan struct{}), make(chan struct{})
	go func() {
		runtime.LockOSThread()
		// The leader remains locked until this handshake: this must be a different
		// thread. No identity-mutated thread creates this goroutine.
		close(locked)
		<-proceed
		call()
		// NEVER unlock this disposable thread.
	}()
	<-locked
	runtime.UnlockOSThread() // Only the untouched leader is returned to Go.
	close(proceed)           // Mutation may start only after that clean unlock.
}

func snapshot(caller storagewire.Caller, umask uint32) (storagewire.Caller, error) {
	if err := (storagewire.Auth{Kind: storagewire.CallerAuth, Caller: &caller}).Validate(); err != nil {
		return storagewire.Caller{}, fmt.Errorf("storageidentity: invalid caller: %w", syscall.EINVAL)
	}
	if caller.FSUID == ^uint32(0) || caller.FSGID == ^uint32(0) || umask & ^uint32(0777) != 0 {
		return storagewire.Caller{}, fmt.Errorf("storageidentity: reserved ID or umask: %w", syscall.EINVAL)
	}
	caller.Groups = slices.Clone(caller.Groups)
	for _, gid := range caller.Groups {
		if gid == ^uint32(0) {
			return storagewire.Caller{}, fmt.Errorf("storageidentity: reserved group: %w", syscall.EINVAL)
		}
	}
	// setgroups sorts but does not deduplicate. Compare the exact multiset.
	slices.Sort(caller.Groups)
	return caller, nil
}
