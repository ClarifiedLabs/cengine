package storageauthority

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func checkRootDuplicate(t *testing.T, fd *os.File, want RootIdentity) {
	t.Helper()
	got, err := identity(fd)
	must(t, err)
	if got != want {
		t.Fatalf("root identity: got %+v, want %+v", got, want)
	}
	flags, err := unix.FcntlInt(fd.Fd(), unix.F_GETFD, 0)
	must(t, err)
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("root duplicate is inheritable")
	}
}

func TestGuardRootRequiresItsOwnLiveAdmission(t *testing.T) {
	var absent *Guard
	_, err := absent.DupVolumeRoot()
	wantErr(t, err, ErrUnauthorized)
	_, err = (&Guard{}).DupVolumeRoot()
	wantErr(t, err, ErrUnauthorized)
	_, err = (&Guard{token: &guardToken{}}).DupVolumeRoot()
	wantErr(t, err, ErrUnauthorized)
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("root")
	_, p := f.runtime(v, ReadOnly)
	first, err := f.a.Admit(p, v.ID, false)
	must(t, err)
	second, err := f.a.Admit(p, v.ID, false)
	must(t, err)
	fd, err := first.DupVolumeRoot()
	must(t, err)
	checkRootDuplicate(t, fd, v.Root)
	if fd.Fd() == f.a.roots[v.ID].Fd() {
		t.Fatal("returned the authority-owned descriptor")
	}
	must(t, fd.Close())
	// Closing one caller-owned duplicate cannot invalidate the retained root.
	fd, err = first.DupVolumeRoot()
	must(t, err)
	checkRootDuplicate(t, fd, v.Root)
	must(t, fd.Close())
	copyFirst := *first
	first.Release()
	copyFirst.Release()
	// Another guard for the same A is not evidence that the first remains live.
	_, err = first.DupVolumeRoot()
	wantErr(t, err, ErrClosed)
	_, err = copyFirst.DupVolumeRoot()
	wantErr(t, err, ErrClosed)
	fd, err = second.DupVolumeRoot()
	must(t, err)
	checkRootDuplicate(t, fd, v.Root)
	must(t, fd.Close())
	wantErr(t, f.a.Close(), ErrBusy)
	second.Release()
	must(t, f.a.Close())
	_, err = second.DupVolumeRoot()
	wantErr(t, err, ErrClosed)
}

func TestGuardRootUsesRetainedDescriptorAfterPathReplacement(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("root")
	_, p := f.runtime(v, ReadWrite)
	originalPath := filepath.Join(f.path, "volumes", v.Name)
	must(t, os.WriteFile(filepath.Join(originalPath, "proof"), []byte("original root"), 0600))
	guard, err := f.a.Admit(p, v.ID, false)
	must(t, err)
	defer guard.Release()
	must(t, os.Rename(originalPath, filepath.Join(f.path, "volumes", "moved-original")))
	replacement := t.TempDir()
	must(t, os.WriteFile(filepath.Join(replacement, "proof"), []byte("wrong root"), 0600))
	must(t, os.Symlink(replacement, originalPath))
	fd, err := guard.DupVolumeRoot()
	must(t, err)
	defer fd.Close()
	checkRootDuplicate(t, fd, v.Root)
	proof, err := child(fd, "proof", unix.O_RDONLY, 0)
	must(t, err)
	defer proof.Close()
	contents, err := io.ReadAll(proof)
	must(t, err)
	if string(contents) != "original root" {
		t.Fatal("root bridge reopened the replaceable volume path")
	}
}

func TestGuardRootFinishesAcceptedWorkAndTransfersResourcesToBarrier(t *testing.T) {
	var resourcesMu sync.Mutex
	var retained *os.File
	var expected Binding
	barrierCalled := make(chan struct{})
	f := newLifecycleWorkloadFixture(t, func(binding Binding, root *os.File) error {
		resourcesMu.Lock()
		defer resourcesMu.Unlock()
		if binding != expected || retained == nil {
			return ErrInvalid
		}
		borrowed, err := identity(root)
		if err != nil {
			return err
		}
		transferred, err := identity(retained)
		if err != nil {
			return err
		}
		if borrowed != transferred {
			return ErrConflict
		}
		if err = retained.Close(); err != nil {
			return err
		}
		close(barrierCalled)
		return nil
	})
	v := f.volume("root")
	b, p := f.runtime(v, ReadWrite)
	guard, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	_, err = f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	_, err = f.a.Admit(p, v.ID, true)
	wantErr(t, err, ErrBlocked)
	// Accepted work may have waited in an external queue until after the fence.
	fd, err := guard.DupVolumeRoot()
	must(t, err)
	checkRootDuplicate(t, fd, v.Root)
	select {
	case <-barrierCalled:
		t.Fatal("barrier ran before request cleanup/transfer")
	default:
	}
	// This models server attachment ownership, transferred before guard release.
	resourcesMu.Lock()
	expected = b
	retained = fd
	resourcesMu.Unlock()
	guard.Release()
	_, err = f.a.Retire(context.Background(), f.control, req)
	must(t, err)
	await(t, barrierCalled)
	_, err = fd.Stat()
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("barrier did not close transferred resource: %v", err)
	}
	_, err = guard.DupVolumeRoot()
	wantErr(t, err, ErrClosed)
}

func TestGuardRootChecksServiceBindingAndRetainedIdentity(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("one")
	other := f.volume("two")
	_, p := f.runtime(v, ReadOnly)
	guard, err := f.a.Admit(p, v.ID, false)
	must(t, err)
	defer guard.Release()
	// These private-state perturbations exercise defensive checks; callers have
	// no API for minting or modifying a guard token or its authenticated binding.
	token := guard.token
	originalEpoch := token.epoch
	token.epoch = mustID(t)
	_, err = guard.DupVolumeRoot()
	wantErr(t, err, ErrUnauthorized)
	token.epoch = originalEpoch
	originalBinding := token.binding
	token.binding.Volume = other.ID
	_, err = guard.DupVolumeRoot()
	wantErr(t, err, ErrUnauthorized)
	token.binding = originalBinding
	source := f.a.roots[v.ID]
	f.a.roots[v.ID] = f.a.roots[other.ID]
	_, err = guard.DupVolumeRoot()
	wantErr(t, err, ErrConflict)
	f.a.roots[v.ID] = source
	fd, err := guard.DupVolumeRoot()
	must(t, err)
	checkRootDuplicate(t, fd, v.Root)
	must(t, fd.Close())
	f.a.mu.Lock()
	f.a.poison(unix.EIO)
	f.a.mu.Unlock()
	_, err = guard.DupVolumeRoot()
	wantErr(t, err, ErrBlocked)
	wantErr(t, err, unix.EIO)
}

func TestDataPrincipalBindingIsOnlyImmutableMetadata(t *testing.T) {
	var absent *DataPrincipal
	_, err := absent.Binding()
	wantErr(t, err, ErrUnauthorized)
	_, err = (&DataPrincipal{}).Binding()
	wantErr(t, err, ErrUnauthorized)
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("root")
	b, p := f.runtime(v, ReadOnly)
	snapshot, err := p.Binding()
	must(t, err)
	if snapshot != b {
		t.Fatal("principal binding differs from authenticated tuple")
	}
	snapshot.Mode = ReadWrite
	snapshot.Volume = mustID(t)
	snapshot.Key = "modified"
	got, err := p.Binding()
	must(t, err)
	if got != b {
		t.Fatal("accessor leaked mutable principal state")
	}
	_, err = f.a.Admit(p, v.ID, true)
	wantErr(t, err, ErrReadOnly)
	f.retire(b)
	got, err = p.Binding()
	must(t, err)
	if got != b {
		t.Fatal("retirement changed identity metadata")
	}
	_, err = f.a.Admit(p, v.ID, false)
	wantErr(t, err, ErrBlocked)
	must(t, f.a.Close())
	got, err = p.Binding()
	must(t, err)
	if got != b {
		t.Fatal("close changed identity metadata")
	}
	_, err = f.a.Admit(p, v.ID, false)
	wantErr(t, err, ErrClosed)
}

func TestGuardRootDupReleaseCloseRace(t *testing.T) {
	// Both legal linearizations are exercised: duplication before Release owns
	// an independent FD; duplication after Release fails. No source descriptor
	// may be closed underneath dup/fstat, even when Authority.Close also races.
	// The test only inspects/closes returned FDs; production callers must still
	// coordinate request-resource cleanup or barrier transfer before Release.
	for iteration := 0; iteration < 24; iteration++ {
		t.Run(fmt.Sprint(iteration), func(t *testing.T) {
			f := newLifecycleWorkloadFixture(t, nil)
			v := f.volume("root")
			_, p := f.runtime(v, ReadOnly)
			guard, err := f.a.Admit(p, v.ID, false)
			must(t, err)
			copyGuard := *guard
			start := make(chan struct{})
			type result struct {
				fd  *os.File
				err error
			}
			duplicates := make(chan result, 1)
			releases := make(chan struct{})
			closes := make(chan error, 1)
			go func() { <-start; fd, err := guard.DupVolumeRoot(); duplicates <- result{fd, err} }()
			go func() { <-start; copyGuard.Release(); guard.Release(); close(releases) }()
			go func() { <-start; closes <- f.a.Close() }()
			close(start)
			duplicated := <-duplicates
			await(t, releases)
			closeErr := <-closes
			if closeErr != nil {
				wantErr(t, closeErr, ErrBusy)
			}
			if duplicated.err != nil {
				wantErr(t, duplicated.err, ErrClosed)
				if duplicated.fd != nil {
					t.Fatal("failed duplication returned a descriptor")
				}
			} else {
				checkRootDuplicate(t, duplicated.fd, v.Root)
				must(t, duplicated.fd.Close())
			}
			must(t, f.a.Close())
			_, err = guard.DupVolumeRoot()
			wantErr(t, err, ErrClosed)
		})
	}
}
