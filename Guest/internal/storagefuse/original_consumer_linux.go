//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"context"
	"os"

	"golang.org/x/sys/unix"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
)

// Read grant observations never open a new client or manufacture FUSE caller
// credentials. The Session must retain the original opened FD across this scope.
func (m *Mounted) BeginOriginalConsumerRead(expected a.DataHello) error {
	if m == nil || m.Err() != nil {
		return ErrProfile
	}
	select {
	case <-m.Done():
		return ErrProfile
	default:
	}
	return m.client.BeginOriginalConsumerRead(expected)
}
func (m *Mounted) EndOriginalConsumerRead(expected a.DataHello) (*c.OriginalConsumerReadGrant, error) {
	if m == nil {
		return nil, ErrProfile
	}
	return m.client.EndOriginalConsumerRead(expected)
}
func (m *Mounted) ReplayOriginalConsumerRead(ctx context.Context, expected a.DataHello, source, target *c.OriginalConsumerReadGrant) (c.OriginalConsumerRootReplay, error) {
	if m == nil || m.Err() != nil {
		return c.OriginalConsumerRootReplay{}, ErrProfile
	}
	select {
	case <-m.Done():
		return c.OriginalConsumerRootReplay{}, ErrProfile
	default:
	}
	result, err := m.client.ReplayOriginalConsumerRead(ctx, expected, source, target)
	if err != nil {
		return c.OriginalConsumerRootReplay{}, err
	}
	select {
	case <-m.Done():
		return c.OriginalConsumerRootReplay{}, ErrProfile
	default:
	}
	if m.Err() != nil {
		return c.OriginalConsumerRootReplay{}, ErrProfile
	}
	return result, nil
}

func (m *Mounted) BeginOriginalConsumerFile(expected a.DataHello, positive bool) error {
	if m == nil || m.Err() != nil {
		return ErrProfile
	}
	select {
	case <-m.Done():
		return ErrProfile
	default:
	}
	return m.client.BeginOriginalConsumerFile(expected, positive)
}
func (m *Mounted) BeginOriginalConsumerCapabilityFile(expected a.DataHello) error {
	if m == nil || m.Err() != nil {
		return ErrProfile
	}
	select {
	case <-m.Done():
		return ErrProfile
	default:
	}
	return m.client.BeginOriginalConsumerCapabilityFile(expected)
}
func (m *Mounted) EndOriginalConsumerFile(expected a.DataHello) (c.OriginalConsumerFileTrace, error) {
	if m == nil {
		return c.OriginalConsumerFileTrace{}, ErrProfile
	}
	return m.client.EndOriginalConsumerFile(expected)
}

// OriginalConsumerRoot opens through the original O_PATH pin, never Mountpoint.
// A replaced/overmounted pathname cannot redirect the writable fixture or make
// syscall ownership differ from the connection owned by OriginalConsumerAbort.
// The caller must run this potentially blocking acquisition on its syscall owner.
func (m *Mounted) OriginalConsumerRoot() (*os.File, error) {
	if m == nil || preparecompat.CurrentProfile() != preparecompat.FullProfile || m.mountedRoot == nil {
		return nil, ErrProfile
	}
	raw, err := m.mountedRoot.SyscallConn()
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
	pin := os.NewFile(uintptr(fd), "original-mount-pin")
	defer pin.Close()
	fd, err = unix.Openat(int(pin.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), "original-mounted-directory")
	var stat unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stat) != nil || stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id != m.mountID {
		_ = root.Close()
		return nil, ErrProfile
	}
	return root, nil
}

// OriginalConsumerAbort only signals the already-owned exact mount abort worker.
// It performs no kernel I/O, waits for no syscall, and makes no join assertion.
// The writable-FD owner must separately join its syscall worker and m.Done().
func (m *Mounted) OriginalConsumerAbort() {
	if m == nil || preparecompat.CurrentProfile() != preparecompat.FullProfile || m.abortSignal == nil {
		return
	}
	m.life.fail(c.ErrClosed)
	m.signalAbort()
}

// OriginalConsumerClosedRoot keeps original DATA ownership at the native mount.
// Done joins native Serve, client workers and cleanup; a terminal flag alone is
// insufficient. No client or tls.Conn is exported and no second writer exists.
func (m *Mounted) OriginalConsumerClosedRoot(ctx context.Context, expected a.DataHello) error {
	if m == nil || preparecompat.CurrentProfile() != preparecompat.FullProfile {
		return ErrProfile
	}
	select {
	case <-m.Done():
	default:
		return ErrProfile
	}
	if m.Err() == nil {
		return ErrProfile
	}
	return m.client.OriginalConsumerClosedRoot(ctx, expected)
}

// OriginalConsumerPositiveRoot uses only the client owned by this still-live
// native mount. The observer already pinned and verified the real FUSE mount.
func (m *Mounted) OriginalConsumerPositiveRoot(ctx context.Context, expected a.DataHello) error {
	if m == nil || preparecompat.CurrentProfile() != preparecompat.FullProfile || m.Err() != nil {
		return ErrProfile
	}
	select {
	case <-m.Done():
		return ErrProfile
	default:
	}
	if err := m.client.OriginalConsumerPositiveRoot(ctx, expected); err != nil {
		return err
	}
	select {
	case <-m.Done():
		return ErrProfile
	default:
	}
	if m.Err() != nil {
		return ErrProfile
	}
	return nil
}

// OriginalConsumerRootAttempt retains this mount's real client and ordinary
// serializer. Do not wait for Done or reject a post-request terminal error:
// remote denial itself may terminate the transport. A local preclose returns
// no request identity from the client and cannot stand in for an attempt.
func (m *Mounted) OriginalConsumerRootAttempt(ctx context.Context, expected a.DataHello) (c.OriginalConsumerRootRequest, error) {
	if m == nil || preparecompat.CurrentProfile() != preparecompat.FullProfile || m.Err() != nil {
		return c.OriginalConsumerRootRequest{}, ErrProfile
	}
	select {
	case <-m.Done():
		return c.OriginalConsumerRootRequest{}, ErrProfile
	default:
	}
	return m.client.OriginalConsumerRootAttempt(ctx, expected)
}
