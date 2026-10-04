package diskbootstrap

import (
	"crypto/ed25519"
	"errors"
	"os"
	"sync"

	"dev.cengine/guest/internal/disk"
	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

// StorageBinding is detached public evidence, not a constructor or capability.
type StorageBinding struct {
	ShimLaunchUUID string `json:"shimLaunchUUID"`
	GuestBootNonce string `json:"guestBootNonce"`
	Ext4UUID       string `json:"ext4UUID"`
	Bytes          uint64 `json:"bytes"`
}

// ContainerBinding is public evidence detached from the committed container boot.
// Only VerifiedBootResult.ContainerBinding can supply it; it confers no storage root.
type ContainerBinding struct {
	ShimLaunchUUID string
	GuestBootNonce string
}

// VerifiedBootResult has no exported constructor or fields. A zero value fails
// closed. Copies share the held descriptor and its close state.
type VerifiedBootResult struct{ state *verifiedState }
type verifiedState struct {
	mu              sync.Mutex
	root            *os.File
	probe           *disk.Ext4ReadOnlyLease
	binding         StorageBinding
	container       *ContainerBinding
	closed          bool
	fresh           bool
	resumeAttempted bool
}

func (r VerifiedBootResult) ContainerBinding() (ContainerBinding, error) {
	if r.state == nil {
		return ContainerBinding{}, failure("commit", nil)
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.closed || r.state.container == nil || r.state.root != nil {
		return ContainerBinding{}, failure("commit", nil)
	}
	return *r.state.container, nil
}

func (r VerifiedBootResult) StorageRoot() (*os.File, StorageBinding, error) {
	if r.state == nil {
		return nil, StorageBinding{}, failure("commit", nil)
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.closed || r.state.container != nil || r.state.root == nil || r.state.probe != nil {
		return nil, StorageBinding{}, failure("commit", nil)
	}
	fd, err := unix.Openat(int(r.state.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, StorageBinding{}, failure("disk-mismatch", nil)
	}
	return os.NewFile(uintptr(fd), "verified-storage-root"), r.state.binding, nil
}

// LifecycleRoot supplies the held journaled root to PID1's lifecycle launcher.
// Before promotion a probe supplies only binding/purpose, with a nil root: no
// descriptor may escape and keep the RO mount busy across the authorized detach.
// After promotion the root is duplicated from the verified NEW mounted root.
// The boolean freezes boot purpose; it is not a promotion capability.
func (r VerifiedBootResult) LifecycleRoot() (*os.File, StorageBinding, bool, error) {
	if r.state == nil {
		return nil, StorageBinding{}, false, failure("commit", nil)
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.closed || r.state.container != nil {
		return nil, StorageBinding{}, false, failure("commit", nil)
	}
	if r.state.probe != nil {
		if r.state.resumeAttempted && !r.state.probe.IsPromoted() {
			return nil, StorageBinding{}, false, failure("commit", nil)
		}
		if !r.state.probe.IsPromoted() {
			return nil, r.state.binding, true, nil
		}
		root, err := r.state.probe.Root()
		return root, r.state.binding, true, err
	}
	if r.state.root == nil {
		return nil, StorageBinding{}, false, failure("commit", nil)
	}
	fd, err := unix.Openat(int(r.state.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, StorageBinding{}, false, failure("disk-mismatch", nil)
	}
	return os.NewFile(uintptr(fd), "lifecycle-storage-root"), r.state.binding, false, nil
}

// PromoteResume consumes the actual read-only boot lease, never an ordinary
// mount result. ROOT authentication and the closed empty/exact-genesis census
// run inside the lease's read-only boundary before its first write-side syscall.
// The exclusively locked device carries admission across RO unmount and a normal
// journaled RW mount; callers receive only the NEW root after success.
func (r VerifiedBootResult) PromoteResume(rootKey ed25519.PublicKey, signed a.SignedLifecycleResumeOpen) error {
	if r.state == nil {
		return failure("commit", nil)
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.closed || r.state.container != nil || r.state.root != nil || r.state.probe == nil || r.state.resumeAttempted {
		return failure("commit", nil)
	}
	r.state.resumeAttempted = true // even rejected authorization is terminal
	rootKey = append(ed25519.PublicKey(nil), rootKey...)
	signed.Signature = append([]byte(nil), signed.Signature...)
	signed.Request.Takeover.Signature = append([]byte(nil), signed.Request.Takeover.Signature...)
	b, l := r.state.binding, signed.Request.Launch
	if string(l.ShimLaunchUUID) != b.ShimLaunchUUID || l.Ext4UUID != b.Ext4UUID || l.Bytes != b.Bytes {
		return failure("disk-mismatch", nil)
	}
	return r.state.probe.Promote(func(root *os.File) error {
		return a.AdmitLifecycleResumeReadOnly(a.Config{Root: root, DeviceID: b.Ext4UUID, BootstrapKey: rootKey,
			// Admission must never call a write-side durability barrier.
			Barrier: func(a.Binding, *os.File) error { return a.ErrInvalid },
		}, signed)
	})
}

func (r VerifiedBootResult) Close() error {
	if r.state == nil {
		return nil
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	r.state.closed = true
	var err error
	if r.state.root != nil {
		err = r.state.root.Close()
		r.state.root = nil
		if err != nil {
			return err
		}
	}
	if r.state.probe != nil {
		err = errors.Join(err, r.state.probe.Close())
	}
	return err
}

// FreshInitialization consumes this live boot's initialized+synced+committed
// storage permission before mutation. Copies share consumption and close state.
func (r VerifiedBootResult) FreshInitialization() error {
	if r.state == nil {
		return failure("commit", nil)
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.closed || !r.state.fresh || r.state.root == nil || r.state.container != nil || r.state.probe != nil {
		return failure("commit", nil)
	}
	r.state.fresh = false
	return nil
}
