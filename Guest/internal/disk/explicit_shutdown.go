package disk

import (
	"fmt"
	"os"
)

// Ext4ShutdownLease retains storage fresh initialization's original exclusive
// block descriptor and post-mount root. Copies share ownership. It is unrelated
// to the independently consumed one-shot service initialization permission.
// Keep the value alive even after initialization or Close fails: failure is
// cleanup-only, and never authorizes another format, root or repair attempt.
// All external root descriptors and workers must be gone before Close.
type Ext4ShutdownLease struct{ lease *ext4ReadOnlyLease }

type ext4BlockSyncOps interface{ syncBlock(*pinnedDevice) error }

func (l Ext4ShutdownLease) Root() (*os.File, error) {
	if l.lease == nil {
		return nil, fmt.Errorf("invalid shutdown lease")
	}
	return l.lease.dupRoot()
}

// SyncIdentity flushes through the already held block/root descriptors. Opening
// the device again would conflict with our own exclusive flock.
func (l Ext4ShutdownLease) SyncIdentity() (Ext4Identity, error) {
	if l.lease == nil {
		return Ext4Identity{}, fmt.Errorf("invalid shutdown lease")
	}
	s := l.lease
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state != leaseOwned || s.root == nil {
		return Ext4Identity{}, fmt.Errorf("shutdown lease unavailable")
	}
	target := &pinnedTarget{file: s.root, path: s.dest}
	verify := func() error {
		snap, err := s.ops.snapshot(target, true)
		if err != nil {
			return err
		}
		if err := s.verifyPromotedMount(snap); err != nil {
			return err
		}
		uuid, err := s.ops.uuid(s.device)
		if err != nil {
			return err
		}
		size, err := s.ops.capacity(s.device)
		if err != nil {
			return err
		}
		if uuid != s.identity.UUID || size != s.identity.Bytes {
			return fmt.Errorf("shutdown lease identity changed")
		}
		return nil
	}
	if err := verify(); err != nil {
		return Ext4Identity{}, err
	}
	if err := s.ops.sync(s.device, target); err != nil {
		return Ext4Identity{}, err
	}
	if err := verify(); err != nil {
		return Ext4Identity{}, err
	}
	return s.identity, nil
}

// Close uses exact owned-mount cleanup, never lazy detach. Uncertain ownership,
// sync, detach or device absence retains the block lock for host hard fallback.
func (l Ext4ShutdownLease) Close() error {
	if l.lease == nil {
		return nil
	}
	return l.lease.close()
}

func (s *ext4ReadOnlyLease) syncUnmountedBlock() error {
	if !s.mayWrite {
		return nil
	}
	ops, ok := s.ops.(ext4BlockSyncOps)
	if !ok {
		return fmt.Errorf("writable lease lacks block durability operation")
	}
	return ops.syncBlock(s.device)
}
