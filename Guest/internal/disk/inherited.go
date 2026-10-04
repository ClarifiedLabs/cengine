package disk

import (
	"fmt"
	"sync"
)

// This interface deliberately cannot open a device for data, read its superblock,
// mount, or format. PID1 already performed the full paired disk verification.
// Stage 2 may only prove that its inherited namespace still exposes that mount.
type inheritedMountOps interface {
	pinDeviceMetadata(string) (*pinnedDevice, error)
	pinTarget(string) (*pinnedTarget, error)
	snapshot(*pinnedTarget, bool) (mountSnapshot, error)
	verifyTargetDevice(*pinnedTarget, *pinnedDevice) error
}

func verifyInheritedMountedExt4(mu *sync.Mutex, ops inheritedMountOps, device, destination string) error {
	mu.Lock()
	defer mu.Unlock()
	if !cleanAbsolute(device) || !cleanAbsolute(destination) {
		return fmt.Errorf("device and destination must be clean absolute non-root paths")
	}
	d, err := ops.pinDeviceMetadata(device)
	if err != nil {
		return fmt.Errorf("pin inherited block metadata: %w", err)
	}
	defer d.file.Close()
	target, err := ops.pinTarget(destination)
	if err != nil {
		return fmt.Errorf("pin inherited destination: %w", err)
	}
	defer target.file.Close()
	// Bracket fstat/fstatfs with exact visible mount snapshots. Each snapshot
	// independently pins the path and compares mount ID and directory identity.
	for check := 0; check < 2; check++ {
		snapshot, err := ops.snapshot(target, true)
		if err != nil {
			return err
		}
		mounted, err := destinationState(snapshot, d, destination)
		if err != nil {
			return err
		}
		if !mounted {
			return fmt.Errorf("inherited ext4 root is not mounted")
		}
		if err := ops.verifyTargetDevice(target, d); err != nil {
			return err
		}
	}
	return nil
}
