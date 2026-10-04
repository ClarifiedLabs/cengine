package storageboot

import (
	a "dev.cengine/guest/internal/storageauthority"
	"net"
)

// The root identity is supplied by PID1 from its held verified descriptor.
type workerRootIdentity struct {
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	MountID uint64 `json:"mountID"`
}

func validManagementAddress(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() == address
}

// Serialize the bounded handoff send with session closure, not disk barriers.
type workerStartGate func(func() error) error

func newWorkerUUID() (string, error) {
	value, err := a.NewID()
	return string(value), err
}
