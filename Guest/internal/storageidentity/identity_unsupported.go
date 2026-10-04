//go:build !linux || (!amd64 && !arm64)

package storageidentity

import (
	"fmt"
	"syscall"

	"dev.cengine/guest/internal/storagewire"
)

func isLeader() bool { return false }

func install(storagewire.Caller, uint32) error {
	return fmt.Errorf("Linux arm64/amd64 required: %w", syscall.ENOSYS)
}
