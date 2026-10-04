//go:build !linux || (!amd64 && !arm64)

package storageidentity

import (
	"errors"
	"syscall"
	"testing"

	"dev.cengine/guest/internal/storagewire"
)

func TestUnsupportedHostFailsClosed(t *testing.T) {
	var w Worker
	err := w.Do(storagewire.Caller{Groups: []uint32{}}, 0, func() error {
		t.Error("callback ran without Linux identity")
		return nil
	})
	if !errors.Is(err, syscall.ENOSYS) {
		t.Fatalf("error = %v", err)
	}
}

func TestLinuxKernelIdentity(t *testing.T) {
	t.Skip("requires actual Linux arm64/amd64 root; no simulated runtime on this host")
}
