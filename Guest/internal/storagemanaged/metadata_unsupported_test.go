//go:build !linux || (!amd64 && !arm64)

package storagemanaged

import (
	"errors"
	"syscall"
	"testing"
)

func TestUnsupportedMetadataSessionFailsClosed(t *testing.T) {
	fd, err := platformMetadataSession()
	if fd != nil || !errors.Is(err, syscall.ENOSYS) {
		t.Fatal("unsupported platform provided metadata authority", fd, err)
	}
}
