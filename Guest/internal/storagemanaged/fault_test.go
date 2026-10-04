package storagemanaged

import (
	"errors"
	"sync"
	"syscall"
	"testing"

	"dev.cengine/guest/internal/storageauthority"
)

func TestVolumeFaultEvidenceSurvivesSuccessfulRetry(t *testing.T) {
	r, err := NewRegistry(new(sync.Mutex))
	if err != nil {
		t.Fatal(err)
	}
	volume := storageauthority.ID("volume-a")
	first := r.latch(volume, syscall.EIO)
	if !errors.Is(first, ErrVolumeFault) || !errors.Is(first, syscall.EIO) {
		t.Fatal(first)
	}
	for _, later := range []error{nil, syscall.ENOSPC, nil} {
		if got := r.latch(volume, later); got != first {
			t.Fatal("first failure replaced", got)
		}
	}
	if got := r.latch(storageauthority.ID("volume-b"), nil); got != nil {
		t.Fatal("unrelated volume fenced", got)
	}
}
