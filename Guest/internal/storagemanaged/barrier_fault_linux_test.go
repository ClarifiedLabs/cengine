//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"errors"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

func TestFirstBarrierSyncFailurePersistsAfterAllResourcesClose(t *testing.T) {
	f := newFixture(t)
	s, _ := f.session(a.ReadWrite)
	metadataFD := int(s.metadataFD.Fd())
	f.expectFaults = true
	once := true
	calls := 0
	f.registry.syncOps.syncfs = func(fd int) error {
		calls++
		if _, err := stat(metadataFD); !errors.Is(err, unix.EBADF) {
			t.Error("metadata capability survived final sync", err)
		}
		if once {
			once = false
			return unix.EIO
		}
		return unix.Syncfs(fd)
	}
	receipt, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: s.binding.Store, Volume: s.binding.Volume, Attachment: s.binding.Attachment, Launch: s.binding.Launch})
	if err == nil || receipt.Revision != 0 {
		t.Fatalf("failed final sync produced receipt: %+v %v", receipt, err)
	}
	if !s.closed || len(f.registry.objects) != 0 || len(s.handles) != 0 || len(s.nodes) != 0 {
		t.Fatal("final sync failure skipped preceding closes")
	}
	if err = f.registry.Barrier(s.binding, f.volume); !errors.Is(err, ErrVolumeFault) || !errors.Is(err, unix.EIO) {
		t.Fatal("successful retry erased final-sync failure", err)
	}
	if calls != 2 {
		t.Fatal("retry failed to attempt actual syncfs", calls)
	}
}
