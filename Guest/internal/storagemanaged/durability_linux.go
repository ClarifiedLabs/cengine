//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

func platformSyncOperations() syncOperations {
	return syncOperations{unix.Fsync, unix.Fdatasync, unix.Syncfs}
}
func (s *Session) syncFile(fd int, dataOnly bool) error {
	call := s.registry.syncOps.fsync
	if dataOnly {
		call = s.registry.syncOps.fdatasync
	}
	err := call(fd)
	if err != nil {
		s.registry.latch(s.binding.Volume, err)
	}
	return err
}
func (r *Registry) syncFilesystem(volume storageauthority.ID, fd int) error {
	err := r.syncOps.syncfs(fd)
	if err != nil {
		r.latch(volume, err)
	}
	return err
}
