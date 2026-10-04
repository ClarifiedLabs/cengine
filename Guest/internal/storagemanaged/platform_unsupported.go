//go:build !linux || (!amd64 && !arm64)

package storagemanaged

import (
	"dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"os"
	"syscall"
)

func (s *Session) initialize() (w.Entry, error) {
	return w.Entry{}, syscall.ENOSYS
}
func platformSyncOperations() syncOperations {
	unsupported := func(int) error { return syscall.ENOSYS }
	return syncOperations{unsupported, unsupported, unsupported}
}
func (s *Session) prepare(*storageauthority.Guard, w.PrepareRequest) (w.ReplyBody, error) {
	return nil, syscall.ENOSYS
}
func (s *Session) execute(w.Request) (Result, error)                 { return Result{}, syscall.ENOSYS }
func (r *Registry) barrier(storageauthority.Binding, *os.File) error { return syscall.ENOSYS }

func PreflightCopyRecovery(*os.File, string, string, storageauthority.CopyIntent) error {
	return syscall.ENOSYS
}
func (s *Session) copyDataRecovery(*storageauthority.Guard, w.Request) (string, storageauthority.CopyIntent, error) {
	return "", storageauthority.CopyIntent{}, nil // portable dispatch tests retain ordinary DATA obligations
}
func (s *Session) prepareCopyRecovery(*storageauthority.Guard, w.PrepareRequest) (w.ReplyBody, []w.Event, error) {
	return nil, nil, syscall.ENOSYS
}

func platformMetadataSession() (*os.File, error) { return nil, syscall.ENOSYS }

func (s *Session) prepareRetirementCensus(*os.File) (bool, error) {
	return false, syscall.ENOSYS
}
