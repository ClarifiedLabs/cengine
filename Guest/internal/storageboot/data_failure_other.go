//go:build !linux

package storageboot

// Guest console emission is Linux-only; portable component tests use a local sink.
func writeDataFailureConsole([]byte) {}
