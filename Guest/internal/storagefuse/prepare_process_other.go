//go:build !linux || (!arm64 && !amd64)

package storagefuse

func pinPrepareProcess(uint32) (prepareProcess, error) { return nil, ErrProfile }
