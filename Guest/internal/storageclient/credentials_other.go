//go:build !linux || (!arm64 && !amd64)

package storageclient

func nativeCredentialQuery(int, *credentialHeader, []uint32) error { return ErrUnsupported }
