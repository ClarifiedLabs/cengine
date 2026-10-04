package storagemanaged

import (
	"crypto/sha256"
	"io"
	"syscall"

	a "dev.cengine/guest/internal/storageauthority"
)

// Hash the former 64MiB manifest bound with one fixed 128KiB transfer buffer.
// Neither DATA frames nor authority state contains the manifest payload.
func digestCopyManifest(reader io.Reader) ([32]byte, uint64, error) {
	hash := sha256.New()
	size, err := io.CopyBuffer(hash, io.LimitReader(reader, a.MaxCopyManifestBytes+1), make([]byte, 128<<10))
	if err != nil {
		return [32]byte{}, 0, err
	}
	if size == 0 || size > a.MaxCopyManifestBytes {
		return [32]byte{}, 0, syscall.EFBIG
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, uint64(size), nil
}
