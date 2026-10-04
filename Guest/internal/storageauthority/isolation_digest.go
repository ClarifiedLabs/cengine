//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

// CompatibilityStateDigest exposes no private ledger values or authority. Only
// the private full-profile Service owner uses it around a joined isolation probe.
func (a *Authority) CompatibilityStateDigest() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.fault != nil {
		return "", ErrBlocked
	}
	data, err := json.Marshal(a.s)
	if err != nil {
		return "", err
	}
	// Independently reread the held journal, with its existing bounded, canonical
	// decoder. Hash no private values until disk and memory exactly agree.
	disk, err := a.j.load()
	if err != nil {
		return "", err
	}
	persisted, err := json.Marshal(disk)
	if err != nil || !bytes.Equal(data, persisted) {
		return "", ErrConflict
	}
	// Independent bounded census includes hidden operation and marker side-files.
	fd, err := unix.Openat(int(a.j.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	dir := os.NewFile(uintptr(fd), "isolation-registry")
	defer dir.Close()
	names, err := dir.Readdirnames(65)
	if err != nil && err != io.EOF {
		return "", err
	}
	if len(names) > 64 {
		return "", ErrLimit
	}
	census := make(map[string]string, len(names))
	remaining := a.j.maxBytes + 65536
	for _, name := range names {
		f, err := child(a.j.dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return "", err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			f.Close()
			return "", ErrInvalid
		}
		if info.Size() > remaining {
			f.Close()
			return "", ErrLimit
		}
		content, err := io.ReadAll(io.LimitReader(f, remaining+1))
		closeErr := f.Close()
		if err != nil || closeErr != nil || int64(len(content)) > remaining {
			return "", ErrInvalid
		}
		// The bytes actually included in the census must themselves equal
		// live state, not merely an earlier reopen of the same pathname.
		if name == stateName && !bytes.Equal(content, data) {
			return "", ErrConflict
		}
		remaining -= int64(len(content))
		hash := sha256.Sum256(content)
		census[name] = hex.EncodeToString(hash[:])
	}
	if _, ok := census[stateName]; !ok {
		return "", ErrMissing
	}
	if _, ok := census["lock"]; !ok {
		return "", ErrMissing
	}
	encoded, err := json.Marshal(census)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(append([]byte("cengine-isolation-registry-v1\n"), data...), encoded...))
	return hex.EncodeToString(sum[:]), nil
}
