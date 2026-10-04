//go:build linux || darwin

package workloadstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"

	"golang.org/x/sys/unix"
)

const retainedReadName = "rtm103-root-object"

// This descriptor is acquired once through the original mounted root and kept
// until the same worker closes it. No write, fsync substitute, or pathname reopen.
type retainedReadFD struct {
	file     *os.File
	identity retainedFDIdentity
	read     bool
}

func openRetainedReadFD(ctx context.Context, root *os.File) (*retainedReadFD, error) {
	if err := retainedFDContext(ctx); err != nil {
		return nil, err
	}
	pin, err := retainedFDPinRoot(root)
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	rootID, err := retainedReadStat(pin, true)
	if err != nil {
		return nil, err
	}
	fd, err := retainedReadOpen(int(pin.Fd()))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "original-root-read-object")
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	identity, err := retainedReadStat(file, false)
	if err != nil {
		return nil, err
	}
	st, err := retainedStatBasic(file, false, false)
	if err != nil || st.Size != 32 || identity.device != rootID.device || identity.mount != rootID.mount {
		return nil, ErrInvalidFrame
	}
	if err := retainedFDContext(ctx); err != nil {
		return nil, err
	}
	keep = true
	return &retainedReadFD{file: file, identity: identity}, nil
}
func (r *retainedReadFD) positive(ctx context.Context) (retainedFDResult, error) {
	var out retainedFDResult
	if err := retainedFDContext(ctx); err != nil {
		return out, err
	}
	if r == nil || r.file == nil || r.read {
		return out, ErrInvalidFrame
	}
	r.read = true
	// One bounded pread. A cached kernel success cannot produce the required
	// independent original-client READ witness and is rejected by Session.
	buf := make([]byte, 4096)
	n, err := unix.Pread(int(r.file.Fd()), buf, 0)
	out.identity, out.readBytes, out.readErr = r.identity, n, err
	if err := retainedFDContext(ctx); err != nil {
		return out, err
	}
	out.completed = true
	if err == nil && n == 32 {
		sum := sha256.Sum256(buf[:n])
		out.readSHA256 = hex.EncodeToString(sum[:])
	}
	clear(buf)
	return out, nil
}
func (r *retainedReadFD) close() error {
	if r == nil || r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}
