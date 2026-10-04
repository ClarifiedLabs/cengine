//go:build linux || darwin

package storagefuse

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

var errNativeReadbackMismatch = errors.New("native readback differs from complete regular-file model")

// Avoid os.File's runtime epoll registration on the filesystem this Go process
// serves. These remain real OPEN/GETATTR/READ/CLOSE operations, not a FUSE bypass.
// The caller's existing outer deadline still bounds a stalled native syscall.
func nativeReadback(name string, model []byte) (err error) {
	if len(model) != 4096 {
		return errNativeReadbackMismatch
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }() // exactly once, including errors
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size != int64(len(model)) {
		return errNativeReadbackMismatch
	}
	actual := make([]byte, len(model)+1)
	n, err := unix.Pread(fd, actual, 0)
	if err != nil {
		return err
	}
	if n != len(model) || !bytes.Equal(actual[:n], model) {
		return errNativeReadbackMismatch
	}
	return nil
}

func TestNativeReadbackMatchesCompleteFile(t *testing.T) {
	model := make([]byte, 4096)
	for i := range model {
		model[i] = byte(i * 37)
	}
	corrupt := bytes.Clone(model)
	corrupt[len(corrupt)-1] ^= 1 // compare the entire model, not just its prefix
	oversized := append(bytes.Clone(model), 0)
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"exact", model, nil},
		{"missing", nil, unix.ENOENT},
		{"empty", []byte{}, errNativeReadbackMismatch},
		{"truncated", model[:len(model)-1], errNativeReadbackMismatch},
		{"oversized", oversized, errNativeReadbackMismatch},
		{"corrupt", corrupt, errNativeReadbackMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "readback")
			if tc.data != nil {
				if err := os.WriteFile(name, tc.data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := nativeReadback(name, model); !errors.Is(err, tc.want) {
				t.Fatalf("readback: got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNativeReadbackRejectsDirectoryAndUnboundedModel(t *testing.T) {
	root := t.TempDir()
	if err := nativeReadback(root, make([]byte, 4096)); !errors.Is(err, errNativeReadbackMismatch) {
		t.Fatalf("directory: %v", err)
	}
	for _, size := range []int{0, 4095, 4097} {
		// Model validation must happen before even opening the missing path.
		if err := nativeReadback(filepath.Join(root, "missing"), make([]byte, size)); !errors.Is(err, errNativeReadbackMismatch) {
			t.Fatalf("model size %d: %v", size, err)
		}
	}
}
