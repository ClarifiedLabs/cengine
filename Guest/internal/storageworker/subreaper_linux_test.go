//go:build linux

package storageworker

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func withSubreaper(t *testing.T) {
	t.Helper()
	var old int32
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&old)), 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(old), 0, 0, 0); err != nil {
			t.Error(err)
		}
	})
}
