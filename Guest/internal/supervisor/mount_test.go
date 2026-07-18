//go:build linux

package supervisor

import (
	"fmt"
	"reflect"
	"testing"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestMountPropagationFlags(t *testing.T) {
	tests := map[string]uintptr{
		"":         unix.MS_PRIVATE | unix.MS_REC,
		"private":  unix.MS_PRIVATE,
		"rprivate": unix.MS_PRIVATE | unix.MS_REC,
		"shared":   unix.MS_SHARED,
		"rshared":  unix.MS_SHARED | unix.MS_REC,
		"slave":    unix.MS_SLAVE,
		"rslave":   unix.MS_SLAVE | unix.MS_REC,
	}
	for propagation, expected := range tests {
		t.Run(propagation, func(t *testing.T) {
			flags, err := mountPropagationFlags(propagation)
			if err != nil {
				t.Fatal(err)
			}
			if flags != expected {
				t.Fatalf("flags = %#x, want %#x", flags, expected)
			}
		})
	}
	if _, err := mountPropagationFlags("invalid"); err == nil {
		t.Fatal("invalid propagation unexpectedly accepted")
	}
}

func TestBindMountAttributesApplyPropagationBeforeReadOnly(t *testing.T) {
	calls := []string{}
	mount := func(_, target, _ string, flags uintptr, _ string) error {
		calls = append(calls, fmt.Sprintf("%s:%#x", target, flags))
		return nil
	}
	err := applyBindMountAttributes("/root/data", protocol.Mount{
		Propagation: "rshared",
		ReadOnly:    true,
	}, mount)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		fmt.Sprintf("/root/data:%#x", uintptr(unix.MS_SHARED|unix.MS_REC)),
		fmt.Sprintf("/root/data:%#x", uintptr(unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY)),
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("mount calls = %#v, want %#v", calls, expected)
	}
}
