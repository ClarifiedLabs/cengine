//go:build linux

package cenginefs

import "testing"

func TestMountOptionsUseDirectKernelMount(t *testing.T) {
	options := mountOptions()
	if !options.DirectMountStrict {
		t.Fatal("cengine guest volume mounts must not depend on fusermount")
	}
}
