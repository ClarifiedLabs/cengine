package storageboot

import (
	"dev.cengine/guest/internal/diskbootstrap"
	"os"
	"testing"
)

const testID = "12345678-1234-4234-8234-123456789abc"

func bindingFixture() diskbootstrap.StorageBinding {
	return diskbootstrap.StorageBinding{ShimLaunchUUID: testID, GuestBootNonce: "23456789-1234-4234-8234-123456789abc", Ext4UUID: "34567890-1234-1234-8234-123456789abc", Bytes: 32 << 20}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func openRoot(t *testing.T) *os.File {
	t.Helper()
	root, err := os.Open(t.TempDir())
	must(t, err)
	t.Cleanup(func() { root.Close() })
	return root
}
