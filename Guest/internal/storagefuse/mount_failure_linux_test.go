//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"errors"
	"testing"
)

func TestNativeMountFailureDiagnosticPreflight(t *testing.T) {
	// Directly enter real native construction. This nonabsolute path is rejected
	// before DATA ownership regardless of UID; no transport/device/mount is used.
	mounted, err := nativeMount(mountConfig{Mountpoint: "SECRET-relative-path", Retire: func(error) { t.Fatal("preflight retired attachment") }})
	if mounted != nil || !errors.Is(err, ErrProfile) {
		t.Fatal("unexpected native constructor result")
	}
	if stage, category := MountFailureDiagnostic(err); stage != "preflight" || category != "profile" {
		t.Fatalf("native diagnostic = %q/%q", stage, category)
	}
}
