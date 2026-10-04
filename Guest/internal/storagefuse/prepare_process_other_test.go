//go:build !linux || (!arm64 && !amd64)

package storagefuse

import "testing"

func TestPrepareProcessUnsupportedHostHasNoFallback(t *testing.T) {
	if owner, err := pinPrepareProcess(1); owner != nil || err == nil {
		t.Fatal("unsupported host supplied process authority", owner, err)
	}
}
