//go:build linux

package supervisor

import (
	"errors"
	"testing"
)

func TestHostBindShareRequiresCloseToOpen(t *testing.T) {
	wantError := errors.New("mount failed")
	calls := 0
	err := mountHostBindShare("bind-tag", "/run/cengine/binds/bind-tag", func(source, target, filesystem string, flags uintptr, data string) error {
		calls++
		if source != "bind-tag" || target != "/run/cengine/binds/bind-tag" || filesystem != "virtiofs" || flags != 0 || data != "host_close_to_open" {
			t.Fatalf("mount arguments = %q %q %q %#x %q", source, target, filesystem, flags, data)
		}
		return wantError
	})
	if calls != 1 || !errors.Is(err, wantError) {
		t.Fatalf("calls = %d, error = %v; expected original mount failure without fallback", calls, err)
	}
}
