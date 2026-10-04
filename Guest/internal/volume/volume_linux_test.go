//go:build linux

package volume

import "testing"

func TestEnsureRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b"} {
		if _, err := Ensure(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
