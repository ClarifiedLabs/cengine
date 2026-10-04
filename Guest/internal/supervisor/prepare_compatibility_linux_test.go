//go:build linux

package supervisor

import (
	"dev.cengine/guest/internal/preparecompat"
	"testing"
)

// No fake authority or copy callback: a selected no-publication exit must fail
// before touching a filesystem or issuing FinishCopy. A zero witness suffices
// for this rejection-only predicate and cannot authorize live publication.
func TestPrepareCompatibilityRejectsSkippedPublication(t *testing.T) {
	copy := &managedCopy{compatibility: &preparecompat.Witness{}}
	if copy.finishWithoutPublication() == nil {
		t.Fatal("skipped publication accepted")
	}
}
func TestPrepareCompatibilityCannotInstallOutsidePID1(t *testing.T) {
	s := new(Supervisor)
	if s.InstallPrepareCompatibility(nil) == nil {
		t.Fatal("nil witness")
	}
	if s.InstallPrepareCompatibility(&preparecompat.Witness{}) == nil {
		t.Fatal("unowned witness")
	}
}
