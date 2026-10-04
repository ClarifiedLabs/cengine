//go:build !cengine_prepare_compat

package preparecompat

import "testing"

func TestOrdinaryProfileCannotConstructWitness(t *testing.T) {
	if Enabled() {
		t.Fatal("enabled")
	}
	if w, err := NewWitness(vectorArm(t)); err == nil || w != nil {
		t.Fatal("ordinary witness")
	}
	if (*Witness)(nil).PublishAndHold(Observation{}) == nil {
		t.Fatal("ordinary hold")
	}
}
