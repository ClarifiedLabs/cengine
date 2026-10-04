package diskbootstrap

import (
	"os"
	"testing"
)

func TestLifecycleFreshCapabilityRequiresLiveInitializedBoot(t *testing.T) {
	if (VerifiedBootResult{}).FreshInitialization() == nil {
		t.Fatal("zero fresh")
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mounted := VerifiedBootResult{state: &verifiedState{root: root}}
	if mounted.FreshInitialization() == nil {
		t.Fatal("mounted fresh")
	}
	initialized := VerifiedBootResult{state: &verifiedState{root: root, fresh: true}}
	copy := initialized
	if err = copy.FreshInitialization(); err != nil {
		t.Fatal(err)
	}
	if initialized.FreshInitialization() == nil {
		t.Fatal("copy replayed fresh capability")
	}
	if err = initialized.Close(); err != nil {
		t.Fatal(err)
	}
	if copy.FreshInitialization() == nil {
		t.Fatal("closed copy fresh")
	}
}
