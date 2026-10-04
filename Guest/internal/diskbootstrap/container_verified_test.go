package diskbootstrap

import "testing"

func TestContainerProofIsDistinctAndRevokedAcrossCopies(t *testing.T) {
	if _, err := (VerifiedBootResult{}).ContainerBinding(); err == nil {
		t.Fatal("zero authorized container")
	}
	storage := VerifiedBootResult{state: &verifiedState{binding: StorageBinding{}}}
	if _, err := storage.ContainerBinding(); err == nil {
		t.Fatal("storage authorized container")
	}
	binding := ContainerBinding{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	proof := VerifiedBootResult{state: &verifiedState{container: &binding}}
	copy := proof
	if got, err := proof.ContainerBinding(); err != nil || got != binding {
		t.Fatal("container evidence unavailable", err)
	}
	if root, _, err := proof.StorageRoot(); err == nil || root != nil {
		t.Fatal("container authorized storage root")
	}
	if err := proof.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := copy.ContainerBinding(); err == nil {
		t.Fatal("closed copy authorized container")
	}
}
