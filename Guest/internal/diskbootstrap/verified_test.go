package diskbootstrap

import (
	"bytes"
	"testing"
)

func TestZeroVerifiedResultCannotSupplyStorageRoot(t *testing.T) {
	root, _, err := (VerifiedBootResult{}).StorageRoot()
	if err == nil || root != nil {
		t.Fatal("zero value authorized root")
	}
}
func TestEvidenceRequiresWholeBatchAndHostCommit(t *testing.T) {
	for _, phase := range []string{"mount:/dev/vdb", "sync:/dev/vdb", "commit", "success"} {
		t.Run(phase, func(t *testing.T) {
			f := &fakeOperations{fail: phase}
			input := rawFrame(manifestFixture())
			if phase != "commit" {
				input = append(input, rawFrame(commitFixture())...)
			}
			x := &exchange{Reader: bytes.NewReader(input)}
			ack, err := sessionEvidence(x, helloFixture(), f)
			if phase == "success" {
				if err != nil || ack == nil || len(ack.Disks) != 2 {
					t.Fatal(ack, err)
				}
			} else if err == nil || ack != nil {
				t.Fatal("uncommitted evidence", ack, err)
			}
		})
	}
}
