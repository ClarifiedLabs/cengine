package storageclient

import "testing"

func TestSnapshotKindDistinguishesInvalidNoneAndPresent(t *testing.T) {
	owner := &Client{}
	for _, tc := range []struct {
		snapshot Snapshot
		want     SnapshotKind
	}{
		{Snapshot{}, SnapshotInvalid},
		{Snapshot{valid: true}, SnapshotInvalid},
		{Snapshot{owner: owner}, SnapshotInvalid},
		{Snapshot{owner: owner, valid: true}, SnapshotNone},
		{Snapshot{owner: owner, valid: true, present: true}, SnapshotPresent},
	} {
		if got := tc.snapshot.Kind(); got != tc.want {
			t.Fatalf("kind = %v, want %v", got, tc.want)
		}
	}
}
