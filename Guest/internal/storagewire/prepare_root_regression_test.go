package storagewire

import "testing"

func TestPrepareEmptyIdentityPathMeansPinnedRoot(t *testing.T) {
	for _, path := range [][]byte{nil, []byte{}, []byte(".")} {
		request := PrepareRequest{Action: IdentityAt, Intent: testID, Path: path}
		raw, err := EncodePrepareIoctl(request)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodePrepareIoctl(raw)
		if err != nil || got.Action != IdentityAt || string(got.Path) != string(path) {
			t.Fatalf("root identity codec: %+v %v", got, err)
		}
	}
}
