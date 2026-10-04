package storageboot

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const lifecycleWorkerUnreapedVectorPath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-worker-unreaped-v2.json"

// Freeze the top-level failure emitted when compatibilityExitLocked cannot
// establish a reaped worker. ReplacementStatus.Code is a separate wire union.
func TestLifecycleWorkerUnreapedSharedVector(t *testing.T) {
	sequence := ^uint64(0)
	want := lifecycleFrame("reply", lifecycleTestBinding())
	want.Sequence = &sequence
	want.ServiceEpoch = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	want.WorkerUUID = "ffffffff-ffff-4fff-9fff-ffffffffffff"
	want.Code = "worker-unreaped"
	encoded, err := EncodeLifecycleFrame(&want)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_LIFECYCLE_WORKER_UNREAPED_FIXTURE") == "1" {
		if err := os.WriteFile(lifecycleWorkerUnreapedVectorPath, append(encoded[4:], '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(lifecycleWorkerUnreapedVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	if !bytes.Equal(body, encoded[4:]) {
		t.Fatal("Go-generated top-level reply changed")
	}
	frame, err := DecodeLifecycleFrame(body)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Operation != "reply" || frame.Code != "worker-unreaped" || frame.Replacement != nil || frame.OK != nil {
		t.Fatal("expected a top-level failure, not a replacement status or success")
	}
	roundtrip, err := EncodeLifecycleFrame(frame)
	if err != nil || !bytes.Equal(roundtrip, encoded) {
		t.Fatal("canonical roundtrip", err)
	}
	for _, replacement := range []string{`"code":"replacement-failed"`, `"code":"worker-gone"`, `"code":null`, `"code":"worker-unreaped","ok":true`} {
		bad := strings.Replace(string(body), `"code":"worker-unreaped"`, replacement, 1)
		if _, err := DecodeLifecycleFrame([]byte(bad)); err == nil {
			t.Fatalf("accepted malformed reply: %s", replacement)
		}
	}
}
