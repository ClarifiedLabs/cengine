package storagewire

import (
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestPrepareCleanupCodecPreservesDurableRootTimes(t *testing.T) {
	value := prepareFixture()
	value.Intent.Phase = a.CopyCleaning
	value.Intent.InitialCaptured = true
	value.Intent.Initial = a.CopyCleanupV1{UID: 123, GID: 456, Mode: 0751, ATimeSeconds: -9, ATimeNanos: 123, MTimeSeconds: 987, MTimeNanos: 999999999}
	value.Intent.Cleanup = value.Intent.Initial
	value.Intent.Cleanup.Manifest = value.Identity
	value.Intent.Cleanup.Manifest.FileType = 0100000
	value.Intent.Cleanup.Manifest.Inode = 24
	binary.LittleEndian.PutUint32(value.Intent.Cleanup.Manifest.Handle[:4], 24)
	value.Intent.Cleanup.Staging = value.Identity
	value.Intent.Cleanup.Staging.Inode = 25
	binary.LittleEndian.PutUint32(value.Intent.Cleanup.Staging.Handle[:4], 25)
	raw, err := EncodePrepareIoctlReply(value)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePrepareIoctlReply(raw)
	if err != nil || !reflect.DeepEqual(got, value) {
		t.Fatalf("cleanup codec lost data: %+v %v", got, err)
	}
	request := PrepareRequest{Action: StartCleanup, Intent: testID}
	if _, err := EncodePrepareIoctl(request); err != nil {
		t.Fatal(err)
	}
	value.Intent.Cleanup.ATimeNanos = 1e9
	if _, err := EncodePrepareIoctlReply(value); err == nil {
		t.Fatal("accepted invalid root timestamp")
	}
}
