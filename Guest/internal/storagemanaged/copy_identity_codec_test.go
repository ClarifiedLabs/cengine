package storagemanaged

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareExt4IdentityPreservesFullHandle(t *testing.T) {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint32(raw, 91)
	binary.LittleEndian.PutUint32(raw[4:], 0x12345678)
	identity, err := decodeExt4Identity(91, unix.S_IFLNK|0777, 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Inode != 91 || identity.Generation != 0x12345678 || identity.FileType != unix.S_IFLNK || identity.HandleType != 1 || identity.HandleSize != 8 || string(identity.Handle[:]) != string(raw) {
		t.Fatalf("identity lost durable data: %+v", identity)
	}
	binary.LittleEndian.PutUint32(raw[4:], 0x12345679)
	replacement, err := decodeExt4Identity(91, unix.S_IFLNK|0777, 1, raw)
	if err != nil || identity == replacement {
		t.Fatalf("inode reuse generation not distinguished: %+v %v", replacement, err)
	}
	if identity.Generation != 0x12345678 {
		t.Fatal("retained mutable handle storage")
	}
}

func TestPrepareExt4IdentityRejectsUncertainty(t *testing.T) {
	for _, tc := range []struct {
		inode uint64
		mode  uint32
		kind  int32
		raw   []byte
	}{
		{7, unix.S_IFREG, 2, []byte{7, 0, 0, 0, 1, 0, 0, 0}},
		{7, unix.S_IFREG, 1, []byte{7, 0, 0, 0}},
		{8, unix.S_IFREG, 1, []byte{7, 0, 0, 0, 1, 0, 0, 0}},
		{0, unix.S_IFREG, 1, make([]byte, 8)},
		{1<<32 | 7, unix.S_IFREG, 1, []byte{7, 0, 0, 0, 1, 0, 0, 0}},
		{7, 0, 1, []byte{7, 0, 0, 0, 1, 0, 0, 0}},
	} {
		if _, err := decodeExt4Identity(tc.inode, tc.mode, tc.kind, tc.raw); err == nil {
			t.Fatalf("accepted uncertain identity: %+v", tc)
		}
	}
}

func TestPrepareUUIDRequiresRealCanonicalShape(t *testing.T) {
	for _, invalid := range []string{"", "native-issued-prepare-preflight", "00112233445566778899aabbccddeeff", "00000000-0000-0000-0000-000000000000", "00112233-4455-6677-8899-aabbccddeefg"} {
		if _, err := parseCopyDeviceUUID(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	got, err := parseCopyDeviceUUID("00112233-4455-6677-8899-aabbccddeeff")
	if err != nil || got[0] != 0 || got[15] != 255 {
		t.Fatalf("uuid: %x %v", got, err)
	}
}

func TestPrepareIdentityPathConfinement(t *testing.T) {
	for _, invalid := range []string{"", "/absolute", "a/../b", "a/./b", "a//b", "a/", "a\x00b"} {
		if copyRelativePath(invalid) {
			t.Fatalf("accepted %q", invalid)
		}
	}
	for _, valid := range []string{"a", ".cengine-copyup-transaction/staging/a", "a/b"} {
		if !copyRelativePath(valid) {
			t.Fatalf("rejected %q", valid)
		}
	}
}
