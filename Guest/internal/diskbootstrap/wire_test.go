package diskbootstrap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

const testNonce = "11111111-1111-4111-8111-111111111111"
const testLaunch = "22222222-2222-4222-8222-222222222222"
const testUUID = "33333333-3333-4333-8333-333333333333"
const testOperation = "44444444-4444-4444-8444-444444444444"
const testBytes = 32 << 20

func ptr[T any](v T) *T { return &v }
func helloFixture() Hello {
	return Hello{Version: Version, Type: "hello", Kind: "container", GuestBootNonce: testNonce, Disks: []HelloDisk{{0, "root", testBytes}, {1, "volume0", testBytes}}}
}
func manifestFixture() Manifest {
	return Manifest{Version: Version, Type: "manifest", Kind: "container", GuestBootNonce: testNonce, ShimLaunchUUID: testLaunch, Disks: []ManifestDisk{
		{Ordinal: 0, Role: "container-root", Action: "initialize-ext4", ExpectedBytes: testBytes, Ext4UUID: ptr(testUUID), OperationUUID: ptr(testOperation)},
		{Ordinal: 1, Role: "direct-volume", VolumeName: ptr("example"), Action: "mount-existing-ext4", ExpectedBytes: testBytes},
	}}
}
func commitFixture() Commit {
	return Commit{Version: Version, Type: "commit", ShimLaunchUUID: testLaunch, GuestBootNonce: testNonce}
}
func frame(data []byte) []byte {
	result := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(result, uint32(len(data)))
	copy(result[4:], data)
	return result
}
func rawFrame(v any) []byte { b, _ := json.Marshal(v); return frame(b) }
func TestWireRoundTripsClosedShapes(t *testing.T) {
	for _, message := range []any{
		helloFixture(), manifestFixture(), commitFixture(),
		Synced{Version: Version, Type: "synced", ShimLaunchUUID: testLaunch, GuestBootNonce: testNonce, Sync: "filesystem-and-block", Disks: []SyncedDisk{{0, testBytes, testUUID, ptr(testOperation)}}},
		failure("disk-operation", ptr(uint32(0))), failure("commit", nil),
	} {
		var buffer bytes.Buffer
		if err := WriteFrame(&buffer, message); err != nil {
			t.Fatal(err)
		}
		encoded := append([]byte(nil), buffer.Bytes()...)
		decoded, err := ReadFrame(&buffer)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(&buffer, decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, buffer.Bytes()) {
			t.Fatalf("roundtrip changed %T", message)
		}
	}
}
func TestWireRejectsUnknownDuplicateNullMissingAndCaseAliases(t *testing.T) {
	fixtures := []any{helloFixture(), manifestFixture(), commitFixture(),
		Synced{Version: Version, Type: "synced", ShimLaunchUUID: testLaunch, GuestBootNonce: testNonce, Sync: "filesystem-and-block", Disks: []SyncedDisk{{0, testBytes, testUUID, ptr(testOperation)}}}, failure("sync", ptr(uint32(0)))}
	for _, fixture := range fixtures {
		data, _ := json.Marshal(fixture)
		var root map[string]json.RawMessage
		_ = json.Unmarshal(data, &root)
		// Exercise every field at the top level and nested disk objects.
		objects := []map[string]json.RawMessage{root}
		if disks, ok := root["disks"]; ok {
			var rows []map[string]json.RawMessage
			_ = json.Unmarshal(disks, &rows)
			objects = append(objects, rows...)
		}
		for _, object := range objects {
			original, _ := json.Marshal(object)
			for key, val := range object {
				encodedKey, _ := json.Marshal(key)
				field := append(append(append([]byte(nil), encodedKey...), ':'), val...)
				for _, replacement := range [][]byte{
					append(append(append([]byte(nil), field...), ','), field...),
					append(append([]byte(nil), encodedKey...), []byte(":null")...),
					[]byte(`"UNKNOWN":` + string(val)),
					[]byte(`"` + strings.ToUpper(key) + `":` + string(val)),
				} {
					badObject := bytes.Replace(original, field, replacement, 1)
					// Re-marshal canonical object ordering before replacing nested text.
					canonical, _ := json.Marshal(root)
					if bytes.Equal(original, canonical) {
						canonical = badObject
					} else {
						var rows []map[string]json.RawMessage
						_ = json.Unmarshal(root["disks"], &rows)
						rowData, _ := json.Marshal(rows)
						canonical = bytes.Replace(canonical, root["disks"], rowData, 1)
						canonical = bytes.Replace(canonical, original, badObject, 1)
					}
					if _, err := ReadFrame(bytes.NewReader(frame(canonical))); err == nil {
						t.Fatalf("accepted mutation of %s: %s", key, canonical)
					}
				}
				// All non-optional fields must be present, even zero ordinal.
				if key == "operationUUID" || key == "volumeName" || key == "ext4UUID" || (key == "ordinal" && root["code"] != nil) {
					continue
				}
				copyObject := map[string]json.RawMessage{}
				for k, v := range object {
					if k != key {
						copyObject[k] = v
					}
				}
				missing, _ := json.Marshal(copyObject)
				canonical, _ := json.Marshal(root)
				if bytes.Equal(original, canonical) {
					canonical = missing
				} else {
					var rows []map[string]json.RawMessage
					_ = json.Unmarshal(root["disks"], &rows)
					rowData, _ := json.Marshal(rows)
					canonical = bytes.Replace(canonical, root["disks"], rowData, 1)
					canonical = bytes.Replace(canonical, original, missing, 1)
				}
				if _, err := ReadFrame(bytes.NewReader(frame(canonical))); err == nil {
					t.Fatalf("accepted missing %s: %s", key, canonical)
				}
			}
		}
	}
}
func TestWireRejectsMalformedEncodingAndIntegers(t *testing.T) {
	data, _ := json.Marshal(manifestFixture())
	for _, number := range []string{"-0", "-1", "1.0", "1e0", "01", "4294967296", "18446744073709551616", "null", `"0"`, "true"} {
		bad := strings.Replace(string(data), `"ordinal":0`, `"ordinal":`+number, 1)
		if _, err := ReadFrame(bytes.NewReader(frame([]byte(bad)))); err == nil {
			t.Fatal("accepted ordinal", number)
		}
	}
	for _, bad := range [][]byte{append(data, []byte(" {}")...), []byte("null"), []byte("[]"), []byte(`{"type":"unknown"}`), []byte(`{"type":"commit","type":"commit"}`), append(data, 0xff), []byte(`{"type":"commit","\u0074ype":"commit"}`)} {
		if _, err := ReadFrame(bytes.NewReader(frame(bad))); err == nil {
			t.Fatalf("accepted bad frame %q", bad)
		}
	}
	for _, n := range []uint32{0, MaximumFrameBytes + 1, 0xffffffff} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		if _, err := ReadFrame(bytes.NewReader(b[:])); err == nil {
			t.Fatal("accepted frame length", n)
		}
	}
	for i := 0; i < len(data)+4; i++ {
		if _, err := ReadFrame(bytes.NewReader(frame(data)[:i])); err == nil {
			t.Fatal("accepted truncated frame", i)
		}
	}
	padded := append(data, bytes.Repeat([]byte(" "), MaximumFrameBytes-len(data))...)
	if _, err := ReadFrame(bytes.NewReader(frame(padded))); err != nil {
		t.Fatal("maximum-sized valid frame rejected", err)
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
func TestWireShortWritesContinueOnlySameStream(t *testing.T) {
	w := &shortWriter{}
	if err := WriteFrame(w, commitFixture()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&w.Buffer); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(zeroWriter{}, commitFixture()); err != io.ErrShortWrite {
		t.Fatalf("zero write: %v", err)
	}
}

func TestWireRejectsSemanticViolations(t *testing.T) {
	hello := helloFixture()
	synced := Synced{Version: Version, Type: "synced", ShimLaunchUUID: testLaunch, GuestBootNonce: testNonce, Sync: "filesystem-and-block", Disks: []SyncedDisk{{0, testBytes, testUUID, ptr(testOperation)}}}
	commit := commitFixture()
	for _, tc := range []struct {
		message any
		field   string
		bad     any
	}{
		{hello, "version", 2}, {hello, "kind", "other"}, {hello, "guestBootNonce", "00000000-0000-0000-0000-000000000000"},
		{hello, "guestBootNonce", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}, {hello, "disks", []HelloDisk{{0, "wrong", testBytes}}},
		{hello, "disks", []HelloDisk{{1, "root", testBytes}}}, {hello, "disks", []HelloDisk{{0, "root", 0}}},
		{hello, "disks", []HelloDisk{{0, "root", 1 << 63}}}, {hello, "kind", "storage"}, {hello, "disks", []HelloDisk{}},
		{synced, "version", 2}, {synced, "sync", "block-only"}, {synced, "shimLaunchUUID", "bad"},
		{synced, "disks", []SyncedDisk{{0, testBytes, "bad", nil}}},
		{synced, "disks", []SyncedDisk{{0, testBytes, testUUID, ptr("bad")}}},
		{commit, "version", 0}, {commit, "guestBootNonce", "bad"},
		{failure("sync", nil), "code", "raw-error"}, {failure("sync", nil), "ordinal", MaximumDisks},
	} {
		b, _ := json.Marshal(tc.message)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m[tc.field] = tc.bad
		if _, err := ReadFrame(bytes.NewReader(rawFrame(m))); err == nil {
			t.Fatalf("accepted %T field %s=%v", tc.message, tc.field, tc.bad)
		}
	}
	max := helloFixture()
	max.Disks = nil
	for i := 0; i < MaximumDisks; i++ {
		max.Disks = append(max.Disks, HelloDisk{uint32(i), blockIdentifier(i), testBytes})
	}
	if _, err := ReadFrame(bytes.NewReader(rawFrame(max))); err != nil {
		t.Fatal("26 disks rejected", err)
	}
	max.Disks = append(max.Disks, HelloDisk{MaximumDisks, blockIdentifier(MaximumDisks), testBytes})
	if _, err := ReadFrame(bytes.NewReader(rawFrame(max))); err == nil {
		t.Fatal("27 disks accepted")
	}
}
