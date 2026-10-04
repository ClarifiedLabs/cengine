package workloadstorage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

type corpus struct {
	Valid   []string `json:"valid"`
	Invalid []string `json:"invalid"`
}

func vectors(t *testing.T) corpus {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
func fixture(t *testing.T, operation, kind string) *Frame {
	t.Helper()
	for _, raw := range vectors(t).Valid {
		f, err := Decode([]byte(raw))
		if err != nil {
			t.Fatal("invalid positive fixture", err)
		}
		if f.Operation == operation && f.Kind == kind {
			return f
		}
	}
	t.Fatal("missing fixture", operation, kind)
	return nil
}
func ptr[T any](v T) *T { return &v }
func encoded(t *testing.T, f *Frame) []byte {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func reject(t *testing.T, f *Frame) {
	t.Helper()
	if _, err := Decode(encoded(t, f)); !errors.Is(err, ErrInvalidFrame) {
		t.Fatal("accepted invalid DTO")
	}
	var b bytes.Buffer
	if err := WriteFrame(&b, f); !errors.Is(err, ErrInvalidFrame) || b.Len() != 0 {
		t.Fatal("writer accepted invalid DTO")
	}
}
func TestSharedVectors(t *testing.T) {
	c := vectors(t)
	coverage := map[string]bool{}
	for i, raw := range c.Valid {
		t.Run(fmt.Sprintf("valid-%03d", i), func(t *testing.T) {
			f, err := Decode([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			suffix := ""
			if f.Data.Code != nil {
				suffix = "-error"
			}
			coverage[f.Operation+"/"+f.Kind+suffix] = true
			var b bytes.Buffer
			if err := WriteFrame(&b, f); err != nil {
				t.Fatal(err)
			}
			got, err := ReadFrame(&b)
			if err != nil || !reflect.DeepEqual(f, got) || b.Len() != 0 {
				t.Fatal("round trip failed", err)
			}
		})
	}
	for _, k := range []string{"offer-keys", "install-certificate", "mount-phase", "prepare", "close-phase", "start", "status", "abort"} {
		for _, op := range []string{"command/", "reply/"} {
			if !coverage[op+k] {
				t.Fatal("missing coverage", op, k)
			}
		}
		if !coverage["reply/"+k+"-error"] {
			t.Fatal("missing error coverage", k)
		}
	}
	for i, raw := range c.Invalid {
		t.Run(fmt.Sprintf("invalid-%03d", i), func(t *testing.T) {
			if _, err := Decode([]byte(raw)); !errors.Is(err, ErrInvalidFrame) {
				t.Fatal("accepted invalid fixture")
			}
		})
	}
}
func TestDigestAndOpaqueWorkload(t *testing.T) {
	if SpecificationDigest([]byte("abc")) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("SHA256 mismatch")
	}
	if SpecificationDigest([]byte("{}")) == SpecificationDigest([]byte("{ }")) {
		t.Fatal("digest rewrites JSON")
	}
	f := fixture(t, "command", "prepare")
	for _, raw := range [][]byte{[]byte("{ \"ioClaim\": \"\" }\n"), {0xff, 0, '\n'}, bytes.Repeat([]byte{'x'}, MaximumWorkloadBytes)} {
		f.Data.WorkloadJSON = ptr(raw)
		f.Scope.SpecificationDigest = SpecificationDigest(raw)
		got, err := Decode(encoded(t, f))
		if err != nil || !bytes.Equal(*got.Data.WorkloadJSON, raw) {
			t.Fatal("opaque bytes changed", err)
		}
	}
	f.Data.WorkloadJSON = ptr(bytes.Repeat([]byte{'x'}, MaximumWorkloadBytes+1))
	f.Scope.SpecificationDigest = SpecificationDigest(*f.Data.WorkloadJSON)
	reject(t, f)
	f.Data.WorkloadJSON = ptr([]byte{})
	f.Scope.SpecificationDigest = SpecificationDigest(nil)
	reject(t, f)
	f.Data.WorkloadJSON = ptr([]byte("abc"))
	reject(t, f)
}
func TestTextAndBinaryBounds(t *testing.T) {
	f := fixture(t, "command", "prepare")
	for _, claim := range []string{"", strings.Repeat("é", 2048), "😀"} {
		f.Data.IOClaim = ptr(claim)
		if _, err := Decode(encoded(t, f)); err != nil {
			t.Fatal("valid claim rejected", err)
		}
	}
	for _, claim := range []string{strings.Repeat("é", 2048) + "a", "a\x00b"} {
		f.Data.IOClaim = ptr(claim)
		reject(t, f)
	}
	f.Data.IOClaim = ptr(string([]byte{0xff}))
	if err := WriteFrame(io.Discard, f); !errors.Is(err, ErrInvalidFrame) {
		t.Fatal("writer repaired invalid UTF8")
	}
	f = fixture(t, "command", "install-certificate")
	for _, n := range []int{1, 16384} {
		f.Data.CertificateDER = ptr(bytes.Repeat([]byte{0xff}, n))
		if _, err := Decode(encoded(t, f)); err != nil {
			t.Fatal("certificate boundary rejected")
		}
	}
	for _, n := range []int{0, 16385} {
		f.Data.CertificateDER = ptr(make([]byte, n))
		reject(t, f)
	}
	f = fixture(t, "reply", "offer-keys")
	for _, n := range []int{1, 4096} {
		(*f.Data.Offers)[0].CSRDER = make([]byte, n)
		if _, err := Decode(encoded(t, f)); err != nil {
			t.Fatal("CSR boundary rejected")
		}
	}
	for _, n := range []int{0, 4097} {
		(*f.Data.Offers)[0].CSRDER = make([]byte, n)
		reject(t, f)
	}
	f = fixture(t, "configure", "")
	for _, address := range []string{"127.0.0.1", "::1", "2001:db8::1", "::ffff:192.0.2.1"} {
		f.Data.Peer.DataAddress = address
		if _, err := Decode(encoded(t, f)); err != nil {
			t.Fatal("raw IP rejected", address)
		}
	}
	for _, address := range []string{"host.example", "[::1]", "fe80::1%en0", "https://127.0.0.1", "127.0.0.1:2049", "127.1", "01.2.3.4"} {
		f.Data.Peer.DataAddress = address
		reject(t, f)
	}
	f.Data.Peer.DataAddress = "::1"
	for _, n := range []int{1, 16384} {
		f.Data.Peer.TLSRootDER, f.Data.Peer.ServerDER = make([]byte, n), make([]byte, n)
		if _, err := Decode(encoded(t, f)); err != nil {
			t.Fatal("peer DER boundary rejected")
		}
	}
	for _, n := range []int{0, 16385} {
		f.Data.Peer.TLSRootDER = make([]byte, n)
		reject(t, f)
	}
}
func newID(n int) string { return fmt.Sprintf("%08x-0000-4000-8000-000000000001", n+1) }
func TestHierarchy(t *testing.T) {
	volume := newID(100)
	mounts := []MountBinding{{0, volume, "/one", "", "read-only", false}, {1, volume, "/two", "sub", "read-write", true}}
	slots := []Slot{{volume, newID(1), "prepare", "read-write"}, {volume, newID(2), "runtime", "read-only"}, {volume, newID(3), "runtime", "read-write"}}
	if ValidateConfiguration(mounts, slots) != nil || ValidateConfiguration(nil, nil) != nil {
		t.Fatal("valid hierarchy rejected")
	}
	mutations := []func([]MountBinding, []Slot) ([]MountBinding, []Slot){
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { m[1].Index = 0; return m, s },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { m[1].Index = 64; return m, s },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) {
			s[1].Attachment = s[0].Attachment
			return m, s
		},
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { s[0].Mode = "read-only"; return m, s },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { return m, s[1:] },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { return m, s[:2] },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { s[2].Mode = "read-only"; return m, s },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { s[2].Volume = newID(101); return m, s },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { m[0].Destination = "relative"; return m, s },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) {
			m[0].Destination = "/" + strings.Repeat("x", 4096)
			return m, s
		},
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) { m[0].Subpath = "\x00"; return m, s },
		func(m []MountBinding, s []Slot) ([]MountBinding, []Slot) {
			m[0].Subpath = strings.Repeat("x", 4097)
			return m, s
		},
	}
	for i, mutate := range mutations {
		m, s := mutate(append([]MountBinding{}, mounts...), append([]Slot{}, slots...))
		if ValidateConfiguration(m, s) == nil {
			t.Fatal("invalid hierarchy accepted", i)
		}
	}
	mounts[0].Destination = "/" + strings.Repeat("x", 4095)
	mounts[0].Subpath = strings.Repeat("x", 4096)
	if ValidateConfiguration(mounts, slots) != nil {
		t.Fatal("path boundary rejected")
	}
	// 64 mounts may reuse the same requested runtime slot.
	many := make([]MountBinding, 64)
	for i := range many {
		many[i] = mounts[i%2]
		many[i].Index = uint32(i)
	}
	if ValidateConfiguration(many, slots) != nil {
		t.Fatal("64 mounts rejected")
	}
	if ValidateConfiguration(append(many, mounts[0]), slots) == nil {
		t.Fatal("65 mounts accepted")
	}
	// Exactly 64 total slots, not 64 per role.
	many = nil
	slots = nil
	for i := 0; i < 32; i++ {
		v := newID(100 + i)
		many = append(many, MountBinding{uint32(i), v, "/data", "", "read-write", false})
		slots = append(slots, Slot{v, newID(i * 2), "prepare", "read-write"}, Slot{v, newID(i*2 + 1), "runtime", "read-write"})
	}
	if ValidateConfiguration(many, slots) != nil {
		t.Fatal("64 slots rejected")
	}
	many = append(many, MountBinding{32, newID(200), "/data", "", "read-write", false})
	slots = append(slots, Slot{newID(200), newID(300), "prepare", "read-write"}, Slot{newID(200), newID(301), "runtime", "read-write"})
	if ValidateConfiguration(many, slots) == nil {
		t.Fatal("66 slots accepted")
	}
}
func TestArrayAndIntegerBounds(t *testing.T) {
	f := fixture(t, "reply", "status")
	ids := make([]string, 65)
	for i := range ids {
		ids[i] = newID(i)
	}
	f.Data.MountedIDs = ptr(ids[:64])
	f.Data.TerminalIDs = ptr([]string{})
	f.Sequence = ptr(^uint64(0))
	f.Scope.ControllerEpoch = ^uint64(0)
	if _, err := Decode(encoded(t, f)); err != nil {
		t.Fatal("unsigned/array max rejected")
	}
	f.Data.MountedIDs = ptr(ids)
	reject(t, f)
	f.Data.MountedIDs = ptr(ids[:1])
	f.Data.TerminalIDs = ptr(ids[:1])
	reject(t, f)
	f.Data.MountedIDs = ptr([]string{})
	f.Data.TerminalIDs = ptr(ids[:32])
	if _, err := Decode(encoded(t, f)); err != nil {
		t.Fatal("terminal list max rejected")
	}
	f.Data.TerminalIDs = ptr(ids[:33])
	reject(t, f)
	f = fixture(t, "reply", "mount-phase")
	f.Data.AttachmentIDs = ptr([]string{ids[0], ids[0]})
	reject(t, f)
	f = fixture(t, "reply", "start")
	f.Data.PID = ptr(uint32(2147483647))
	if _, err := Decode(encoded(t, f)); err != nil {
		t.Fatal("pid max rejected")
	}
	for _, pid := range []uint32{0, 2147483648, ^uint32(0)} {
		f.Data.PID = ptr(pid)
		reject(t, f)
	}
}
func TestParserLimitsAndUnicode(t *testing.T) {
	f := fixture(t, "configured", "")
	body := encoded(t, f)
	for _, bad := range [][]byte{append(append([]byte{}, body...), 0xff), append(body, []byte(" {}")...), []byte("null")} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("malformed body accepted")
		}
	}
	for _, s := range []string{`"\ud800"`, `"\udc00"`, `"\ud800x"`, `"\ud800\u0041"`, `"\ud800\ud800"`} {
		if validUnicode([]byte(s)) {
			t.Fatal("unpaired surrogate accepted")
		}
	}
	for _, s := range []string{`"\ud83d\ude00"`, `"\\ud800"`, `"normal"`, `"\uFFFD"`} {
		if !validUnicode([]byte(s)) {
			t.Fatal("valid Unicode rejected")
		}
	}
	// The token parser bounds even structures rejected later by the DTO shape.
	for _, depth := range []int{8, 9} {
		d := json.NewDecoder(strings.NewReader(strings.Repeat("[", depth) + "1" + strings.Repeat("]", depth)))
		d.UseNumber()
		_, err := value(d, 0)
		if (err == nil) != (depth == 8) {
			t.Fatal("depth boundary wrong", depth)
		}
	}
	exactBody := append(append([]byte{}, body...), bytes.Repeat([]byte{' '}, MaximumFrameBytes-len(body))...)
	if _, err := Decode(exactBody); err != nil {
		t.Fatal("exact frame bound rejected")
	}
	if _, err := Decode(append(exactBody, ' ')); err == nil {
		t.Fatal("oversized body accepted")
	}
	var wire bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(exactBody)))
	wire.Write(header[:])
	wire.Write(exactBody)
	if _, err := ReadFrame(&wire); err != nil {
		t.Fatal("maximum framed body rejected")
	}
	for _, n := range []uint32{0, MaximumFrameBytes + 1, ^uint32(0)} {
		binary.BigEndian.PutUint32(header[:], n)
		if _, err := ReadFrame(bytes.NewReader(header[:])); err == nil {
			t.Fatal("bad length accepted")
		}
	}
	for _, raw := range [][]byte{{}, {0, 0, 0}, {0, 0, 0, 2, '{'}} {
		if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
			t.Fatal("truncation accepted")
		}
	}
}

type chunkWriter struct{ bytes.Buffer }

func (w *chunkWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}

type badWriter int

func (w badWriter) Write(b []byte) (int, error) {
	switch w {
	case -1:
		return -1, nil
	case 0:
		return 0, nil
	case 1:
		return len(b) + 1, nil
	default:
		return 0, io.ErrClosedPipe
	}
}
func TestFramingAndWriter(t *testing.T) {
	f := fixture(t, "configured", "")
	constructed := NewFrame(f.Operation, f.Binding, *f.Scope, f.Data)
	if !reflect.DeepEqual(f, constructed) {
		t.Fatal("constructor mismatch")
	}
	var w chunkWriter
	for i := 0; i < 2; i++ {
		if err := WriteFrame(&w, f); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := ReadFrame(&w); err != nil {
			t.Fatal("persistent stream framing failed", err)
		}
	}
	for _, w := range []badWriter{-1, 0, 1, 2} {
		if WriteFrame(w, f) == nil {
			t.Fatal("invalid writer accepted")
		}
	}
	if WriteFrame(io.Discard, nil) == nil {
		t.Fatal("nil frame accepted")
	}
	f.Data.Role = ptr("")
	reject(t, f)
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte(`"\ud800"`))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Decode(b)
		if err == nil {
			var out bytes.Buffer
			if err := WriteFrame(&out, got); err != nil {
				t.Fatal("decoded frame cannot encode", err)
			}
		}
	})
}

func TestHelloHasOnlyBootBinding(t *testing.T) {
	f := &Frame{Version: Version, Type: Type, Operation: "hello", Binding: BootBinding{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}}
	var b bytes.Buffer
	if err := WriteFrame(&b, f); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&b)
	if err != nil || got.Scope != nil || !reflect.DeepEqual(got, f) {
		t.Fatal("hello mismatch", err)
	}
	f.Scope = fixture(t, "configure", "").Scope
	reject(t, f)
	f.Scope = nil
	f.Sequence = ptr(uint64(1))
	reject(t, f)
	f.Sequence = nil
	f.Data.Code = ptr("internal")
	reject(t, f)
}
