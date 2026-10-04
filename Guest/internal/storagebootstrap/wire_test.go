package storagebootstrap

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestCanonicalPrivateWire(t *testing.T) {
	good := []byte(`{"operation":"controller-csr","request_id":18446744073709551615,"version":"lifecycle-child.v2"}`)
	var r lifecyclePrivateRequest
	if err := canonical(good, &r); err != nil || r.RequestID != ^uint64(0) {
		t.Fatal(err, r)
	}
	for _, bad := range []string{
		`{"operation":"controller-csr","request_id":1,"request_id":1,"version":"lifecycle-child.v2"}`,
		`{"request_id":1,"operation":"controller-csr","version":"lifecycle-child.v2"}`,
		`{"operation":"controller-csr","request_id":1.0,"version":"lifecycle-child.v2"}`,
		`{"key":"secret","operation":"controller-csr","request_id":1,"version":"lifecycle-child.v2"}`,
		string(good) + " ",
	} {
		if canonical([]byte(bad), &r) == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestRecursiveCanonical(t *testing.T) {
	type nested struct {
		ID     uint64 `json:"id"`
		Before string `json:"before"`
	}
	type body struct {
		Request nested `json:"request"`
		Earlier uint64 `json:"earlier"`
	}
	good := []byte(`{"earlier":18446744073709551615,"request":{"before":"x","id":1}}`)
	var value body
	if canonical(good, &value) != nil || value.Earlier != ^uint64(0) {
		t.Fatal("recursive canonical mismatch")
	}
}

func TestFramesBoundBeforeAllocation(t *testing.T) {
	for _, n := range []uint32{0, MaximumPayload + 1, ^uint32(0)} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		if _, err := ReadFrame(bytes.NewReader(h[:])); err != ErrProtocol {
			t.Fatal(err)
		}
	}
	var b bytes.Buffer
	request := lifecyclePrivateCommand("controller-csr", nil)
	check(t, WriteFrame(&b, request))
	raw, err := ReadFrame(&b)
	check(t, err)
	var decoded lifecyclePrivateRequest
	check(t, canonical(raw, &decoded))
	if decoded.Operation != request.Operation || decoded.RequestID != request.RequestID || decoded.Version != request.Version {
		t.Fatal(decoded)
	}
	if _, err = ReadFrame(bytes.NewReader([]byte{0, 0, 0, 2, 'x'})); err == nil {
		t.Fatal("truncation accepted")
	}
	if err := WriteFrame(io.Discard, bytes.Repeat([]byte("x"), MaximumPayload)); err != ErrProtocol {
		t.Fatal("oversized output accepted", err)
	}
}
