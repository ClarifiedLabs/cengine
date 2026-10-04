package storagewire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/storageauthority"
)

func callerAuth() Auth {
	return Auth{Kind: CallerAuth, Caller: &Caller{FSUID: 1000, FSGID: 1001, Groups: []uint32{7, 8}, EffectiveCaps: 0}}
}
func request(body RequestBody) Request { return Request{Sequence: 1, Auth: callerAuth(), Body: body} }
func goodAttr() Attr {
	return Attr{Ino: 123, Mode: 0100644, Nlink: 0, Size: 17, Blocks: 8, BlockSize: 4096, ATime: Timestamp{-10, 999999999}}
}
func goodEntry() Entry {
	return Entry{Node: 2, Generation: 3, Object: ObjectID{1, 2, 3}, Attr: goodAttr()}
}

const testID storageauthority.ID = "11111111-1111-4111-8111-111111111111"

func TestGoldenBinaryLookup(t *testing.T) {
	r := request(LookupRequest{Parent: 1, Name: []byte{0xff, 0x80, 'a'}})
	want := `{"sequence":1,"auth":{"kind":1,"caller":{"fsuid":1000,"fsgid":1001,"groups":[7,8],"effective_caps":0}},"op":"lookup","body":{"parent":1,"name":"/4Bh"}}`
	got, err := Marshal(&r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("golden mismatch\n%s\n%s", got, want)
	}
	var framed bytes.Buffer
	if err := WriteFrame(&framed, &r); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(framed.Bytes()[:4]) != uint32(len(want)) || string(framed.Bytes()[4:]) != want {
		t.Fatal("frame golden")
	}
	var out Request
	if err := ReadFrame(&framed, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, out) {
		t.Fatalf("lossy roundtrip: %#v", out)
	}
}
func TestEmptyXAttrProbeAndERANGE(t *testing.T) {
	cases := []struct {
		capacity, size uint32
		value          []byte
		errno          uint32
		body           ReplyBody
		valid          bool
	}{
		{1, 0, []byte{}, 0, nil, true},
		{0, 17, []byte{}, 0, nil, true},
		{0, 2, []byte{0, 255}, 0, nil, false},
		{2, 2, []byte{0, 255}, 0, nil, true},
		{2, 2, []byte{}, 0, nil, false},
		{1, 2, []byte{0, 255}, 0, nil, false},
		{1, 0, nil, ErrnoERANGE, XAttrSizeError{2}, true},
		{2, 0, nil, ErrnoERANGE, XAttrSizeError{2}, false},
		{0, 0, nil, ErrnoERANGE, XAttrSizeError{2}, false},
		{1, 0, nil, 5, XAttrSizeError{2}, false},
	}
	for i, c := range cases {
		req := request(GetXAttrRequest{Node: 1, Name: []byte("user.x"), Size: c.capacity})
		body := c.body
		if body == nil {
			body = GetXAttrReply{Size: c.size, Value: c.value}
		}
		rep := Reply{Sequence: 1, Op: OpGetXAttr, Errno: c.errno, Body: body}
		err := ValidateReplyFor(req, rep)
		if (err == nil) != c.valid {
			t.Errorf("case %d: %v", i, err)
		}
	}
	rep := Reply{Sequence: 1, Op: OpGetXAttr, Body: GetXAttrReply{Size: 0, Value: []byte{}}}
	b, err := Marshal(&rep)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"sequence":1,"op":"get_xattr","errno":0,"body":{"size":0,"value":""}}` {
		t.Fatal(string(b))
	}
	var out Reply
	if err := Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, rep) {
		t.Fatal("empty xattr lost")
	}
}
func TestMalformedJSON(t *testing.T) {
	r := request(LookupRequest{Parent: 1, Name: []byte("x")})
	b, err := Marshal(&r)
	if err != nil {
		t.Fatal(err)
	}
	good := string(b)
	cases := map[string]string{
		"duplicate":         strings.Replace(good, `"sequence":1`, `"sequence":1,"sequence":2`, 1),
		"escaped_duplicate": strings.Replace(good, `"sequence":1`, `"sequence":1,"sequen\u0063e":2`, 1),
		"nested_duplicate":  strings.Replace(good, `"fsuid":1000`, `"fsuid":1000,"fsuid":0`, 1),
		"unknown":           strings.Replace(good, `"sequence":1`, `"sequence":1,"other":0`, 1),
		"nested_unknown":    strings.Replace(good, `"fsuid":1000`, `"fsuid":1000,"other":0`, 1),
		"body_unknown":      strings.Replace(good, `"parent":1`, `"parent":1,"node":1`, 1),
		"missing":           strings.Replace(good, `"fsuid":1000,`, "", 1),
		"casefold":          strings.Replace(good, `"fsuid"`, `"FSUID"`, 1),
		"null":              strings.Replace(good, `"fsuid":1000`, `"fsuid":null`, 1),
		"null_groups":       strings.Replace(good, `[7,8]`, `null`, 1),
		"wrong_type":        strings.Replace(good, `"parent":1`, `"parent":"1"`, 1),
		"overflow":          strings.Replace(good, `"parent":1`, `"parent":18446744073709551616`, 1),
		"negative":          strings.Replace(good, `"sequence":1`, `"sequence":-1`, 1),
		"fraction":          strings.Replace(good, `"sequence":1`, `"sequence":1.0`, 1),
		"exponent":          strings.Replace(good, `"sequence":1`, `"sequence":1e0`, 1),
		"trailing":          good + ` {}`,
		"array_bytes":       strings.Replace(good, `"eA=="`, `[120]`, 1),
		"bad_base64":        strings.Replace(good, `"eA=="`, `"eB=="`, 1),
		"base64_newline":    strings.Replace(good, `"eA=="`, `"eA==\n"`, 1),
		"null_bytes":        strings.Replace(good, `"eA=="`, `null`, 1),
		"wrong_union":       strings.Replace(good, `"lookup"`, `"write"`, 1),
		"unknown_op":        strings.Replace(good, `"lookup"`, `"ioctl"`, 1),
		"missing_caller":    `{"sequence":1,"auth":{"kind":1},"op":"lookup","body":{"parent":1,"name":"eA=="}}`,
		"depth":             strings.Replace(good, `"parent":1`, `"parent":`+strings.Repeat("[", MaxDepth+1)+"1"+strings.Repeat("]", MaxDepth+1), 1),
		"invalid_utf8":      good[:5] + string([]byte{255}) + good[5:],
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			out := r
			if err := Unmarshal([]byte(s), &out); !errors.Is(err, ErrInvalid) {
				t.Fatalf("wanted invalid: %v", err)
			}
			if !reflect.DeepEqual(out, r) {
				t.Fatal("failed decode changed destination")
			}
		})
	}
	malformedReplies := []string{
		`{"sequence":1,"op":"flush","errno":0}`,
		`{"sequence":1,"op":"flush","errno":0,"body":null}`,
		`{"sequence":1,"op":"flush","errno":0,"body":{"written":0}}`,
		`{"sequence":1,"op":"flush","errno":5,"body":{}}`,
		`{"sequence":1,"op":"flush","errno":-1}`,
		`{"sequence":1,"op":"flush","errno":4096}`,
		`{"sequence":1,"op":"get_xattr","errno":34,"body":{"size":1,"unknown":0}}`,
	}
	for _, s := range malformedReplies {
		var out Reply
		if err := Unmarshal([]byte(s), &out); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
func TestFramingLimitsAndTruncation(t *testing.T) {
	for _, n := range []uint32{0, MaxFrame + 1, math.MaxUint32} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		var out Request
		if err := ReadFrame(bytes.NewReader(h[:]), &out); !errors.Is(err, ErrInvalid) {
			t.Fatal(n, err)
		}
	}
	var out Request
	for _, b := range [][]byte{{0}, {0, 0, 0, 2, '{'}} {
		if err := ReadFrame(bytes.NewReader(b), &out); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	}
	r := request(LookupRequest{1, []byte("x")})
	var w shortWriter
	if err := WriteFrame(&w, &r); err != nil {
		t.Fatal(err)
	}
	if err := ReadFrame(bytes.NewReader(w.Bytes()), &out); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(zeroWriter{}, &r); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	hello := ServerHello{testID, Version, RequiredProfile()}
	b, err := Marshal(&hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := Unmarshal(append(b, bytes.Repeat([]byte(" "), MaxHello)...), &hello); err == nil {
		t.Fatal("oversize hello")
	}
	if err := ReadFrame(bytes.NewReader([]byte{0, 0, 0x40, 1}), &hello); err == nil {
		t.Fatal("oversize hello header")
	}
	if err := MarshalNil(); err == nil {
		t.Fatal("nil")
	}
}
func MarshalNil() error { var r *Request; _, err := Marshal(r); return err }

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestMaximumCallerAndWrite(t *testing.T) {
	r := request(WriteRequest{Node: 1, Handle: 2, Data: bytes.Repeat([]byte{255}, MaxIO)})
	r.Auth.Caller.Groups = make([]uint32, MaxGroups)
	for i := range r.Auth.Caller.Groups {
		r.Auth.Caller.Groups[i] = math.MaxUint32
	}
	r.Auth.Caller.EffectiveCaps = math.MaxUint64
	b, err := Marshal(&r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxFrame {
		t.Fatal(len(b))
	}
	var out Request
	if err := Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, out) {
		t.Fatal("maximal caller lost")
	}
	r.Auth.Caller.Groups = append(r.Auth.Caller.Groups, 1)
	if _, err := Marshal(&r); err == nil {
		t.Fatal("groups limit")
	}
	// Typed decoder bounds too, without using the encoder to construct bad data.
	bad := bytes.Replace(b, []byte(`"groups":[`), []byte(`"groups":[1,`), 1)
	if err := Unmarshal(bad, &out); err == nil {
		t.Fatal("decode groups limit")
	}
}
func TestDirectJSONRequestAndReplyRemainStrict(t *testing.T) {
	var r Request
	if err := json.Unmarshal([]byte(`{"sequence":1,"sequence":2}`), &r); err == nil {
		t.Fatal("json.Unmarshal bypass")
	}
	var rep Reply
	if err := json.Unmarshal([]byte(`{"sequence":1,"op":"flush","errno":0,"body":{}}`), &rep); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(Request{}); err == nil {
		t.Fatal("marshal invalid")
	}
}
