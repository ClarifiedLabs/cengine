package storagewire

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid storagewire v4 message")

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }

// Message is sealed; only pointers to the six top-level messages are accepted.
// The codec is stateless. SequenceTracker handles stream ordering separately.
type Message interface {
	Validate() error
	message()
}

func (*Request) message()     {}
func (*Reply) message()       {}
func (*ServerHello) message() {}
func (*ClientHello) message() {}
func (*RootReply) message()   {}
func (*Event) message()       {}

func messageLimit(m Message) (int, error) {
	if m == nil || reflect.ValueOf(m).Kind() != reflect.Pointer || reflect.ValueOf(m).IsNil() {
		return 0, invalid("nil message")
	}
	switch m.(type) {
	case *Request, *Reply, *Event:
		return MaxFrame, nil
	case *ServerHello, *ClientHello, *RootReply:
		return MaxHello, nil
	default:
		return 0, invalid("unknown message type")
	}
}

// Marshal validates before emitting JSON; nil byte slices/lists are not empty.
func Marshal(m Message) ([]byte, error) {
	limit, err := messageLimit(m)
	if err != nil {
		return nil, err
	}
	if err = m.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, invalid("frame limit")
	}
	// Enforce the identical strict shape for locally constructed messages too.
	dst := reflect.New(reflect.TypeOf(m).Elem()).Interface().(Message)
	if err = Unmarshal(b, dst); err != nil {
		return nil, err
	}
	return b, nil
}

// Unmarshal rejects noncanonical field spellings, missing required fields,
// duplicate keys, nulls, malformed base64, unknown fields and trailing values.
// A failed decode never partially changes dst. Whitespace is permitted.
func Unmarshal(b []byte, dst Message) error {
	limit, err := messageLimit(dst)
	if err != nil {
		return err
	}
	if len(b) == 0 || len(b) > limit {
		return invalid("frame limit")
	}
	tmp := reflect.New(reflect.TypeOf(dst).Elem()).Interface().(Message)
	switch v := tmp.(type) {
	case *Request:
		err = v.UnmarshalJSON(b)
	case *Reply:
		err = v.UnmarshalJSON(b)
	default:
		err = strictDecode(b, tmp)
	}
	if err != nil {
		return err
	}
	if err = tmp.Validate(); err != nil {
		return err
	}
	reflect.ValueOf(dst).Elem().Set(reflect.ValueOf(tmp).Elem())
	return nil
}

// ReadFrame allocates only after checking the uint32 big-endian length. There is
// no compression. Callers must also bound aggregate receive memory and time.
func ReadFrame(r io.Reader, dst Message) error {
	limit, err := messageLimit(dst)
	if err != nil {
		return err
	}
	var header [4]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > uint32(limit) {
		return invalid("frame length")
	}
	b := make([]byte, int(n))
	if _, err = io.ReadFull(r, b); err != nil {
		return err
	}
	return Unmarshal(b, dst)
}

// WriteFrame does not synchronize writers. Use one bounded ordered writer.
func WriteFrame(w io.Writer, m Message) error {
	b, err := Marshal(m)
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(b)))
	copy(frame[4:], b)
	for len(frame) > 0 {
		n, e := w.Write(frame)
		if n < 0 || n > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type requestEnvelope struct {
	Sequence uint64          `json:"sequence"`
	Auth     Auth            `json:"auth"`
	Op       Operation       `json:"op"`
	Body     json.RawMessage `json:"body"`
}
type replyEnvelope struct {
	Sequence uint64          `json:"sequence"`
	Op       Operation       `json:"op"`
	Errno    uint32          `json:"errno"`
	Body     json.RawMessage `json:"body,omitempty"`
}

func (r Request) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r.Body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(requestEnvelope{r.Sequence, r.Auth, r.Body.Operation(), b})
}
func (r *Request) UnmarshalJSON(b []byte) error {
	var e requestEnvelope
	if err := strictDecode(b, &e); err != nil {
		return err
	}
	body, err := decodeRequestBody(e.Op, e.Body)
	if err != nil {
		return err
	}
	v := Request{e.Sequence, e.Auth, body}
	if err = v.Validate(); err != nil {
		return err
	}
	*r = v
	return nil
}
func (r Reply) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b []byte
	if r.Body != nil {
		var err error
		b, err = json.Marshal(r.Body)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(replyEnvelope{r.Sequence, r.Op, r.Errno, b})
}
func (r *Reply) UnmarshalJSON(b []byte) error {
	var e replyEnvelope
	if err := strictDecode(b, &e); err != nil {
		return err
	}
	v := Reply{Sequence: e.Sequence, Op: e.Op, Errno: e.Errno}
	if e.Errno == 0 {
		body, err := decodeReplyBody(e.Op, e.Body)
		if err != nil {
			return err
		}
		v.Body = body
	} else if len(e.Body) > 0 {
		var size XAttrSizeError
		if err := strictDecode(e.Body, &size); err != nil {
			return err
		}
		v.Body = size
	}
	if err := v.Validate(); err != nil {
		return err
	}
	*r = v
	return nil
}

var rawType = reflect.TypeOf(json.RawMessage{})
var objectType = reflect.TypeOf(ObjectID{})

// RawMessage is internal staging only: the envelope selects a closed concrete
// body, which is fully shape/type/semantically checked before publication.
func strictDecode(b []byte, dst any) error {
	if err := checkJSON(b); err != nil {
		return err
	}
	if err := checkShape(b, reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}
func checkJSON(b []byte) error {
	if len(b) == 0 || len(b) > MaxFrame || !utf8.Valid(b) {
		return invalid("JSON encoding/length")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := scanValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalid("trailing JSON")
	}
	return nil
}
func scanValue(d *json.Decoder, depth int) error {
	if depth > MaxDepth {
		return invalid("JSON nesting")
	}
	token, err := d.Token()
	if err != nil {
		return invalid("malformed JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return invalid("object key")
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return invalid("duplicate/object key")
			}
			seen[s] = true
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return invalid("object end")
		}
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return invalid("array end")
		}
	default:
		return invalid("unexpected delimiter")
	}
	return nil
}
func checkShape(b []byte, t reflect.Type) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return invalid("missing/null field")
	}
	if t == rawType {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		return checkShape(b, t.Elem())
	}
	if t == reflect.TypeOf(PrepareReply{}) {
		return checkShape(b, reflect.TypeOf(prepareReplyDTO{}))
	}
	if t == objectType {
		var id ObjectID
		if err := id.UnmarshalJSON(b); err != nil {
			return invalid("object ID")
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if b[0] != '{' {
			return invalid("object required")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			return invalid("object")
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			if name == "" {
				return invalid("untagged schema field")
			}
			raw, ok := fields[name]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !ok {
				if optional {
					continue
				}
				return invalid("missing " + name)
			}
			if err := checkShape(raw, f.Type); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			delete(fields, name)
		}
		if len(fields) != 0 {
			return invalid("unknown field")
		}
	case reflect.Array:
		var values []json.RawMessage
		if b[0] != '[' || json.Unmarshal(b, &values) != nil || len(values) != t.Len() {
			return invalid("fixed array length")
		}
		for _, value := range values {
			if err := checkShape(value, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			if b[0] != '"' {
				return invalid("base64 string required")
			}
			var s string
			if err := json.Unmarshal(b, &s); err != nil {
				return invalid("base64 string")
			}
			v, err := base64.StdEncoding.Strict().DecodeString(s)
			if err != nil || base64.StdEncoding.EncodeToString(v) != s {
				return invalid("noncanonical base64")
			}
		} else {
			if b[0] != '[' {
				return invalid("array required")
			}
			var values []json.RawMessage
			if err := json.Unmarshal(b, &values); err != nil {
				return invalid("array")
			}
			// Bound before typed allocation; the outer frame also bounds scanning.
			limit := MaxGroups
			if t.Elem() == reflect.TypeOf(DirEntry{}) {
				limit = MaxDirEntries
			}
			if t.Elem() == reflect.TypeOf(ForgetEntry{}) {
				limit = MaxForget
			}
			if len(values) > limit {
				return invalid("array limit")
			}
			for _, v := range values {
				if err := checkShape(v, t.Elem()); err != nil {
					return err
				}
			}
		}
	default:
		v := reflect.New(t).Interface()
		if err := json.Unmarshal(b, v); err != nil {
			return invalid("field type/range")
		}
	}
	return nil
}

// SequenceTracker accepts positive strictly increasing numbers (gaps allowed).
// It is owned by one FIFO stream, not shared concurrently. Overflow is terminal:
// after MaxUint64 no value is accepted. Replies also require ValidateReplyFor.
type SequenceTracker struct{ last uint64 }

func (s *SequenceTracker) Accept(sequence uint64) error {
	if sequence == 0 || sequence <= s.last {
		return invalid("nonmonotonic sequence")
	}
	s.last = sequence
	return nil
}
