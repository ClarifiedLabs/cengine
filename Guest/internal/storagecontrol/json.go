package storagecontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func invalid(_ string) error { return ErrProtocol }

var rawType = reflect.TypeOf(json.RawMessage{})

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
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	return nil
}
func checkJSON(b []byte) error {
	if len(b) == 0 || len(b) > MaxAggregate || !utf8.Valid(b) {
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
	if depth > 32 {
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
			for _, v := range values {
				if err := checkShape(v, t.Elem()); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		if b[0] != '{' {
			return ErrProtocol
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			return ErrProtocol
		}
		for _, raw := range fields {
			if err := checkShape(raw, t.Elem()); err != nil {
				return err
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
