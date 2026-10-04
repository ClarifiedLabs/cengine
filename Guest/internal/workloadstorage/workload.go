package workloadstorage

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	"dev.cengine/guest/internal/protocol"
)

// The ordinary workload has richer JSON than the authority envelope. Preserve
// its exact bytes for hashing, but reject aliases/duplicates and injected trusted
// attachment metadata before decoding and injecting the separate I/O claim.
func decodeManagedWorkload(raw []byte) (protocol.WorkloadSpec, error) {
	var spec protocol.WorkloadSpec
	if len(raw) == 0 || len(raw) > MaximumWorkloadBytes || !validUnicode(raw) {
		return spec, ErrInvalidFrame
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	scan.UseNumber()
	tree, err := workloadValue(scan, 0)
	if err != nil {
		return spec, ErrInvalidFrame
	}
	if _, err = scan.Token(); err != io.EOF {
		return spec, ErrInvalidFrame
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return spec, ErrInvalidFrame
	}
	claim, ok := root["ioClaim"].(string)
	if !ok || claim != "" {
		return spec, ErrInvalidFrame
	}
	mounts, ok := root["mounts"].([]any)
	if !ok {
		return spec, ErrInvalidFrame
	}
	for _, item := range mounts {
		mount, ok := item.(map[string]any)
		if !ok {
			return spec, ErrInvalidFrame
		}
		if _, present := mount["managedAttachment"]; present {
			return spec, ErrInvalidFrame
		}
	}
	if !exactWorkloadShape(tree, reflect.TypeOf(spec)) {
		return spec, ErrInvalidFrame
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&spec); err != nil {
		return protocol.WorkloadSpec{}, ErrInvalidFrame
	}
	if spec.IOClaim != "" {
		return protocol.WorkloadSpec{}, ErrInvalidFrame
	}
	return spec, nil
}
func workloadValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrInvalidFrame
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalidFrame
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		result := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, ErrInvalidFrame
			}
			name, ok := key.(string)
			if !ok {
				return nil, ErrInvalidFrame
			}
			if _, exists := result[name]; exists {
				return nil, ErrInvalidFrame
			}
			value, err := workloadValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			result[name] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalidFrame
		}
		return result, nil
	case '[':
		result := []any{}
		for decoder.More() {
			value, err := workloadValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalidFrame
		}
		return result, nil
	default:
		return nil, ErrInvalidFrame
	}
}

// encoding/json accepts case-insensitive field aliases, unlike the paired Swift
// schema. Validate exact JSON tag spelling recursively, while leaving dictionary
// keys (environment annotations, sysctls, hosts) intentionally unconstrained.
func exactWorkloadShape(value any, typ reflect.Type) bool {
	if value == nil {
		return typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Map || typ.Kind() == reflect.Slice
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag != "" && tag != "-" {
				fields[tag] = field.Type
			}
		}
		for key, entry := range object {
			field, ok := fields[key]
			if !ok || !exactWorkloadShape(entry, field) {
				return false
			}
		}
		return true
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		for _, entry := range object {
			if !exactWorkloadShape(entry, typ.Elem()) {
				return false
			}
		}
		return true
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, entry := range array {
			if !exactWorkloadShape(entry, typ.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Bool:
		_, ok := value.(bool)
		return ok
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint, reflect.Uint64, reflect.Uint32, reflect.Uint16:
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}
