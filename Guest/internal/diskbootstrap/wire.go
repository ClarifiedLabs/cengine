// Package diskbootstrap implements the private, one-shot pre-workload disk gate.
// This file deliberately has no Linux or syscall dependencies.
package diskbootstrap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

const (
	Version           = 1
	Port              = 4105
	RemoteCID         = 2
	MaximumFrameBytes = 65536
	MaximumDisks      = 26
)

var errFrame = errors.New("invalid-frame")

type HelloDisk struct {
	Ordinal         uint32 `json:"ordinal"`
	BlockIdentifier string `json:"blockIdentifier"`
	Bytes           uint64 `json:"bytes"`
}
type Hello struct {
	Version        uint32      `json:"version"`
	Type           string      `json:"type"`
	Kind           string      `json:"kind"`
	GuestBootNonce string      `json:"guestBootNonce"`
	Disks          []HelloDisk `json:"disks"`
}
type ManifestDisk struct {
	Ordinal       uint32  `json:"ordinal"`
	Role          string  `json:"role"`
	VolumeName    *string `json:"volumeName,omitempty"`
	Action        string  `json:"action"`
	ExpectedBytes uint64  `json:"expectedBytes"`
	Ext4UUID      *string `json:"ext4UUID,omitempty"`
	OperationUUID *string `json:"operationUUID,omitempty"`
}
type Manifest struct {
	Version        uint32         `json:"version"`
	Type           string         `json:"type"`
	Kind           string         `json:"kind"`
	ShimLaunchUUID string         `json:"shimLaunchUUID"`
	GuestBootNonce string         `json:"guestBootNonce"`
	Disks          []ManifestDisk `json:"disks"`
}
type SyncedDisk struct {
	Ordinal       uint32  `json:"ordinal"`
	Bytes         uint64  `json:"bytes"`
	Ext4UUID      string  `json:"ext4UUID"`
	OperationUUID *string `json:"operationUUID,omitempty"`
}
type Synced struct {
	Version        uint32       `json:"version"`
	Type           string       `json:"type"`
	ShimLaunchUUID string       `json:"shimLaunchUUID"`
	GuestBootNonce string       `json:"guestBootNonce"`
	Sync           string       `json:"sync"`
	Disks          []SyncedDisk `json:"disks"`
}
type Commit struct {
	Version        uint32 `json:"version"`
	Type           string `json:"type"`
	ShimLaunchUUID string `json:"shimLaunchUUID"`
	GuestBootNonce string `json:"guestBootNonce"`
}
type Failure struct {
	Version uint32  `json:"version"`
	Type    string  `json:"type"`
	Code    string  `json:"code"`
	Ordinal *uint32 `json:"ordinal,omitempty"`
}

func (f *Failure) Error() string { return f.Code }
func failure(code string, ordinal *uint32) *Failure {
	return &Failure{Version: Version, Type: "error", Code: code, Ordinal: ordinal}
}

func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || strings.ToLower(s) != s {
		return false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(raw) == 16 && s != "00000000-0000-0000-0000-000000000000"
}
func validSize(n uint64) bool { return n > 0 && n <= 1<<63-1 }
func validKind(s string) bool { return s == "container" || s == "storage" }
func validName(s string) bool {
	return len(s) > 0 && len(s) <= 255 && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00") && utf8.ValidString(s)
}
func validCount(n int) bool { return n > 0 && n <= MaximumDisks }

// ReadFrame consumes exactly one uint32-big-endian framed UTF-8 JSON message.
func ReadFrame(r io.Reader) (any, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, errFrame
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaximumFrameBytes {
		return nil, errFrame
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, errFrame
	}
	return decode(data)
}
func WriteFrame(w io.Writer, message any) error {
	data, err := json.Marshal(message)
	if err != nil || len(data) > MaximumFrameBytes {
		return errFrame
	}
	if _, err = decode(data); err != nil {
		return err
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if n < 0 || n > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Token parsing rejects duplicates (including escaped aliases), all nulls,
// trailing JSON, and excessive nesting before decoding into a closed shape.
func value(d *json.Decoder, depth int) (any, error) {
	if depth > 8 {
		return nil, errFrame
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return nil, errFrame
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, errFrame
				}
				s, ok := key.(string)
				if !ok {
					return nil, errFrame
				}
				if _, exists := m[s]; exists {
					return nil, errFrame
				}
				v, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[s] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errFrame
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errFrame
			}
			return a, nil
		default:
			return nil, errFrame
		}
	}
	return t, nil
}
func closed(v any, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			fields[tag[0]] = f
			if _, exists := m[tag[0]]; !exists && len(tag) == 1 {
				return false
			}
		}
		for k, item := range m {
			f, ok := fields[k]
			if !ok || !closed(item, f.Type) {
				return false
			}
		}
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, item := range a {
			if !closed(item, typ.Elem()) {
				return false
			}
		}
	case reflect.String:
		_, ok := v.(string)
		return ok
	case reflect.Uint32, reflect.Uint64:
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		s := n.String()
		if len(s) == 0 {
			return false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
	default:
		return false
	}
	return true
}
func decode(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errFrame
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := value(d, 0)
	if err != nil {
		return nil, errFrame
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errFrame
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errFrame
	}
	var result any
	switch m["type"] {
	case "hello":
		result = &Hello{}
	case "manifest":
		result = &Manifest{}
	case "synced":
		result = &Synced{}
	case "commit":
		result = &Commit{}
	case "error":
		result = &Failure{}
	default:
		return nil, errFrame
	}
	if !closed(v, reflect.TypeOf(result)) || json.Unmarshal(data, result) != nil || !validMessage(result) {
		return nil, errFrame
	}
	return result, nil
}
func validMessage(message any) bool {
	switch m := message.(type) {
	case *Hello:
		if m.Version != Version || !validKind(m.Kind) || !validUUID(m.GuestBootNonce) || !validCount(len(m.Disks)) {
			return false
		}
		for i, d := range m.Disks {
			if d.Ordinal != uint32(i) || !validSize(d.Bytes) || d.BlockIdentifier != blockIdentifier(i) {
				return false
			}
		}
		return m.Kind != "storage" || len(m.Disks) == 1
	case *Manifest:
		if m.Version != Version || !validKind(m.Kind) || !validUUID(m.GuestBootNonce) || !validUUID(m.ShimLaunchUUID) || !validCount(len(m.Disks)) {
			return false
		}
		names, operations := map[string]bool{}, map[string]bool{}
		for i, d := range m.Disks {
			if d.Ordinal != uint32(i) || !validSize(d.ExpectedBytes) {
				return false
			}
			role := "direct-volume"
			if i == 0 {
				role = "container-root"
				if m.Kind == "storage" {
					role = "storage-root"
				}
			}
			if d.Role != role {
				return false
			}
			if role == "direct-volume" {
				if d.VolumeName == nil || !validName(*d.VolumeName) || names[*d.VolumeName] {
					return false
				}
				names[*d.VolumeName] = true
			} else if d.VolumeName != nil {
				return false
			}
			if d.Ext4UUID != nil && !validUUID(*d.Ext4UUID) {
				return false
			}
			switch d.Action {
			case "initialize-ext4":
				if d.ExpectedBytes < 16<<20 || d.ExpectedBytes%4096 != 0 || d.Ext4UUID == nil || d.OperationUUID == nil || !validUUID(*d.OperationUUID) || operations[*d.OperationUUID] {
					return false
				}
				operations[*d.OperationUUID] = true
			case "probe-read-only":
				// Observation only: no destructive initialization capability.
				if m.Kind != "storage" || len(m.Disks) != 1 || d.Ext4UUID == nil || d.OperationUUID != nil {
					return false
				}
			case "mount-existing-ext4":
				if d.OperationUUID != nil {
					return false
				}
			default:
				return false
			}
		}
		return m.Kind != "storage" || len(m.Disks) == 1
	case *Synced:
		if m.Version != Version || !validUUID(m.GuestBootNonce) || !validUUID(m.ShimLaunchUUID) || (m.Sync != "filesystem-and-block" && m.Sync != "read-only-no-replay") || !validCount(len(m.Disks)) {
			return false
		}
		if m.Sync == "read-only-no-replay" && (len(m.Disks) != 1 || m.Disks[0].OperationUUID != nil) {
			return false
		}
		for i, d := range m.Disks {
			if d.Ordinal != uint32(i) || !validSize(d.Bytes) || !validUUID(d.Ext4UUID) || (d.OperationUUID != nil && !validUUID(*d.OperationUUID)) {
				return false
			}
		}
		return true
	case *Commit:
		return m.Version == Version && validUUID(m.GuestBootNonce) && validUUID(m.ShimLaunchUUID)
	case *Failure:
		if m.Version != Version || (m.Ordinal != nil && *m.Ordinal >= MaximumDisks) {
			return false
		}
		switch m.Code {
		case "invalid-peer", "invalid-frame", "invalid-manifest", "disk-mismatch", "disk-operation", "sync", "commit":
			return true
		}
	}
	return false
}
