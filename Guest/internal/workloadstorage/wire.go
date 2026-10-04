// Package workloadstorage defines the private workload storage wire format only.
// It does not authenticate peers or implement sessions, lifecycle, or networking.
package workloadstorage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"dev.cengine/guest/internal/preparecompat"
)

const (
	Version              = 1
	Type                 = "workload-storage.v1"
	Port                 = 4109
	DataPort             = 2049
	MaximumFrameBytes    = 1 << 20
	MaximumWorkloadBytes = 512 << 10
)

// ErrInvalidFrame deliberately contains no payload or secret material.
var ErrInvalidFrame = errors.New("invalid-frame")

type BootBinding preparecompat.BootBinding

type Scope preparecompat.Scope

type Peer struct {
	TLSRootDER  []byte `json:"tlsRootDER"`
	ServerDER   []byte `json:"serverDER"`
	ServerKey   string `json:"serverKey"`
	DataAddress string `json:"dataAddress"`
}

type Slot preparecompat.Slot

type MountBinding preparecompat.MountBinding

type Offer struct {
	Attachment string `json:"attachment"`
	Key        string `json:"key"`
	CSRDER     []byte `json:"csrDER"`
}

// Payload is a closed, flattened tagged union. Operation and Kind select the
// exact permitted fields; pointers distinguish absent fields from false/empty.
// IOClaim is a secret: never log a Frame or Payload.
type Payload struct {
	CompatibilityIOObservation    *preparecompat.IOObservation    `json:"compatibilityIOObservation,omitempty"`
	CompatibilityEarlyObservation *preparecompat.EarlyObservation `json:"compatibilityEarlyObservation,omitempty"`
	CompatibilityProfile          *string                         `json:"compatibilityProfile,omitempty"`
	CompatibilityArm              *preparecompat.Arm              `json:"compatibilityArm,omitempty"`
	CompatibilityDigest           *string                         `json:"compatibilityDigest,omitempty"`
	CompatibilityObservation      *preparecompat.Observation      `json:"compatibilityObservation,omitempty"`
	Peer                          *Peer                           `json:"peer,omitempty"`
	Mounts                        *[]MountBinding                 `json:"mounts,omitempty"`
	Slots                         *[]Slot                         `json:"slots,omitempty"`
	Role                          *string                         `json:"role,omitempty"`
	Attachment                    *string                         `json:"attachment,omitempty"`
	CertificateDER                *[]byte                         `json:"certificateDER,omitempty"`
	WorkloadJSON                  *[]byte                         `json:"workloadJSON,omitempty"`
	IOClaim                       *string                         `json:"ioClaim,omitempty"`
	Offers                        *[]Offer                        `json:"offers,omitempty"`
	AttachmentIDs                 *[]string                       `json:"attachmentIDs,omitempty"`
	Prepare                       *string                         `json:"prepare,omitempty"`
	ContainerInstance             *string                         `json:"containerInstance,omitempty"`
	Launch                        *string                         `json:"launch,omitempty"`
	Succeeded                     *bool                           `json:"succeeded,omitempty"`
	CleanCopyUp                   *bool                           `json:"cleanCopyUp,omitempty"`
	EvidenceDigest                *string                         `json:"evidenceDigest,omitempty"`
	Clean                         *bool                           `json:"clean,omitempty"`
	Status                        *string                         `json:"status,omitempty"`
	PID                           *uint32                         `json:"pid,omitempty"`
	Phase                         *string                         `json:"phase,omitempty"`
	MountedIDs                    *[]string                       `json:"mountedIDs,omitempty"`
	TerminalIDs                   *[]string                       `json:"terminalIDs,omitempty"`
	Code                          *string                         `json:"code,omitempty"`
}

type Frame struct {
	Version   uint32      `json:"version"`
	Type      string      `json:"type"`
	Operation string      `json:"operation"`
	Binding   BootBinding `json:"binding"`
	Scope     *Scope      `json:"scope,omitempty"`
	Data      Payload     `json:"data"`
	Sequence  *uint64     `json:"sequence,omitempty"`
	Kind      string      `json:"kind,omitempty"`
}

func NewFrame(operation string, binding BootBinding, scope Scope, data Payload) *Frame {
	return &Frame{Version: Version, Type: Type, Operation: operation, Binding: binding, Scope: &scope, Data: data}
}

// SpecificationDigest hashes exact opaque bytes, without decoding or rewriting.
func SpecificationDigest(workloadJSON []byte) string {
	sum := sha256.Sum256(workloadJSON)
	return hex.EncodeToString(sum[:])
}

func ReadFrame(r io.Reader) (*Frame, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, ErrInvalidFrame
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > MaximumFrameBytes {
		return nil, ErrInvalidFrame
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, ErrInvalidFrame
	}
	return Decode(body)
}

func WriteFrame(w io.Writer, f *Frame) error {
	// encoding/json repairs invalid UTF-8 strings, so reject these before marshal.
	if f == nil || !validStrings(reflect.ValueOf(f)) {
		return ErrInvalidFrame
	}
	body, err := json.Marshal(f)
	if err != nil {
		return ErrInvalidFrame
	}
	if _, err = Decode(body); err != nil {
		return err
	}
	data := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(data, uint32(len(body)))
	copy(data[4:], body)
	for len(data) != 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validStrings(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer:
		return v.IsNil() || validStrings(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !validStrings(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.Uint8 {
			for i := 0; i < v.Len(); i++ {
				if !validStrings(v.Index(i)) {
					return false
				}
			}
		}
	case reflect.String:
		return utf8.ValidString(v.String())
	}
	return true
}

// Go's JSON decoder repairs unpaired escaped surrogates. Scan string escapes
// first, while letting the decoder enforce all remaining JSON grammar.
func validUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// The bounded token pass rejects escaped duplicate keys, nulls and trailing JSON
// before decoding into a closed DTO. Root depth is zero, as in storageboot.
func value(d *json.Decoder, depth int) (any, error) {
	if depth > 8 {
		return nil, ErrInvalidFrame
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return nil, ErrInvalidFrame
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, ErrInvalidFrame
				}
				s, ok := key.(string)
				if !ok {
					return nil, ErrInvalidFrame
				}
				if _, exists := m[s]; exists {
					return nil, ErrInvalidFrame
				}
				item, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[s] = item
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalidFrame
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				if len(a) == 64 {
					return nil, ErrInvalidFrame
				}
				item, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, item)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalidFrame
			}
			return a, nil
		default:
			return nil, ErrInvalidFrame
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
		if typ.Elem().Kind() == reflect.Uint8 {
			text, ok := v.(string)
			if !ok {
				return false
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(text)
			return err == nil && base64.StdEncoding.EncodeToString(decoded) == text
		}
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
	case reflect.Bool:
		_, ok := v.(bool)
		return ok
	case reflect.Uint32, reflect.Uint64:
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		s := n.String()
		if len(s) == 0 || len(s) > 1 && s[0] == '0' {
			return false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		_, err := strconv.ParseUint(s, 10, typ.Bits())
		return err == nil
	default:
		return false
	}
	return true
}

func Decode(body []byte) (*Frame, error) {
	if len(body) == 0 || len(body) > MaximumFrameBytes || !validUnicode(body) {
		return nil, ErrInvalidFrame
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	v, err := value(d, 0)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalidFrame
	}
	if !closed(v, reflect.TypeOf(Frame{})) {
		return nil, ErrInvalidFrame
	}
	f := new(Frame)
	if json.Unmarshal(body, f) != nil || !validFrame(f, v.(map[string]any)) {
		return nil, ErrInvalidFrame
	}
	return f, nil
}

func uuid(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || strings.ToLower(s) != s {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(b) == 16 && s != "00000000-0000-0000-0000-000000000000"
}
func id(s string) bool { return uuid(s) && s[14] == '4' && strings.ContainsRune("89ab", rune(s[19])) }
func pin(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func role(s string) bool          { return s == "prepare" || s == "runtime" }
func mode(s string) bool          { return s == "read-only" || s == "read-write" }
func text(s string) bool          { return len(s) <= 4096 && utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
func blob(b []byte, max int) bool { return len(b) > 0 && len(b) <= max }
func exact(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func uniqueIDs(ids []string, max int) bool {
	if len(ids) > max {
		return false
	}
	seen := map[string]bool{}
	for _, s := range ids {
		if !id(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func validScope(s Scope) bool {
	return id(s.Intent) && id(s.Store) && id(s.ServiceEpoch) && s.ControllerEpoch > 0 && pin(s.ControllerKey) && pin(s.Container) && id(s.ContainerInstance) && id(s.Launch) && id(s.Prepare) && pin(s.SpecificationDigest)
}
func validPeer(p *Peer) bool {
	address, err := netip.ParseAddr(p.DataAddress)
	return err == nil && address.Zone() == "" && blob(p.TLSRootDER, 16384) && blob(p.ServerDER, 16384) && pin(p.ServerKey)
}
func kind(s string) bool {
	switch s {
	case "prepare-compatibility-arm", "offer-keys", "install-certificate", "mount-phase", "prepare", "close-phase", "start", "status", "abort":
		return true
	}
	return false
}
func code(s string) bool {
	switch s {
	case "invalid-frame", "binding-mismatch", "scope-mismatch", "configuration", "sequence", "phase", "certificate", "mount", "prepare", "start", "aborted", "terminal", "internal":
		return true
	}
	return false
}
func phase(s string) bool {
	switch s {
	case "configured", "keys-offered", "certificates-installed", "prepare-mounted", "prepared", "prepare-closed", "runtime-mounted", "running", "aborted", "terminal":
		return true
	}
	return false
}

// ValidateConfiguration checks the complete hierarchy, not session authority.
func ValidateConfiguration(mounts []MountBinding, slots []Slot) error {
	if len(mounts) > 64 || len(slots) > 64 {
		return ErrInvalidFrame
	}
	indices := map[uint32]bool{}
	volumes := map[string]bool{}
	type slotKey struct{ volume, role, mode string }
	required := map[slotKey]bool{}
	for _, m := range mounts {
		if m.Index >= 64 || indices[m.Index] || !id(m.Volume) || !text(m.Destination) || !strings.HasPrefix(m.Destination, "/") || !text(m.Subpath) || !mode(m.Mode) {
			return ErrInvalidFrame
		}
		indices[m.Index] = true
		volumes[m.Volume] = true
		required[slotKey{m.Volume, "prepare", "read-write"}] = true
		required[slotKey{m.Volume, "runtime", m.Mode}] = true
	}
	attachments := map[string]bool{}
	seen := map[slotKey]bool{}
	for _, s := range slots {
		k := slotKey{s.Volume, s.Role, s.Mode}
		if !id(s.Volume) || !id(s.Attachment) || !role(s.Role) || !mode(s.Mode) || !volumes[s.Volume] || attachments[s.Attachment] || seen[k] || !required[k] {
			return ErrInvalidFrame
		}
		attachments[s.Attachment] = true
		seen[k] = true
	}
	if len(seen) != len(required) {
		return ErrInvalidFrame
	}
	return nil
}

func validFrame(f *Frame, m map[string]any) bool {
	if f.Version != Version || f.Type != Type || !id(f.Binding.ShimLaunchUUID) || !id(f.Binding.GuestBootNonce) {
		return false
	}
	if f.Operation == "hello" {
		return exact(m, "version", "type", "operation", "binding", "data") && (exact(m["data"].(map[string]any)) || exact(m["data"].(map[string]any), "compatibilityProfile") && f.Data.CompatibilityProfile != nil && (*f.Data.CompatibilityProfile == preparecompat.Profile || *f.Data.CompatibilityProfile == preparecompat.EarlyProfile || *f.Data.CompatibilityProfile == preparecompat.FullProfile))
	}
	if f.Scope == nil || !validScope(*f.Scope) || f.Binding.ShimLaunchUUID != f.Scope.Launch {
		return false
	}
	keys := []string{"version", "type", "operation", "binding", "scope", "data"}
	if f.Operation == "command" || f.Operation == "reply" {
		keys = append(keys, "sequence", "kind")
		if f.Sequence == nil || *f.Sequence == 0 || !kind(f.Kind) {
			return false
		}
	}
	if !exact(m, keys...) {
		return false
	}
	dm := m["data"].(map[string]any)
	p := &f.Data
	switch f.Operation {
	case "configure":
		return exact(dm, "peer", "mounts", "slots") && validPeer(p.Peer) && ValidateConfiguration(*p.Mounts, *p.Slots) == nil
	case "prepare-early-checkpoint":
		return exact(dm, "compatibilityEarlyObservation") && p.CompatibilityEarlyObservation != nil && preparecompat.ValidateEarlyObservation(*p.CompatibilityEarlyObservation) == nil
	case "prepare-checkpoint":
		if p.CompatibilityIOObservation != nil {
			return exact(dm, "compatibilityIOObservation") && preparecompat.ValidateIOObservation(*p.CompatibilityIOObservation) == nil
		}
		return exact(dm, "compatibilityObservation") && p.CompatibilityObservation != nil && preparecompat.ValidateObservation(*p.CompatibilityObservation) == nil
	case "configured":
		return exact(dm)
	case "terminal":
		return exact(dm, "attachmentIDs", "code") && len(*p.AttachmentIDs) > 0 && uniqueIDs(*p.AttachmentIDs, 32) && code(*p.Code)
	case "command":
		switch f.Kind {
		case "prepare-compatibility-arm":
			return exact(dm, "compatibilityArm") && p.CompatibilityArm != nil && preparecompat.ValidateArm(*p.CompatibilityArm) == nil && p.CompatibilityArm.Binding == preparecompat.BootBinding(f.Binding) && p.CompatibilityArm.Scope == preparecompat.Scope(*f.Scope)
		case "offer-keys", "mount-phase", "close-phase":
			return exact(dm, "role") && role(*p.Role)
		case "install-certificate":
			return exact(dm, "attachment", "certificateDER") && id(*p.Attachment) && blob(*p.CertificateDER, 16384)
		case "prepare":
			return exact(dm, "workloadJSON", "ioClaim") && blob(*p.WorkloadJSON, MaximumWorkloadBytes) && text(*p.IOClaim) && SpecificationDigest(*p.WorkloadJSON) == f.Scope.SpecificationDigest
		case "start", "status", "abort":
			return exact(dm)
		}
	case "reply":
		if exact(dm, "code") {
			return code(*p.Code)
		}
		switch f.Kind {
		case "prepare-compatibility-arm":
			return exact(dm, "compatibilityDigest") && p.CompatibilityDigest != nil && pin(*p.CompatibilityDigest)
		case "offer-keys":
			if !exact(dm, "offers") || len(*p.Offers) > 64 {
				return false
			}
			seen := map[string]bool{}
			for _, o := range *p.Offers {
				if !id(o.Attachment) || !pin(o.Key) || !blob(o.CSRDER, 4096) || seen[o.Attachment] {
					return false
				}
				seen[o.Attachment] = true
			}
			return true
		case "install-certificate":
			return exact(dm, "attachment") && id(*p.Attachment)
		case "mount-phase":
			return exact(dm, "attachmentIDs") && uniqueIDs(*p.AttachmentIDs, 64)
		case "prepare":
			return exact(dm, "prepare", "containerInstance", "launch", "succeeded", "cleanCopyUp", "evidenceDigest") && *p.Prepare == f.Scope.Prepare && *p.ContainerInstance == f.Scope.ContainerInstance && *p.Launch == f.Scope.Launch && pin(*p.EvidenceDigest)
		case "close-phase":
			return exact(dm, "role", "attachmentIDs", "clean") && role(*p.Role) && uniqueIDs(*p.AttachmentIDs, 64)
		case "start":
			return exact(dm, "status", "pid") && *p.Status == "running" && *p.PID > 0 && *p.PID <= 2147483647
		case "status":
			if !exact(dm, "phase", "mountedIDs", "terminalIDs") || !phase(*p.Phase) || !uniqueIDs(*p.MountedIDs, 64) || !uniqueIDs(*p.TerminalIDs, 32) {
				return false
			}
			mounted := map[string]bool{}
			for _, s := range *p.MountedIDs {
				mounted[s] = true
			}
			for _, s := range *p.TerminalIDs {
				if mounted[s] {
					return false
				}
			}
			return true
		case "abort":
			return exact(dm, "terminalIDs") && uniqueIDs(*p.TerminalIDs, 32)
		}
	}
	return false
}
