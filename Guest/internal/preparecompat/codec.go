package preparecompat

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalidFrame = errors.New("prepare-compatibility")

func validStrings(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return v.IsNil() || validStrings(v.Elem())
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if !validStrings(k) || !validStrings(v.MapIndex(k)) {
				return false
			}
		}
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
	if typ == reflect.TypeOf(DrainCut{}) {
		return closed(v, reflect.TypeOf(drainCutJSON{}))
	}
	if typ == reflect.TypeOf(BoundCut{}) {
		return closed(v, reflect.TypeOf(boundCutJSON{}))
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

// CanonicalJSON preserves integers, never uses HTML escaping, and follows the
// Go/Swift frozen U+2028/U+2029 rule. Object keys are sorted recursively by Go's
// map encoder; no DTO field names depend on Unicode collation.
func CanonicalJSON(v any) ([]byte, error) {
	if !validStrings(reflect.ValueOf(v)) {
		return nil, ErrInvalidFrame
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return nil, ErrInvalidFrame
	}
	d := json.NewDecoder(bytes.NewReader(b.Bytes()))
	d.UseNumber()
	var tree any
	if d.Decode(&tree) != nil {
		return nil, ErrInvalidFrame
	}
	b.Reset()
	if e.Encode(tree) != nil {
		return nil, ErrInvalidFrame
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
func decode(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max || !validUnicode(raw) {
		return ErrInvalidFrame
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tree, err := value(d, 0)
	if err != nil {
		return ErrInvalidFrame
	}
	if _, err = d.Token(); err != io.EOF || !closed(tree, reflect.TypeOf(out)) {
		return ErrInvalidFrame
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrInvalidFrame
	}
	return nil
}
func normalize(a Arm) Arm {
	a.Mounts = append([]MountBinding{}, a.Mounts...)
	a.Slots = append([]Slot{}, a.Slots...)
	a.Credentials = append([]Credential{}, a.Credentials...)
	sort.Slice(a.Mounts, func(i, j int) bool { return a.Mounts[i].Index < a.Mounts[j].Index })
	sort.Slice(a.Slots, func(i, j int) bool { return a.Slots[i].Attachment < a.Slots[j].Attachment })
	sort.Slice(a.Credentials, func(i, j int) bool { return a.Credentials[i].Attachment < a.Credentials[j].Attachment })
	return a
}
func ValidateArm(a Arm) error {
	if a.CaseName == "vm-two-volume-drain-reply-gap" {
		if len(a.Mounts) != 2 || len(a.Slots) != 4 || len(a.Credentials) != 2 || a.Mounts[0].Volume == a.Mounts[1].Volume || a.Mounts[0].Destination == a.Mounts[1].Destination {
			return ErrInvalidFrame
		}
		for _, m := range a.Mounts {
			if m.NoCopy || m.Subpath != "" || m.Mode != "read-write" {
				return ErrInvalidFrame
			}
		}
	}

	if isVMCase(a.CaseName) && (len(a.Mounts) != 1 || len(a.Slots) != 2 || len(a.Credentials) != 1) {
		return ErrInvalidFrame
	}
	if !validArmProfile(a) || !id(a.RequestID) || !id(a.TargetAttachment) || !id(a.Binding.ShimLaunchUUID) || !id(a.Binding.GuestBootNonce) || a.Binding.ShimLaunchUUID != a.Scope.Launch || !validScope(a.Scope) || a.Mounts == nil || a.Slots == nil || a.Credentials == nil || len(a.Credentials) > 64 || ValidateConfiguration(a.Mounts, a.Slots) != nil {
		return ErrInvalidFrame
	}
	prepare := map[string]bool{}
	targetVolume := ""
	for _, s := range a.Slots {
		if s.Role == "prepare" {
			prepare[s.Attachment] = true
		}
		if s.Attachment == a.TargetAttachment && s.Role == "prepare" && s.Mode == "read-write" {
			targetVolume = s.Volume
		}
	}
	if targetVolume == "" || len(prepare) != len(a.Credentials) {
		return ErrInvalidFrame
	}
	keys := map[string]bool{}
	certs := map[string]bool{}
	for _, c := range a.Credentials {
		if !prepare[c.Attachment] || !pin(c.Key) || !pin(c.CertificateSHA256) || keys[c.Key] || certs[c.CertificateSHA256] {
			return ErrInvalidFrame
		}
		delete(prepare, c.Attachment)
		keys[c.Key] = true
		certs[c.CertificateSHA256] = true
	}
	targetMounts := 0
	for _, m := range a.Mounts {
		if m.Volume == targetVolume {
			if m.NoCopy || m.Subpath != "" || m.Mode != "read-write" {
				return ErrInvalidFrame
			}
			targetMounts++
		}
	}
	raw, err := CanonicalJSON(normalize(a))
	if err != nil || len(raw) > MaximumArmBytes {
		return ErrInvalidFrame
	}
	if targetMounts != 1 {
		return ErrInvalidFrame
	}
	return nil
}
func CanonicalArmData(a Arm) ([]byte, error) {
	if ValidateArm(a) != nil {
		return nil, ErrInvalidFrame
	}
	b, err := CanonicalJSON(normalize(a))
	if err != nil || len(b) > MaximumArmBytes {
		return nil, ErrInvalidFrame
	}
	return b, nil
}
func ArmDigest(a Arm) (string, error) {
	b, err := CanonicalArmData(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func DecodeArm(raw []byte) (Arm, error) {
	var a Arm
	if decode(raw, &a, MaximumArmBytes) != nil || ValidateArm(a) != nil {
		return Arm{}, ErrInvalidFrame
	}
	return a, nil
}
func (o ObjectIdentity) Valid() bool {
	b, err := hex.DecodeString(o.Handle)
	return err == nil && len(b) == 8 && hex.EncodeToString(b) == o.Handle && o.Inode > 0 && o.Inode <= uint64(^uint32(0)) && uint64(binary.LittleEndian.Uint32(b[:4])) == o.Inode && binary.LittleEndian.Uint32(b[4:]) == o.Generation && (o.FileType == 16384 || o.FileType == 32768)
}
func ValidateObservation(o Observation) error {
	fs, err := hex.DecodeString(o.FilesystemUUID)
	if !o.SourceAtimes.Valid() || !validPhysicalProfile(o.Version, o.Profile) || !id(o.RequestID) || !pin(o.ArmDigest) || (o.Stage != "first-child-published" && !(o.Version == 3 && o.Profile == FullProfile && o.Stage == "vm-root-synced-before-cleanup")) || o.Count != 1 || !id(o.TargetAttachment) || !id(o.CopyIntent) || err != nil || len(fs) != 16 || hex.EncodeToString(fs) != o.FilesystemUUID || bytes.Equal(fs, make([]byte, 16)) || !pin(o.ManifestDigest) || o.ManifestSize == 0 || o.ManifestSize > 64<<20 {
		return ErrInvalidFrame
	}
	if !o.Root.Valid() || !o.Transaction.Valid() || !o.Published.Valid() || !o.Staged.Valid() || o.Root.FileType != 16384 || o.Transaction.FileType != 16384 || o.Published.FileType != 32768 || o.Staged.FileType != 32768 {
		return ErrInvalidFrame
	}
	b, err := CanonicalJSON(o)
	if err != nil || len(b) > MaximumObservationBytes {
		return ErrInvalidFrame
	}
	return nil
}
func DecodeObservation(raw []byte) (Observation, error) {
	var o Observation
	if decode(raw, &o, MaximumObservationBytes) != nil || ValidateObservation(o) != nil {
		return Observation{}, ErrInvalidFrame
	}
	return o, nil
}
