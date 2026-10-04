package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"
)

const RootChallengeVersion = "root-proof.v1"
const MaxRootChallengeSize = 4 << 10
const rootChallengePrefix = "cengine.storagebootstrap.root-proof.v1\x00"

type RootChallengePurpose string

const (
	RootInitial  RootChallengePurpose = "initial"
	RootTakeover RootChallengePurpose = "takeover"
	RootConfirm  RootChallengePurpose = "confirm"
)

// RootChallengeFields contains only values, not slices or caller-owned objects.
// Binary values use canonical padded standard base64. IDs are canonical UUIDv4.
// Declaration order is the frozen lexical JSON key order; do not reorder fields.
// ExpectedEpoch and process unique IDs retain the full unsigned 64-bit range.
type RootChallengeFields struct {
	ChildAudit       string               `json:"child_audit"`
	ChildUniqueID    uint64               `json:"child_unique_id"`
	ControllerSPKI   string               `json:"controller_spki"`
	DaemonAudit      string               `json:"daemon_audit"`
	DaemonUniqueID   uint64               `json:"daemon_unique_id"`
	ExpectedEpoch    uint64               `json:"expected_epoch"`
	ExpiresUnixMS    uint64               `json:"expires_unix_ms"`
	GrantID          string               `json:"grant_id"`
	IncarnationID    string               `json:"incarnation_id"`
	Nonce            string               `json:"nonce"`
	Purpose          RootChallengePurpose `json:"purpose"`
	RequestID        string               `json:"request_id"`
	ServiceEpoch     ServiceEpoch         `json:"service_epoch"`
	Store            StoreID              `json:"store"`
	TranscriptSHA256 string               `json:"transcript_sha256"`
	Version          string               `json:"version"`
}

// RootChallenge freezes the exact signed representation. Its zero value fails.
// This proves controller key possession, not privileged-root authorization.
type RootChallenge struct {
	fields    RootChallengeFields
	canonical string
}

func canonicalBase64(s string, size int) ([]byte, bool) {
	if len(s) != base64.StdEncoding.EncodedLen(size) {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) == size && base64.StdEncoding.EncodeToString(b) == s
}

// NewRootChallenge validates schema, not time: decoding historical evidence is
// permitted. SignRootChallenge separately enforces expiry against the real clock.
func NewRootChallenge(f RootChallengeFields) (RootChallenge, error) {
	if f.Version != RootChallengeVersion || f.ChildUniqueID == 0 || f.DaemonUniqueID == 0 || f.ExpectedEpoch == 0 || f.ExpiresUnixMS == 0 || !uuid(f.GrantID) || !uuid(f.IncarnationID) || !uuid(f.RequestID) || !uuid(string(f.ServiceEpoch)) || !uuid(string(f.Store)) {
		return RootChallenge{}, ErrInvalid
	}
	for _, s := range []string{f.ChildAudit, f.DaemonAudit, f.Nonce} {
		if _, ok := canonicalBase64(s, 32); !ok {
			return RootChallenge{}, ErrInvalid
		}
	}
	spki, ok := canonicalBase64(f.ControllerSPKI, 44)
	if !ok {
		return RootChallenge{}, ErrInvalid
	}
	public, err := x509.ParsePKIXPublicKey(spki)
	key, ok := public.(ed25519.PublicKey)
	if err != nil || !ok {
		return RootChallenge{}, ErrInvalid
	}
	canonicalSPKI, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(canonicalSPKI, spki) {
		return RootChallenge{}, ErrInvalid
	}
	switch f.Purpose {
	case RootInitial:
		if f.ExpectedEpoch != 1 || f.GrantID != f.RequestID || f.TranscriptSHA256 != "" {
			return RootChallenge{}, ErrInvalid
		}
	case RootTakeover:
		if f.TranscriptSHA256 != "" {
			return RootChallenge{}, ErrInvalid
		}
	case RootConfirm:
		if !container(f.TranscriptSHA256) {
			return RootChallenge{}, ErrInvalid
		}
	default:
		return RootChallenge{}, ErrInvalid
	}
	b, err := json.Marshal(f)
	if err != nil || len(b) > MaxRootChallengeSize {
		return RootChallenge{}, ErrInvalid
	}
	return RootChallenge{fields: f, canonical: string(b)}, nil
}

// DecodeRootChallenge rejects every alternate encoding, including duplicate or
// missing keys, unknown fields, whitespace, trailing values, and number coercion.
func DecodeRootChallenge(payload []byte) (RootChallenge, error) {
	if len(payload) == 0 || len(payload) > MaxRootChallengeSize {
		return RootChallenge{}, ErrInvalid
	}
	var fields RootChallengeFields
	if json.Unmarshal(payload, &fields) != nil {
		return RootChallenge{}, ErrInvalid
	}
	c, err := NewRootChallenge(fields)
	if err != nil || !bytes.Equal(payload, c.Canonical()) {
		return RootChallenge{}, ErrInvalid
	}
	return c, nil
}

func (c RootChallenge) Fields() RootChallengeFields { return c.fields }
func (c RootChallenge) Canonical() []byte           { return []byte(c.canonical) }
func (c RootChallenge) SigningBytes() []byte {
	if c.canonical == "" {
		return nil
	}
	return []byte(rootChallengePrefix + c.canonical)
}

// SignRootChallenge is deliberately NOT a general signing oracle/crypto.Signer.
// The transport must independently authenticate the privileged ROOT peer and
// compare frozen store/incarnation/process audit linkage before requesting proof.
func (k Key) SignRootChallenge(c RootChallenge) ([]byte, error) {
	if !k.valid || k.role != ControllerRole || c.canonical == "" {
		return nil, ErrInvalid
	}
	checked, err := NewRootChallenge(c.fields)
	if err != nil || checked != c {
		return nil, ErrInvalid
	}
	now := time.Now().UnixMilli()
	if now < 0 || c.fields.ExpiresUnixMS <= uint64(now) {
		return nil, ErrInvalid
	}
	spki, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil || c.fields.ControllerSPKI != base64.StdEncoding.EncodeToString(spki) {
		return nil, ErrInvalid
	}
	return ed25519.Sign(k.private(), c.SigningBytes()), nil
}
