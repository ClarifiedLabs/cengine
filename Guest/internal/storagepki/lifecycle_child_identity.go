package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"
)

const LifecycleChildIdentityVersion = "storage-child-identity.v1"
const lifecycleChildIdentityChallengeDomain = "cengine.storage-child-identity.challenge.v1\x00"
const lifecycleChildIdentityReplyDomain = "cengine.storage-child-identity.reply.v1\x00"

type LifecycleChildIdentityChallengeFields struct {
	Version       string                       `json:"version"`
	Greeting      LifecycleChildGreetingFields `json:"greeting"`
	ChildAudit    string                       `json:"child_audit"`
	ChildUniqueID uint64                       `json:"child_unique_id"`
	DaemonAudit   string                       `json:"daemon_audit"`
	Counter       uint64                       `json:"counter"`
	Nonce         string                       `json:"nonce"`
	RequestSHA256 string                       `json:"request_sha256"`
	ExpiresUnixMS uint64                       `json:"expires_unix_ms"`
}
type LifecycleChildIdentityChallenge struct {
	fields    LifecycleChildIdentityChallengeFields
	canonical string
}

func NewLifecycleChildIdentityChallenge(f LifecycleChildIdentityChallengeFields) (LifecycleChildIdentityChallenge, error) {
	if _, err := NewLifecycleChildGreeting(f.Greeting); err != nil {
		return LifecycleChildIdentityChallenge{}, ErrInvalid
	}
	if f.Version != LifecycleChildIdentityVersion || f.ChildUniqueID == 0 || f.ChildUniqueID == f.Greeting.DaemonUniqueID || f.ChildAudit == f.DaemonAudit || f.Counter == 0 || f.ExpiresUnixMS == 0 {
		return LifecycleChildIdentityChallenge{}, ErrInvalid
	}
	for _, v := range []string{f.ChildAudit, f.DaemonAudit, f.Nonce, f.RequestSHA256} {
		if _, ok := canonicalBase64(v, 32); !ok {
			return LifecycleChildIdentityChallenge{}, ErrInvalid
		}
	}
	b, err := lifecycleChildCanonical(f)
	if err != nil {
		return LifecycleChildIdentityChallenge{}, err
	}
	return LifecycleChildIdentityChallenge{f, string(b)}, nil
}
func DecodeLifecycleChildIdentityChallenge(b []byte) (LifecycleChildIdentityChallenge, error) {
	var f LifecycleChildIdentityChallengeFields
	if !lifecycleChildDecode(b, &f) {
		return LifecycleChildIdentityChallenge{}, ErrInvalid
	}
	c, e := NewLifecycleChildIdentityChallenge(f)
	if e != nil || !bytes.Equal(b, c.Canonical()) {
		return LifecycleChildIdentityChallenge{}, ErrInvalid
	}
	return c, nil
}
func (c LifecycleChildIdentityChallenge) Fields() LifecycleChildIdentityChallengeFields {
	return c.fields
}
func (c LifecycleChildIdentityChallenge) Canonical() []byte { return []byte(c.canonical) }
func (c LifecycleChildIdentityChallenge) IsFresh(now uint64) bool {
	return c.canonical != "" && c.fields.ExpiresUnixMS > now && c.fields.ExpiresUnixMS-now <= LifecycleChildLifetimeMS
}
func (c LifecycleChildIdentityChallenge) Digest() []byte {
	if c.canonical == "" {
		return nil
	}
	d := sha256.Sum256([]byte(lifecycleChildIdentityChallengeDomain + c.canonical))
	return d[:]
}

type LifecycleChildIdentityReplyFields struct {
	Version         string `json:"version"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	Signature       string `json:"signature"`
}
type LifecycleChildIdentityReply struct {
	fields    LifecycleChildIdentityReplyFields
	canonical string
}

func NewLifecycleChildIdentityReply(f LifecycleChildIdentityReplyFields) (LifecycleChildIdentityReply, error) {
	if f.Version != LifecycleChildIdentityVersion {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	if _, ok := canonicalBase64(f.ChallengeSHA256, 32); !ok {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	if _, ok := canonicalBase64(f.Signature, 64); !ok {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	b, e := lifecycleChildCanonical(f)
	if e != nil {
		return LifecycleChildIdentityReply{}, e
	}
	return LifecycleChildIdentityReply{f, string(b)}, nil
}
func DecodeLifecycleChildIdentityReply(b []byte) (LifecycleChildIdentityReply, error) {
	var f LifecycleChildIdentityReplyFields
	if !lifecycleChildDecode(b, &f) {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	r, e := NewLifecycleChildIdentityReply(f)
	if e != nil || !bytes.Equal(b, r.Canonical()) {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	return r, nil
}
func (r LifecycleChildIdentityReply) Canonical() []byte { return []byte(r.canonical) }
func (r LifecycleChildIdentityReply) SigningBytes() []byte {
	if r.canonical == "" {
		return nil
	}
	d, _ := canonicalBase64(r.fields.ChallengeSHA256, 32)
	return append([]byte(lifecycleChildIdentityReplyDomain), d...)
}
func (r LifecycleChildIdentityReply) Verifies(c LifecycleChildIdentityChallenge) bool {
	if r.canonical == "" || c.canonical == "" {
		return false
	}
	d, _ := canonicalBase64(r.fields.ChallengeSHA256, 32)
	if !bytes.Equal(d, c.Digest()) {
		return false
	}
	spki, _ := canonicalBase64(c.fields.Greeting.ControllerSPKI, 44)
	sig, _ := canonicalBase64(r.fields.Signature, 64)
	return ed25519.Verify(ed25519.PublicKey(spki[12:]), r.SigningBytes(), sig)
}
func (k Key) SignLifecycleChildIdentityReply(c LifecycleChildIdentityChallenge) (LifecycleChildIdentityReply, error) {
	if !k.valid || k.role != ControllerRole || !c.IsFresh(uint64(time.Now().UnixMilli())) {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	checked, e := NewLifecycleChildIdentityChallenge(c.fields)
	if e != nil || checked.canonical != c.canonical {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	spki, e := x509.MarshalPKIXPublicKey(k.PublicKey())
	if e != nil || c.fields.Greeting.ControllerSPKI != base64.StdEncoding.EncodeToString(spki) {
		return LifecycleChildIdentityReply{}, ErrInvalid
	}
	f := LifecycleChildIdentityReplyFields{LifecycleChildIdentityVersion, base64.StdEncoding.EncodeToString(c.Digest()), base64.StdEncoding.EncodeToString(make([]byte, 64))}
	r, e := NewLifecycleChildIdentityReply(f)
	if e != nil {
		return r, e
	}
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.private(), r.SigningBytes()))
	return NewLifecycleChildIdentityReply(f)
}

// Closed family discriminator only. Each selected decoder then requires exact
// canonical bytes, rejecting duplicates, unknown fields and cross-family payloads.
func LifecycleChildProofVersion(b []byte) (string, error) {
	var f struct {
		Version string `json:"version"`
	}
	if len(b) == 0 || len(b) > MaxLifecycleChildSize || json.Unmarshal(b, &f) != nil {
		return "", ErrInvalid
	}
	switch f.Version {
	case LifecycleChildVersion, LifecycleChildIdentityVersion:
		return f.Version, nil
	default:
		return "", ErrInvalid
	}
}
