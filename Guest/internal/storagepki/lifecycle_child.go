package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"

	// Dependency direction: storagepki depends on storageauthority's value-only
	// lifecycle DTOs and signing bytes. Do not introduce the reverse dependency.
	"dev.cengine/guest/internal/storageauthority"
)

const LifecycleChildVersion = "storage-child-lifecycle.v2"
const LifecycleChildLifetimeMS uint64 = 30_000
const MaxLifecycleChildSize = 64 << 10

const lifecycleChildChallengeDomain = "cengine.storage-child-lifecycle.challenge.v2\x00"
const lifecycleChildReplyDomain = "cengine.storage-child-lifecycle.reply.v2\x00"

type LifecycleChildPurpose string

const (
	LifecycleChildCandidate     LifecycleChildPurpose = "candidate"
	LifecycleChildResult        LifecycleChildPurpose = "result"
	LifecycleChildServiceResult LifecycleChildPurpose = "serviceResult"
	LifecycleChildServiceCommit LifecycleChildPurpose = "serviceCommit"
)

// LifecycleChildGreetingFields is a value-only DTO. Binary fields are canonical
// padded base64. Neither the DTO nor proof of its key authenticates a process.
type LifecycleChildGreetingFields struct {
	Version        string `json:"version"`
	ChannelID      string `json:"channel_id"`
	IncarnationID  string `json:"incarnation_id"`
	DaemonUniqueID uint64 `json:"daemon_unique_id"`
	ControllerSPKI string `json:"controller_spki"`
	RootPublicKey  string `json:"root_public_key"`
	Store          string `json:"store"`
	Binding        string `json:"binding"`
	ExpectedEpoch  uint64 `json:"expected_epoch"`
}

// LifecycleChildGreeting freezes the closed canonical wire. Zero values fail.
type LifecycleChildGreeting struct {
	fields    LifecycleChildGreetingFields
	canonical string
}

func NewLifecycleChildGreeting(f LifecycleChildGreetingFields) (LifecycleChildGreeting, error) {
	if f.Version != LifecycleChildVersion || f.DaemonUniqueID == 0 || f.ExpectedEpoch == ^uint64(0) || !uuid(f.ChannelID) || !uuid(f.IncarnationID) || !uuid(f.Store) || !container(f.Binding) {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	spki, ok := canonicalBase64(f.ControllerSPKI, 44)
	if !ok {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	public, err := x509.ParsePKIXPublicKey(spki)
	key, ok := public.(ed25519.PublicKey)
	if err != nil || !ok {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(der, spki) {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	root, ok := canonicalBase64(f.RootPublicKey, ed25519.PublicKeySize)
	if !ok {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	rootFingerprint, err := PublicKeyFingerprint(ed25519.PublicKey(root))
	if err != nil || rootFingerprint == sha256.Sum256(spki) {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	b, err := lifecycleChildCanonical(f)
	if err != nil {
		return LifecycleChildGreeting{}, err
	}
	return LifecycleChildGreeting{fields: f, canonical: string(b)}, nil
}

func DecodeLifecycleChildGreeting(payload []byte) (LifecycleChildGreeting, error) {
	var f LifecycleChildGreetingFields
	if !lifecycleChildDecode(payload, &f) {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	g, err := NewLifecycleChildGreeting(f)
	if err != nil || !bytes.Equal(payload, g.Canonical()) {
		return LifecycleChildGreeting{}, ErrInvalid
	}
	return g, nil
}

func (g LifecycleChildGreeting) Fields() LifecycleChildGreetingFields { return g.fields }
func (g LifecycleChildGreeting) Canonical() []byte                    { return []byte(g.canonical) }

func (g LifecycleChildGreeting) Matches(grant storageauthority.LifecycleGrant) bool {
	if g.canonical == "" || grant.Validate() != nil {
		return false
	}
	spki, _ := canonicalBase64(g.fields.ControllerSPKI, 44)
	fingerprint := Fingerprint(sha256.Sum256(spki))
	expected := g.fields.ExpectedEpoch
	if grant.Operation == storageauthority.LifecycleRetire {
		expected++ // Greeting validation reserves room for retire's successor epoch.
	}
	return string(grant.Identity.Store) == g.fields.Store && string(grant.Identity.Binding) == g.fields.Binding && string(grant.NewKey) == fingerprint.String() && grant.ExpectedEpoch == expected
}

// The full greeting and full ROOT grant are bound, not just their identifiers.
// No caller-owned slices or pointers are retained by the frozen challenge.
type LifecycleChildChallengeFields struct {
	Version       string                              `json:"version"`
	Greeting      LifecycleChildGreetingFields        `json:"greeting"`
	Grant         storageauthority.LifecycleGrant     `json:"grant"`
	ChildAudit    string                              `json:"child_audit"`
	ChildUniqueID uint64                              `json:"child_unique_id"`
	DaemonAudit   string                              `json:"daemon_audit"`
	Counter       uint64                              `json:"counter"`
	Nonce         string                              `json:"nonce"`
	Purpose       LifecycleChildPurpose               `json:"purpose"`
	Boot          *LifecycleBootTrustFields           `json:"boot,omitempty"`
	ChangeRequest *LifecycleServiceChangeRequest      `json:"change_request,omitempty"`
	Confirmation  *LifecycleServiceChangeConfirmation `json:"confirmation,omitempty"`
	ExpiresUnixMS uint64                              `json:"expires_unix_ms"`
}

type LifecycleChildChallenge struct {
	fields    LifecycleChildChallengeFields
	canonical string
}

// NewLifecycleChildChallenge validates shape, not freshness, so historical
// vectors can be decoded. Signing separately checks the real clock.
func NewLifecycleChildChallenge(f LifecycleChildChallengeFields) (LifecycleChildChallenge, error) {
	f.Boot = cloneLifecycleBootTrust(f.Boot)
	f.ChangeRequest = cloneLifecycleServiceChangeRequest(f.ChangeRequest)
	f.Confirmation = cloneLifecycleServiceChangeConfirmation(f.Confirmation)
	g, err := NewLifecycleChildGreeting(f.Greeting)
	if err != nil || f.Version != LifecycleChildVersion || !g.Matches(f.Grant) || f.ChildUniqueID == 0 || f.ChildUniqueID == f.Greeting.DaemonUniqueID || f.Counter == 0 || f.ExpiresUnixMS == 0 {
		return LifecycleChildChallenge{}, ErrInvalid
	}
	switch f.Purpose {
	case LifecycleChildCandidate:
		if f.Boot != nil || f.ChangeRequest != nil || f.Confirmation != nil {
			return LifecycleChildChallenge{}, ErrInvalid
		}
	case LifecycleChildResult, LifecycleChildServiceResult, LifecycleChildServiceCommit:
		if f.Boot == nil {
			return LifecycleChildChallenge{}, ErrInvalid
		}
		boot, err := NewLifecycleBootTrust(*f.Boot)
		root, _ := canonicalBase64(f.Greeting.RootPublicKey, ed25519.PublicKeySize)
		fingerprint, fingerprintErr := PublicKeyFingerprint(ed25519.PublicKey(root))
		if err != nil || !boot.MatchesGrant(f.Grant) || fingerprintErr != nil || f.Boot.BootstrapKey != fingerprint.String() {
			return LifecycleChildChallenge{}, ErrInvalid
		}
		switch f.Purpose {
		case LifecycleChildResult:
			if f.ChangeRequest != nil || f.Confirmation != nil {
				return LifecycleChildChallenge{}, ErrInvalid
			}
		case LifecycleChildServiceResult:
			if f.Grant.Operation == storageauthority.LifecycleRetire || f.Confirmation != nil {
				return LifecycleChildChallenge{}, ErrInvalid
			}
			if f.ChangeRequest != nil && (f.ChangeRequest.ValidateSuccessorBoot(*f.Boot) != nil || f.ChangeRequest.Predecessor.Grant != f.Grant) {
				return LifecycleChildChallenge{}, ErrInvalid
			}
		case LifecycleChildServiceCommit:
			if f.ChangeRequest != nil || f.Confirmation == nil || f.Confirmation.Validate() != nil || f.Confirmation.Successor.Grant != f.Grant || f.Confirmation.Successor.Boot != *f.Boot {
				return LifecycleChildChallenge{}, ErrInvalid
			}
		}
	default:
		return LifecycleChildChallenge{}, ErrInvalid
	}
	for _, field := range []string{f.ChildAudit, f.DaemonAudit, f.Nonce} {
		if _, ok := canonicalBase64(field, 32); !ok {
			return LifecycleChildChallenge{}, ErrInvalid
		}
	}
	b, err := lifecycleChildCanonical(f)
	if err != nil {
		return LifecycleChildChallenge{}, err
	}
	return LifecycleChildChallenge{fields: f, canonical: string(b)}, nil
}

func DecodeLifecycleChildChallenge(payload []byte) (LifecycleChildChallenge, error) {
	var f LifecycleChildChallengeFields
	if !lifecycleChildDecode(payload, &f) {
		return LifecycleChildChallenge{}, ErrInvalid
	}
	c, err := NewLifecycleChildChallenge(f)
	if err != nil || !bytes.Equal(payload, c.Canonical()) {
		return LifecycleChildChallenge{}, ErrInvalid
	}
	return c, nil
}

func (c LifecycleChildChallenge) Fields() LifecycleChildChallengeFields {
	f := c.fields
	f.Boot = cloneLifecycleBootTrust(f.Boot)
	f.ChangeRequest = cloneLifecycleServiceChangeRequest(f.ChangeRequest)
	f.Confirmation = cloneLifecycleServiceChangeConfirmation(f.Confirmation)
	return f
}
func (c LifecycleChildChallenge) Canonical() []byte { return []byte(c.canonical) }
func (c LifecycleChildChallenge) IsFresh(unixMS uint64) bool {
	return c.canonical != "" && c.fields.ExpiresUnixMS > unixMS && c.fields.ExpiresUnixMS-unixMS <= LifecycleChildLifetimeMS
}
func (c LifecycleChildChallenge) Digest() []byte {
	if c.canonical == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(lifecycleChildChallengeDomain + c.canonical))
	return digest[:]
}

type LifecycleChildReplyFields struct {
	Version         string                                   `json:"version"`
	ChallengeSHA256 string                                   `json:"challenge_sha256"`
	Receipt         *storageauthority.LifecycleReceipt       `json:"receipt,omitempty"`
	ServiceResult   *storageauthority.LifecycleServiceResult `json:"service_result,omitempty"`
	Signature       string                                   `json:"signature"`
}

// LifecycleChildReply proves controller-key possession over a typed challenge
// and optional result, NOT authentication, a fresh TLS result, or storage drain.
// The future private child coordinator must obtain and correlate that TLS result
// independently before requesting a result signature; persisted DTOs cannot do so.
type LifecycleChildReply struct {
	fields    LifecycleChildReplyFields
	canonical string
}

func cloneLifecycleChildReceipt(r *storageauthority.LifecycleReceipt) *storageauthority.LifecycleReceipt {
	if r == nil {
		return nil
	}
	copy := *r
	copy.Nonce = bytes.Clone(r.Nonce)
	return &copy
}

func cloneLifecycleChildServiceResult(r *storageauthority.LifecycleServiceResult) *storageauthority.LifecycleServiceResult {
	if r == nil {
		return nil
	}
	copy := *r
	copy.Nonce = bytes.Clone(r.Nonce)
	return &copy
}

func NewLifecycleChildReply(f LifecycleChildReplyFields) (LifecycleChildReply, error) {
	f.Receipt = cloneLifecycleChildReceipt(f.Receipt)
	f.ServiceResult = cloneLifecycleChildServiceResult(f.ServiceResult)
	if f.Version != LifecycleChildVersion {
		return LifecycleChildReply{}, ErrInvalid
	}
	if _, ok := canonicalBase64(f.ChallengeSHA256, 32); !ok {
		return LifecycleChildReply{}, ErrInvalid
	}
	if _, ok := canonicalBase64(f.Signature, ed25519.SignatureSize); !ok {
		return LifecycleChildReply{}, ErrInvalid
	}
	if (f.Receipt != nil && f.ServiceResult != nil) || (f.ServiceResult != nil && f.ServiceResult.Validate() != nil) || (f.Receipt != nil && f.Receipt.Validate() != nil) {
		return LifecycleChildReply{}, ErrInvalid
	}
	b, err := lifecycleChildCanonical(f)
	if err != nil {
		return LifecycleChildReply{}, err
	}
	return LifecycleChildReply{fields: f, canonical: string(b)}, nil
}

func DecodeLifecycleChildReply(payload []byte) (LifecycleChildReply, error) {
	var f LifecycleChildReplyFields
	if !lifecycleChildDecode(payload, &f) {
		return LifecycleChildReply{}, ErrInvalid
	}
	r, err := NewLifecycleChildReply(f)
	if err != nil || !bytes.Equal(payload, r.Canonical()) {
		return LifecycleChildReply{}, ErrInvalid
	}
	return r, nil
}

func (r LifecycleChildReply) Fields() LifecycleChildReplyFields {
	f := r.fields
	f.Receipt = cloneLifecycleChildReceipt(f.Receipt)
	f.ServiceResult = cloneLifecycleChildServiceResult(f.ServiceResult)
	return f
}
func (r LifecycleChildReply) Canonical() []byte { return []byte(r.canonical) }
func (r LifecycleChildReply) SigningBytes() []byte {
	if r.canonical == "" {
		return nil
	}
	digest, _ := canonicalBase64(r.fields.ChallengeSHA256, 32)
	b := append([]byte(lifecycleChildReplyDomain), digest...)
	if r.fields.ServiceResult != nil {
		result, err := storageauthority.LifecycleServiceResultSigningBytes(*r.fields.ServiceResult)
		if err != nil {
			return nil
		}
		b = append(b, []byte("service-result\x00")...)
		return append(b, result...)
	}
	if r.fields.Receipt == nil {
		return append(b, []byte("candidate\x00")...)
	}
	// Use the actual lifecycle receipt contract, including declaration-order JSON.
	receipt, err := storageauthority.LifecycleReceiptSigningBytes(*r.fields.Receipt)
	if err != nil {
		return nil
	}
	b = append(b, []byte("result\x00")...)
	return append(b, receipt...)
}

func lifecycleChildReceiptMatches(c LifecycleChildChallenge, receipt *storageauthority.LifecycleReceipt) bool {
	switch c.fields.Purpose {
	case LifecycleChildCandidate:
		return receipt == nil
	case LifecycleChildResult:
		nonce, _ := canonicalBase64(c.fields.Nonce, 32)
		return receipt != nil && receipt.Validate() == nil && receipt.Grant == c.fields.Grant && bytes.Equal(receipt.Nonce, nonce) && c.fields.Boot != nil && string(receipt.ServiceEpoch) == c.fields.Boot.ServiceEpoch
	default:
		return false
	}
}

func lifecycleChildReplyMatches(c LifecycleChildChallenge, receipt *storageauthority.LifecycleReceipt, result *storageauthority.LifecycleServiceResult) bool {
	if c.fields.Purpose != LifecycleChildServiceResult && c.fields.Purpose != LifecycleChildServiceCommit {
		return result == nil && lifecycleChildReceiptMatches(c, receipt)
	}
	nonce, _ := canonicalBase64(c.fields.Nonce, 32)
	if receipt != nil || result == nil || c.fields.Boot == nil || result.Grant != c.fields.Grant || !bytes.Equal(result.Nonce, nonce) || string(result.ServiceEpoch) != c.fields.Boot.ServiceEpoch {
		return false
	}
	state, err := LifecycleServiceStateFromResult(*result, *c.fields.Boot)
	if err != nil {
		return false
	}
	if change := c.fields.ChangeRequest; change != nil {
		confirmation := LifecycleServiceChangeConfirmation{Request: *change, Successor: state}
		if confirmation.Validate() != nil {
			return false
		}
	}
	return c.fields.Confirmation == nil || c.fields.Confirmation.Successor == state
}

// Verifies checks only the signature and challenge/result correlation, not time,
// message-sender authentication, counter consumption, or the source of a result.
func (r LifecycleChildReply) Verifies(c LifecycleChildChallenge) bool {
	if r.canonical == "" || c.canonical == "" || !lifecycleChildReplyMatches(c, r.fields.Receipt, r.fields.ServiceResult) {
		return false
	}
	digest, _ := canonicalBase64(r.fields.ChallengeSHA256, 32)
	if !bytes.Equal(digest, c.Digest()) {
		return false
	}
	spki, _ := canonicalBase64(c.fields.Greeting.ControllerSPKI, 44)
	signature, _ := canonicalBase64(r.fields.Signature, ed25519.SignatureSize)
	return ed25519.Verify(ed25519.PublicKey(spki[12:]), r.SigningBytes(), signature)
}

// SignLifecycleChildReply is intentionally not a generic-message signing API or
// crypto.Signer. Only the generated controller key matching both greeting SPKI
// and grant fingerprint can sign. A nil receipt is required for candidate; result
// requires the exact challenge grant and nonce. This does NOT attest that a DTO
// came from authenticated TLS: that belongs to the future private coordinator.
func (k Key) SignLifecycleChildReply(c LifecycleChildChallenge, receipt *storageauthority.LifecycleReceipt) (LifecycleChildReply, error) {
	return k.signLifecycleChildReply(c, receipt, nil)
}

// SignLifecycleChildServiceReply signs only a correlated live service result or
// commit. The caller must independently authenticate the result's TLS source.
func (k Key) SignLifecycleChildServiceReply(c LifecycleChildChallenge, result *storageauthority.LifecycleServiceResult) (LifecycleChildReply, error) {
	if c.fields.Purpose != LifecycleChildServiceResult && c.fields.Purpose != LifecycleChildServiceCommit {
		return LifecycleChildReply{}, ErrInvalid
	}
	return k.signLifecycleChildReply(c, nil, result)
}

func (k Key) signLifecycleChildReply(c LifecycleChildChallenge, receipt *storageauthority.LifecycleReceipt, result *storageauthority.LifecycleServiceResult) (LifecycleChildReply, error) {
	if !k.valid || k.role != ControllerRole || c.canonical == "" {
		return LifecycleChildReply{}, ErrInvalid
	}
	checked, err := NewLifecycleChildChallenge(c.fields)
	if err != nil || checked.canonical != c.canonical {
		return LifecycleChildReply{}, ErrInvalid
	}
	now := time.Now().UnixMilli()
	if now < 0 || !c.IsFresh(uint64(now)) {
		return LifecycleChildReply{}, ErrInvalid
	}
	spki, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil || c.fields.Greeting.ControllerSPKI != base64.StdEncoding.EncodeToString(spki) {
		return LifecycleChildReply{}, ErrInvalid
	}
	receipt = cloneLifecycleChildReceipt(receipt)
	result = cloneLifecycleChildServiceResult(result)
	if !lifecycleChildReplyMatches(c, receipt, result) {
		return LifecycleChildReply{}, ErrInvalid
	}
	f := LifecycleChildReplyFields{Version: LifecycleChildVersion, ChallengeSHA256: base64.StdEncoding.EncodeToString(c.Digest()), Receipt: receipt, ServiceResult: result, Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	r, err := NewLifecycleChildReply(f)
	if err != nil {
		return LifecycleChildReply{}, err
	}
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.private(), r.SigningBytes()))
	return NewLifecycleChildReply(f)
}

// Sorting through json.Number preserves every uint64 digit, unlike decoding
// into float64. Re-encoding the validated typed DTO closes schemas recursively:
// duplicate/unknown/missing keys, null receipt, alternate spelling and whitespace
// all fail exact comparison. This helper never handles unvalidated raw input.
func lifecycleChildCanonical(value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil || len(b) > MaxLifecycleChildSize {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var sorted any
	if decoder.Decode(&sorted) != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(sorted)
}

func lifecycleChildDecode(payload []byte, value any) bool {
	return len(payload) > 0 && len(payload) <= MaxLifecycleChildSize && json.Unmarshal(payload, value) == nil
}
