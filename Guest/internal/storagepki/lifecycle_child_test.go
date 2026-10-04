package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"dev.cengine/guest/internal/storageauthority"
)

const lifecycleChildFixturePath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-child-v2.json"

// RFC 8032 public test seeds ONLY. No API for importing/exporting production
// controller private keys is added by these deterministic cross-language vectors.
const lifecycleChildControllerSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
const lifecycleChildRootSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// Fixture schema: the five named messages are ordinary JSON objects. *_canonical_json
// strings are their exact closed sorted-key transport; *_sha256 and *_signing_bytes
// are padded base64 of raw digests/bytes (not textual hex). uint64 stays integral.
type lifecycleChildFixture struct {
	Version                  string                        `json:"version"`
	ControllerSeedHex        string                        `json:"controller_seed_hex"`
	RootSeedHex              string                        `json:"root_seed_hex"`
	Greeting                 LifecycleChildGreetingFields  `json:"greeting"`
	Challenge                LifecycleChildChallengeFields `json:"challenge"`
	CandidateReply           LifecycleChildReplyFields     `json:"candidate_reply"`
	ResultChallenge          LifecycleChildChallengeFields `json:"result_challenge"`
	ResultReply              LifecycleChildReplyFields     `json:"result_reply"`
	GreetingCanonicalJSON    string                        `json:"greeting_canonical_json"`
	ChallengeCanonicalJSON   string                        `json:"challenge_canonical_json"`
	CandidateCanonicalJSON   string                        `json:"candidate_reply_canonical_json"`
	ResultChallengeCanonical string                        `json:"result_challenge_canonical_json"`
	ResultReplyCanonicalJSON string                        `json:"result_reply_canonical_json"`
	ChallengeSHA256          []byte                        `json:"challenge_sha256"`
	ResultChallengeSHA256    []byte                        `json:"result_challenge_sha256"`
	CandidateSigningBytes    []byte                        `json:"candidate_signing_bytes"`
	ResultSigningBytes       []byte                        `json:"result_signing_bytes"`
}

func lifecycleChildVectorFields(t *testing.T) (Key, LifecycleChildChallengeFields) {
	t.Helper()
	seed, err := hex.DecodeString(lifecycleChildControllerSeed)
	if err != nil {
		t.Fatal(err)
	}
	k := Key{role: ControllerRole, valid: true}
	copy(k.seed[:], seed)
	rootSeed, _ := hex.DecodeString(lifecycleChildRootSeed)
	root := ed25519.NewKeyFromSeed(rootSeed).Public().(ed25519.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	fp, err := k.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	greeting := LifecycleChildGreetingFields{
		Version:        LifecycleChildVersion,
		ChannelID:      "11111111-1111-4111-8111-111111111111",
		IncarnationID:  "22222222-2222-4222-8222-222222222222",
		DaemonUniqueID: 9007199254740997,
		ControllerSPKI: base64.StdEncoding.EncodeToString(spki),
		RootPublicKey:  base64.StdEncoding.EncodeToString(root),
		Store:          "33333333-3333-4333-8333-333333333333",
		Binding:        strings.Repeat("ab", 32), ExpectedEpoch: ^uint64(0) - 1,
	}
	grant := storageauthority.LifecycleGrant{
		Operation: storageauthority.LifecycleTakeover,
		ID:        "44444444-4444-4444-8444-444444444444",
		Identity:  storageauthority.LifecycleIdentity{Store: storageauthority.ID(greeting.Store), Generation: 9007199254740993, Binding: storageauthority.Fingerprint(greeting.Binding)},
		Serial:    ^uint64(0), ExpectedEpoch: greeting.ExpectedEpoch, NewKey: storageauthority.Fingerprint(fp.String()),
	}
	return k, LifecycleChildChallengeFields{
		Version: LifecycleChildVersion, Greeting: greeting, Grant: grant,
		ChildAudit:    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x81}, 32)),
		ChildUniqueID: ^uint64(0), DaemonAudit: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfe}, 32)),
		Counter: 9007199254740995, Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32)),
		Purpose: LifecycleChildCandidate, ExpiresUnixMS: ^uint64(0),
	}
}

func lifecycleChildTestChallenge(t *testing.T, f LifecycleChildChallengeFields) LifecycleChildChallenge {
	t.Helper()
	c, err := NewLifecycleChildChallenge(f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func lifecycleChildTestBoot(t *testing.T, f LifecycleChildChallengeFields) *LifecycleBootTrustFields {
	t.Helper()
	root, _ := base64.StdEncoding.DecodeString(f.Greeting.RootPublicKey)
	fingerprint, err := PublicKeyFingerprint(ed25519.PublicKey(root))
	if err != nil {
		t.Fatal(err)
	}
	return &LifecycleBootTrustFields{Identity: f.Grant.Identity, ServiceEpoch: "55555555-5555-4555-8555-555555555555",
		TLSRootSHA256: strings.Repeat("cd", 32), ServerSPKI: strings.Repeat("ef", 32), BootstrapKey: fingerprint.String()}
}

func lifecycleChildTestReceipt(c LifecycleChildChallenge) *storageauthority.LifecycleReceipt {
	nonce, _ := base64.StdEncoding.DecodeString(c.fields.Nonce)
	return &storageauthority.LifecycleReceipt{Grant: c.fields.Grant, Nonce: nonce, ServiceEpoch: "55555555-5555-4555-8555-555555555555", Revision: ^uint64(0)}
}

func lifecycleChildVectorReply(t *testing.T, k Key, c LifecycleChildChallenge, receipt *storageauthority.LifecycleReceipt) LifecycleChildReply {
	t.Helper()
	f := LifecycleChildReplyFields{Version: LifecycleChildVersion, ChallengeSHA256: base64.StdEncoding.EncodeToString(c.Digest()), Receipt: receipt, Signature: base64.StdEncoding.EncodeToString(make([]byte, 64))}
	r, err := NewLifecycleChildReply(f)
	if err != nil {
		t.Fatal(err)
	}
	// Historical fixed vectors bypass ONLY the real-clock check, inside tests.
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.private(), r.SigningBytes()))
	r, err = NewLifecycleChildReply(f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func buildLifecycleChildFixture(t *testing.T) lifecycleChildFixture {
	t.Helper()
	k, f := lifecycleChildVectorFields(t)
	g, err := NewLifecycleChildGreeting(f.Greeting)
	if err != nil {
		t.Fatal(err)
	}
	c := lifecycleChildTestChallenge(t, f)
	candidate := lifecycleChildVectorReply(t, k, c, nil)
	f.Purpose = LifecycleChildResult
	f.Boot = lifecycleChildTestBoot(t, f)
	f.Counter++
	f.Nonce = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xef}, 32))
	resultChallenge := lifecycleChildTestChallenge(t, f)
	result := lifecycleChildVectorReply(t, k, resultChallenge, lifecycleChildTestReceipt(resultChallenge))
	return lifecycleChildFixture{
		Version: LifecycleChildVersion, ControllerSeedHex: lifecycleChildControllerSeed, RootSeedHex: lifecycleChildRootSeed,
		Greeting: g.Fields(), Challenge: c.Fields(), CandidateReply: candidate.Fields(), ResultChallenge: resultChallenge.Fields(), ResultReply: result.Fields(),
		GreetingCanonicalJSON: string(g.Canonical()), ChallengeCanonicalJSON: string(c.Canonical()), CandidateCanonicalJSON: string(candidate.Canonical()), ResultChallengeCanonical: string(resultChallenge.Canonical()), ResultReplyCanonicalJSON: string(result.Canonical()),
		ChallengeSHA256: c.Digest(), ResultChallengeSHA256: resultChallenge.Digest(), CandidateSigningBytes: candidate.SigningBytes(), ResultSigningBytes: result.SigningBytes(),
	}
}

// Regenerate ONLY explicit, public fixtures:
// CENGINE_WRITE_LIFECYCLE_CHILD_FIXTURE=1 go test ./internal/storagepki -run '^TestLifecycleChildFixture$' -count=1
func TestLifecycleChildFixture(t *testing.T) {
	want := buildLifecycleChildFixture(t)
	expected, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	if os.Getenv("CENGINE_WRITE_LIFECYCLE_CHILD_FIXTURE") == "1" {
		if err := os.WriteFile(lifecycleChildFixturePath, expected, 0644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(lifecycleChildFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, expected) {
		t.Fatal("lifecycle child fixture changed")
	}
	var fixture lifecycleChildFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	g, err := DecodeLifecycleChildGreeting([]byte(fixture.GreetingCanonicalJSON))
	if err != nil || g.Fields() != fixture.Greeting {
		t.Fatal("greeting vector", err)
	}
	c, err := DecodeLifecycleChildChallenge([]byte(fixture.ChallengeCanonicalJSON))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := DecodeLifecycleChildChallenge([]byte(fixture.ResultChallengeCanonical))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := DecodeLifecycleChildReply([]byte(fixture.CandidateCanonicalJSON))
	if err != nil {
		t.Fatal(err)
	}
	result, err := DecodeLifecycleChildReply([]byte(fixture.ResultReplyCanonicalJSON))
	if err != nil {
		t.Fatal(err)
	}
	if !candidate.Verifies(c) || !result.Verifies(rc) || candidate.Verifies(rc) || result.Verifies(c) {
		t.Fatal("signature/correlation vector")
	}
	if strings.Contains(fixture.CandidateCanonicalJSON, `"receipt"`) {
		t.Fatal("absent receipt must be omitted")
	}
	if !bytes.Equal(c.Digest(), fixture.ChallengeSHA256) || !bytes.Equal(rc.Digest(), fixture.ResultChallengeSHA256) || !bytes.Equal(candidate.SigningBytes(), fixture.CandidateSigningBytes) || !bytes.Equal(result.SigningBytes(), fixture.ResultSigningBytes) {
		t.Fatal("digest/signing bytes vector")
	}
	if c.fields.ChildUniqueID != ^uint64(0) || c.fields.Grant.Serial != ^uint64(0) || c.fields.Grant.Identity.Generation != 9007199254740993 || c.fields.Greeting.ExpectedEpoch != ^uint64(0)-1 || result.fields.Receipt.Revision != ^uint64(0) {
		t.Fatal("lost uint64 precision")
	}
	// Assert the result includes the real receipt contract, NOT sorted transport JSON.
	receipt, err := storageauthority.LifecycleReceiptSigningBytes(*result.Fields().Receipt)
	if err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte(lifecycleChildReplyDomain), rc.Digest()...)
	prefix = append(prefix, []byte("result\x00")...)
	if !bytes.Equal(result.SigningBytes(), append(prefix, receipt...)) {
		t.Fatal("wrong receipt signing bytes")
	}
}

func TestLifecycleChildTypedSigningAndOwnership(t *testing.T) {
	k, f := lifecycleChildVectorFields(t)
	f.ExpiresUnixMS = uint64(time.Now().UnixMilli()) + 20_000
	c := lifecycleChildTestChallenge(t, f)
	candidate, err := k.SignLifecycleChildReply(c, nil)
	if err != nil || !candidate.Verifies(c) {
		t.Fatal("candidate signing", err)
	}
	f.Purpose = LifecycleChildResult
	f.Boot = lifecycleChildTestBoot(t, f)
	f.Counter++
	c = lifecycleChildTestChallenge(t, f)
	receipt := lifecycleChildTestReceipt(c)
	result, err := k.SignLifecycleChildReply(c, receipt)
	if err != nil || !result.Verifies(c) {
		t.Fatal("result signing", err)
	}
	original := result.Canonical()
	receipt.Nonce[0] ^= 1
	receipt.Grant.Serial++
	fields := result.Fields()
	fields.Receipt.Nonce[0] ^= 1
	fields.Receipt.Grant.Serial++
	clear(result.Canonical())
	clear(result.SigningBytes())
	cf := c.Fields()
	cf.Grant.Serial++
	cf.Boot.ServiceEpoch = string(cf.Grant.ID)
	f.Boot.TLSRootSHA256 = strings.Repeat("aa", 32)
	clear(c.Canonical())
	clear(c.Digest())
	if !bytes.Equal(result.Canonical(), original) || !result.Verifies(c) {
		t.Fatal("caller mutated frozen values")
	}
	for _, role := range []Role{ServerRole, PrepareRole, RuntimeRole, ""} {
		wrong := k // Same key material isolates the role check from SPKI matching.
		wrong.role = role
		if _, err := wrong.SignLifecycleChildReply(c, lifecycleChildTestReceipt(c)); err == nil {
			t.Fatalf("signed for role %q", role)
		}
	}
	wrong, err := NewControllerKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Key{{}, wrong} {
		if _, err := bad.SignLifecycleChildReply(c, lifecycleChildTestReceipt(c)); err == nil {
			t.Fatal("wrong key signed")
		}
	}
	if _, err := k.SignLifecycleChildReply(LifecycleChildChallenge{}, nil); err == nil {
		t.Fatal("zero challenge signed")
	}
	if _, err := k.SignLifecycleChildReply(c, nil); err == nil {
		t.Fatal("result without receipt signed")
	}
	for _, mutate := range []func(*storageauthority.LifecycleReceipt){
		func(r *storageauthority.LifecycleReceipt) { r.Nonce[0] ^= 1 },
		func(r *storageauthority.LifecycleReceipt) { r.Grant.Serial-- },
		func(r *storageauthority.LifecycleReceipt) { r.Revision = 0 },
		func(r *storageauthority.LifecycleReceipt) { r.ServiceEpoch = r.Grant.ID },
	} {
		r := lifecycleChildTestReceipt(c)
		mutate(r)
		if _, err := k.SignLifecycleChildReply(c, r); err == nil {
			t.Fatal("mismatched/invalid receipt signed")
		}
	}
	f.Purpose = LifecycleChildCandidate
	f.Boot = nil
	candidateChallenge := lifecycleChildTestChallenge(t, f)
	if _, err := k.SignLifecycleChildReply(candidateChallenge, lifecycleChildTestReceipt(candidateChallenge)); err == nil {
		t.Fatal("candidate with receipt signed")
	}
	for _, expiry := range []uint64{1, uint64(time.Now().Add(-time.Second).UnixMilli()), uint64(time.Now().Add(time.Minute).UnixMilli()), ^uint64(0)} {
		f.ExpiresUnixMS = expiry
		if _, err := k.SignLifecycleChildReply(lifecycleChildTestChallenge(t, f), nil); err == nil {
			t.Fatal("stale/future challenge signed")
		}
	}
	if (LifecycleChildReply{}).Verifies(c) || result.Verifies(LifecycleChildChallenge{}) || (LifecycleChildReply{}).SigningBytes() != nil || (LifecycleChildChallenge{}).Digest() != nil {
		t.Fatal("zero value accepted")
	}
}

func TestLifecycleChildFreshnessAndEpochBounds(t *testing.T) {
	_, f := lifecycleChildVectorFields(t)
	f.ExpiresUnixMS = 40_000
	c := lifecycleChildTestChallenge(t, f)
	for _, test := range []struct {
		now   uint64
		fresh bool
	}{{9_999, false}, {10_000, true}, {39_999, true}, {40_000, false}, {40_001, false}, {^uint64(0), false}} {
		if c.IsFresh(test.now) != test.fresh {
			t.Fatalf("freshness at %d", test.now)
		}
	}
	f.ExpiresUnixMS = ^uint64(0)
	c = lifecycleChildTestChallenge(t, f)
	if !c.IsFresh(^uint64(0)-1) || c.IsFresh(0) {
		t.Fatal("freshness overflow")
	}
	f.Grant.Operation = storageauthority.LifecycleRetire
	f.Grant.ExpectedEpoch = ^uint64(0)
	lifecycleChildTestChallenge(t, f)
	f.Greeting.ExpectedEpoch = ^uint64(0)
	if _, err := NewLifecycleChildChallenge(f); err == nil {
		t.Fatal("retire overflow")
	}
	f.Greeting.ExpectedEpoch = 0
	f.Grant.ExpectedEpoch = 0
	f.Grant.Operation = storageauthority.LifecycleInitialize
	lifecycleChildTestChallenge(t, f)
	f.Grant.ExpectedEpoch = 1
	if _, err := NewLifecycleChildChallenge(f); err == nil {
		t.Fatal("initialize epoch")
	}
}

func TestLifecycleChildInvalidValues(t *testing.T) {
	_, f := lifecycleChildVectorFields(t)
	for name, mutate := range map[string]func(*LifecycleChildChallengeFields){
		"version":          func(f *LifecycleChildChallengeFields) { f.Version = RootChallengeVersion },
		"greeting_version": func(f *LifecycleChildChallengeFields) { f.Greeting.Version = RootChallengeVersion },
		"channel":          func(f *LifecycleChildChallengeFields) { f.Greeting.ChannelID = "invalid" },
		"incarnation":      func(f *LifecycleChildChallengeFields) { f.Greeting.IncarnationID = "" },
		"store": func(f *LifecycleChildChallengeFields) {
			f.Greeting.Store = strings.ToUpper(f.Greeting.Store[:14]) + "5" + f.Greeting.Store[15:]
		},
		"binding": func(f *LifecycleChildChallengeFields) { f.Greeting.Binding = strings.Repeat("AB", 32) },
		"spki": func(f *LifecycleChildChallengeFields) {
			f.Greeting.ControllerSPKI = base64.StdEncoding.EncodeToString(make([]byte, 44))
		},
		"root": func(f *LifecycleChildChallengeFields) {
			f.Greeting.RootPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31))
		},
		"root_is_controller": func(f *LifecycleChildChallengeFields) {
			der, _ := base64.StdEncoding.DecodeString(f.Greeting.ControllerSPKI)
			f.Greeting.RootPublicKey = base64.StdEncoding.EncodeToString(der[12:])
		},
		"daemon_zero":  func(f *LifecycleChildChallengeFields) { f.Greeting.DaemonUniqueID = 0 },
		"child_zero":   func(f *LifecycleChildChallengeFields) { f.ChildUniqueID = 0 },
		"same_process": func(f *LifecycleChildChallengeFields) { f.ChildUniqueID = f.Greeting.DaemonUniqueID },
		"counter":      func(f *LifecycleChildChallengeFields) { f.Counter = 0 },
		"expiry":       func(f *LifecycleChildChallengeFields) { f.ExpiresUnixMS = 0 },
		"nonce":        func(f *LifecycleChildChallengeFields) { f.Nonce = strings.TrimRight(f.Nonce, "=") },
		"child_audit":  func(f *LifecycleChildChallengeFields) { f.ChildAudit = "" },
		"daemon_audit": func(f *LifecycleChildChallengeFields) { f.DaemonAudit += "\n" },
		"purpose":      func(f *LifecycleChildChallengeFields) { f.Purpose = "sign" },
		"grant_key": func(f *LifecycleChildChallengeFields) {
			f.Grant.NewKey = storageauthority.Fingerprint(strings.Repeat("cd", 32))
		},
		"grant_store": func(f *LifecycleChildChallengeFields) {
			f.Grant.Identity.Store = storageauthority.ID(f.Greeting.ChannelID)
		},
		"grant_binding": func(f *LifecycleChildChallengeFields) {
			f.Grant.Identity.Binding = storageauthority.Fingerprint(strings.Repeat("cd", 32))
		},
		"grant_epoch":      func(f *LifecycleChildChallengeFields) { f.Grant.ExpectedEpoch-- },
		"grant_id":         func(f *LifecycleChildChallengeFields) { f.Grant.ID = "" },
		"grant_serial":     func(f *LifecycleChildChallengeFields) { f.Grant.Serial = 0 },
		"grant_generation": func(f *LifecycleChildChallengeFields) { f.Grant.Identity.Generation = 0 },
		"grant_operation":  func(f *LifecycleChildChallengeFields) { f.Grant.Operation = "sign" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := f
			mutate(&copy)
			if _, err := NewLifecycleChildChallenge(copy); err == nil {
				t.Fatal("invalid challenge accepted")
			}
		})
	}
}

func TestLifecycleChildClosedWire(t *testing.T) {
	fixture := buildLifecycleChildFixture(t)
	for name, test := range map[string]struct {
		wire   string
		decode func([]byte) bool
	}{
		"greeting":         {fixture.GreetingCanonicalJSON, func(b []byte) bool { _, err := DecodeLifecycleChildGreeting(b); return err == nil }},
		"challenge":        {fixture.ChallengeCanonicalJSON, func(b []byte) bool { _, err := DecodeLifecycleChildChallenge(b); return err == nil }},
		"candidate":        {fixture.CandidateCanonicalJSON, func(b []byte) bool { _, err := DecodeLifecycleChildReply(b); return err == nil }},
		"result_challenge": {fixture.ResultChallengeCanonical, func(b []byte) bool { _, err := DecodeLifecycleChildChallenge(b); return err == nil }},
		"result":           {fixture.ResultReplyCanonicalJSON, func(b []byte) bool { _, err := DecodeLifecycleChildReply(b); return err == nil }},
	} {
		t.Run(name, func(t *testing.T) {
			b := test.wire
			bad := []string{b + "\n", " " + b, b + "{}", "null", "{}", strings.Repeat("x", MaxLifecycleChildSize+1),
				b[:len(b)-1] + `,"version":"` + LifecycleChildVersion + `"}`,
				b[:len(b)-1] + `,"unknown":0}`,
				strings.ReplaceAll(b, `"version":`, `"Version":`),
				strings.ReplaceAll(b, LifecycleChildVersion, "storage-child-lifecycle.v1"),
				strings.ReplaceAll(b, LifecycleChildVersion, `storage-child-lifecycle.v\u0032`),
				strings.ReplaceAll(b, `,"version":"`+LifecycleChildVersion+`"`, ""),
			}
			// Recursively mutate every nested object's keys, even zero-valued fields.
			for _, token := range []string{`"grant":{`, `"greeting":{`, `"identity":{`, `"receipt":{`, `"boot":{`} {
				if strings.Contains(b, token) {
					bad = append(bad, strings.Replace(b, token, token+`"unknown":0,`, 1), strings.Replace(b, token, token+`"version":null,`, 1))
				}
			}
			// Exercise every UInt64 field at every depth, including repeated epoch
			// keys in distinct objects; never convert fixture integers to floats.
			for _, match := range regexp.MustCompile(`("[a-z_]+":)([0-9]+)`).FindAllStringSubmatchIndex(b, -1) {
				key, number := b[match[2]:match[3]], b[match[4]:match[5]]
				for _, n := range []string{`"` + number + `"`, number + ".0", number + "e0", "-1", "18446744073709551616", "null", "0" + number} {
					bad = append(bad, b[:match[0]]+key+n+b[match[1]:])
				}
				token := b[match[0]:match[1]]
				bad = append(bad, b[:match[0]]+token+","+token+b[match[1]:])
				if b[match[1]] == ',' {
					bad = append(bad, b[:match[0]]+b[match[1]+1:])
				} else {
					bad = append(bad, b[:match[0]-1]+b[match[1]:])
				}
			}
			if name == "candidate" {
				bad = append(bad, strings.Replace(b, `"signature":`, `"receipt":null,"signature":`, 1))
			}
			if name == "result" {
				bad = append(bad, strings.Replace(b, `"revision":18446744073709551615`, `"revision":0`, 1), strings.Replace(b, `"nonce":"`, `"nonce":"\\n`, 1))
			}
			for i, data := range bad {
				if test.decode([]byte(data)) {
					t.Fatalf("accepted noncanonical wire %d: %s", i, data)
				}
			}
		})
	}
}

func TestLifecycleChildInvalidReplyValues(t *testing.T) {
	fixture := buildLifecycleChildFixture(t)
	for _, mutate := range []func(*LifecycleChildReplyFields){
		func(f *LifecycleChildReplyFields) { f.Version = RootChallengeVersion },
		func(f *LifecycleChildReplyFields) { f.ChallengeSHA256 = "" },
		func(f *LifecycleChildReplyFields) { f.ChallengeSHA256 = strings.TrimRight(f.ChallengeSHA256, "=") },
		func(f *LifecycleChildReplyFields) { f.Signature = base64.StdEncoding.EncodeToString(make([]byte, 63)) },
		func(f *LifecycleChildReplyFields) { f.Signature += "\n" },
		func(f *LifecycleChildReplyFields) { f.Receipt.Revision = 0 },
		func(f *LifecycleChildReplyFields) { f.Receipt.ServiceEpoch = "invalid" },
		func(f *LifecycleChildReplyFields) { f.Receipt.Nonce = nil },
	} {
		f := fixture.ResultReply
		f.Receipt = cloneLifecycleChildReceipt(f.Receipt)
		mutate(&f)
		if _, err := NewLifecycleChildReply(f); err == nil {
			t.Fatal("invalid reply accepted")
		}
	}
	// An omitted initialize epoch must not be accepted as an implicit zero.
	_, f := lifecycleChildVectorFields(t)
	f.Grant.Operation = storageauthority.LifecycleInitialize
	f.Grant.ExpectedEpoch, f.Greeting.ExpectedEpoch = 0, 0
	c := lifecycleChildTestChallenge(t, f)
	missing := strings.ReplaceAll(string(c.Canonical()), `"expected_epoch":0,`, "")
	if _, err := DecodeLifecycleChildChallenge([]byte(missing)); err == nil {
		t.Fatal("missing zero epochs accepted")
	}
}

func TestLifecycleChildChallengeAndReceiptBinding(t *testing.T) {
	k, f := lifecycleChildVectorFields(t)
	f.Purpose = LifecycleChildResult
	f.Boot = lifecycleChildTestBoot(t, f)
	c := lifecycleChildTestChallenge(t, f)
	r := lifecycleChildVectorReply(t, k, c, lifecycleChildTestReceipt(c))
	for _, mutate := range []func(*LifecycleChildChallengeFields){
		func(f *LifecycleChildChallengeFields) { f.Greeting.ChannelID = f.Greeting.IncarnationID },
		func(f *LifecycleChildChallengeFields) { f.Greeting.IncarnationID = f.Greeting.ChannelID },
		func(f *LifecycleChildChallengeFields) { f.Greeting.DaemonUniqueID++ },
		func(f *LifecycleChildChallengeFields) { f.ChildUniqueID-- },
		func(f *LifecycleChildChallengeFields) { f.Grant.Serial-- },
		func(f *LifecycleChildChallengeFields) {
			f.Grant.Identity.Generation++
			f.Boot.Identity = f.Grant.Identity
		},
		func(f *LifecycleChildChallengeFields) { f.Counter++ },
		func(f *LifecycleChildChallengeFields) { f.Nonce = f.ChildAudit },
		func(f *LifecycleChildChallengeFields) { f.ChildAudit = f.DaemonAudit },
		func(f *LifecycleChildChallengeFields) { f.DaemonAudit = f.ChildAudit },
		func(f *LifecycleChildChallengeFields) { f.ExpiresUnixMS-- },
		func(f *LifecycleChildChallengeFields) { f.Purpose = LifecycleChildCandidate; f.Boot = nil },
	} {
		copy := f
		copy.Boot = cloneLifecycleBootTrust(f.Boot)
		mutate(&copy)
		if r.Verifies(lifecycleChildTestChallenge(t, copy)) {
			t.Fatal("accepted changed challenge")
		}
	}
	for _, mutate := range []func(*LifecycleChildReplyFields){
		func(f *LifecycleChildReplyFields) { f.Receipt.Revision-- },
		func(f *LifecycleChildReplyFields) { f.Receipt.ServiceEpoch = f.Receipt.Grant.ID },
		func(f *LifecycleChildReplyFields) { f.Receipt.Grant.Serial-- },
		func(f *LifecycleChildReplyFields) { f.Receipt.Nonce[0] ^= 1 },
		func(f *LifecycleChildReplyFields) { f.Receipt = nil },
		func(f *LifecycleChildReplyFields) { f.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		func(f *LifecycleChildReplyFields) {
			f.ChallengeSHA256 = base64.StdEncoding.EncodeToString(make([]byte, 32))
		},
	} {
		fields := r.Fields()
		mutate(&fields)
		changed, err := NewLifecycleChildReply(fields)
		if err != nil {
			t.Fatal(err)
		}
		if changed.Verifies(c) {
			t.Fatal("accepted changed result")
		}
	}
	sig, _ := base64.StdEncoding.DecodeString(r.fields.Signature)
	for _, message := range [][]byte{c.Canonical(), c.Digest(), r.Canonical(), append([]byte("cengine.storage-child-lifecycle.reply.v1\x00"), r.SigningBytes()[len(lifecycleChildReplyDomain):]...)} {
		if ed25519.Verify(k.PublicKey(), message, sig) {
			t.Fatal("signature valid in wrong domain")
		}
	}
	// Challenge digest uses canonical JSON, not a raw JSON hash or v1 domain.
	raw := sha256.Sum256(c.Canonical())
	if bytes.Equal(raw[:], c.Digest()) {
		t.Fatal("missing challenge domain")
	}
}

func TestLifecycleChildBootRequiredAndBound(t *testing.T) {
	k, f := lifecycleChildVectorFields(t)
	f.Boot = lifecycleChildTestBoot(t, f)
	if _, err := NewLifecycleChildChallenge(f); err == nil {
		t.Fatal("candidate boot accepted")
	}
	f.Purpose = LifecycleChildResult
	good := lifecycleChildTestChallenge(t, f)
	reply := lifecycleChildVectorReply(t, k, good, lifecycleChildTestReceipt(good))
	for name, mutate := range map[string]func(*LifecycleChildChallengeFields){
		"missing":       func(f *LifecycleChildChallengeFields) { f.Boot = nil },
		"store":         func(f *LifecycleChildChallengeFields) { f.Boot.Identity.Store = f.Grant.ID },
		"generation":    func(f *LifecycleChildChallengeFields) { f.Boot.Identity.Generation++ },
		"binding":       func(f *LifecycleChildChallengeFields) { f.Boot.Identity.Binding = f.Grant.NewKey },
		"bootstrap-key": func(f *LifecycleChildChallengeFields) { f.Boot.BootstrapKey = f.Boot.ServerSPKI },
	} {
		t.Run(name, func(t *testing.T) {
			fields := good.Fields()
			mutate(&fields)
			if _, err := NewLifecycleChildChallenge(fields); err == nil {
				t.Fatal("unbound boot accepted")
			}
		})
	}
	for _, mutate := range []func(*LifecycleBootTrustFields){
		func(b *LifecycleBootTrustFields) { b.ServiceEpoch = string(f.Grant.ID) },
		func(b *LifecycleBootTrustFields) { b.TLSRootSHA256 = b.ServerSPKI },
		func(b *LifecycleBootTrustFields) { b.ServerSPKI = b.TLSRootSHA256 },
	} {
		fields := good.Fields()
		mutate(fields.Boot)
		changed := lifecycleChildTestChallenge(t, fields)
		if reply.Verifies(changed) {
			t.Fatal("boot field not signature-bound")
		}
	}
	f.Boot = nil
	raw, _ := lifecycleChildCanonical(f)
	if _, err := DecodeLifecycleChildChallenge(raw); err == nil {
		t.Fatal("legacy result without boot accepted")
	}
	nullBoot := bytes.Replace(raw, []byte(`{"child_audit":`), []byte(`{"boot":null,"child_audit":`), 1)
	if _, err := DecodeLifecycleChildChallenge(nullBoot); err == nil {
		t.Fatal("null boot accepted")
	}
}

func TestLifecycleBootTrustValidationAndOwnership(t *testing.T) {
	_, f := lifecycleChildVectorFields(t)
	fields := *lifecycleChildTestBoot(t, f)
	frozen, err := NewLifecycleBootTrust(fields)
	if err != nil || !frozen.MatchesGrant(f.Grant) {
		t.Fatal("valid boot", err)
	}
	original := frozen.Fields()
	fields.ServiceEpoch = string(f.Grant.ID)
	exposed := frozen.Fields()
	exposed.Identity.Generation++
	clear(frozen.Canonical())
	if frozen.Fields() != original {
		t.Fatal("caller mutated frozen boot")
	}
	if (LifecycleBootTrust{}).MatchesGrant(f.Grant) {
		t.Fatal("zero boot matched")
	}
	for _, mutate := range []func(*LifecycleBootTrustFields){
		func(b *LifecycleBootTrustFields) { b.Identity.Generation = 0 },
		func(b *LifecycleBootTrustFields) { b.Identity.Store = "bad" },
		func(b *LifecycleBootTrustFields) { b.Identity.Binding = "bad" },
		func(b *LifecycleBootTrustFields) { b.ServiceEpoch = "bad" },
		func(b *LifecycleBootTrustFields) { b.TLSRootSHA256 = strings.Repeat("A", 64) },
		func(b *LifecycleBootTrustFields) { b.ServerSPKI = "bad" },
		func(b *LifecycleBootTrustFields) { b.BootstrapKey = "" },
	} {
		bad := original
		mutate(&bad)
		if _, err := NewLifecycleBootTrust(bad); err == nil {
			t.Fatal("invalid boot accepted")
		}
	}
}
