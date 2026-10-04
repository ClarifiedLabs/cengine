package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func challengeFields(t *testing.T, k Key) RootChallengeFields {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return RootChallengeFields{ChildAudit: base64.StdEncoding.EncodeToString(make([]byte, 32)), ChildUniqueID: 1, ControllerSPKI: base64.StdEncoding.EncodeToString(spki), DaemonAudit: base64.StdEncoding.EncodeToString(make([]byte, 32)), DaemonUniqueID: 2, ExpectedEpoch: 1, ExpiresUnixMS: uint64(time.Now().Add(time.Minute).UnixMilli()), GrantID: other, IncarnationID: other, Nonce: base64.StdEncoding.EncodeToString(make([]byte, 32)), Purpose: RootInitial, RequestID: other, ServiceEpoch: epoch, Store: store, Version: RootChallengeVersion}
}

func TestRootChallengeTypedSigningAndOwnership(t *testing.T) {
	k, err := NewControllerKey()
	if err != nil {
		t.Fatal(err)
	}
	f := challengeFields(t, k)
	c, err := NewRootChallenge(f)
	if err != nil {
		t.Fatal(err)
	}
	original := c.Canonical()
	f.Store = StoreID(other)
	fields := c.Fields()
	fields.ExpectedEpoch++
	clear(c.Canonical())
	clear(c.SigningBytes())
	if !bytes.Equal(c.Canonical(), original) {
		t.Fatal("mutable challenge")
	}
	sig, err := k.SignRootChallenge(c)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(k.PublicKey(), append([]byte("cengine.storagebootstrap.root-proof.v1\x00"), original...), sig) {
		t.Fatal("bad signature/domain")
	}
	if ed25519.Verify(k.PublicKey(), original, sig) {
		t.Fatal("missing domain separation")
	}
	for _, purpose := range []RootChallengePurpose{RootTakeover, RootConfirm} {
		f := c.Fields()
		f.Purpose = purpose
		if purpose == RootConfirm {
			f.TranscriptSHA256 = strings.Repeat("a", 64)
		}
		next, e := NewRootChallenge(f)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = k.SignRootChallenge(next); e != nil {
			t.Fatal(e)
		}
	}
	wrong, _ := NewControllerKey()
	server, _ := NewServerKey()
	attachment, _ := NewAttachmentKey(RuntimeRole)
	for _, bad := range []Key{Key{}, wrong, server, attachment} {
		if _, e := bad.SignRootChallenge(c); e == nil {
			t.Fatal("wrong key/role accepted")
		}
	}
	f = c.Fields()
	f.ExpiresUnixMS = uint64(time.Now().Add(-time.Second).UnixMilli())
	expired, e := NewRootChallenge(f)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []RootChallenge{expired, RootChallenge{}} {
		if _, e := k.SignRootChallenge(bad); e == nil {
			t.Fatal("expired/zero challenge signed")
		}
	}
	fixture := setup(t)
	if _, _, e := fixture.controller.ExportDER(); e == nil {
		t.Fatal("controller private DER exported")
	}
	if _, _, e := fixture.controller.ExportPEM(); e == nil {
		t.Fatal("controller private PEM exported")
	}
}

func TestRootChallengeRejectsNoncanonicalAndInvalidSchema(t *testing.T) {
	k, _ := NewControllerKey()
	f := challengeFields(t, k)
	c, err := NewRootChallenge(f)
	if err != nil {
		t.Fatal(err)
	}
	b := string(c.Canonical())
	bad := []string{b + "\n", " " + b, b + "{}", b[:len(b)-1] + `,"version":"root-proof.v1"}`, strings.Replace(b, `"version":`, `"unknown":`, 1), strings.Replace(b, `"expected_epoch":1`, `"expected_epoch":null`, 1), strings.Replace(b, `"version":"root-proof.v1"`, `"Version":"root-proof.v1"`, 1), strings.Replace(b, `"version":"root-proof.v1"`, `"version":"root-proof.v\u0031"`, 1), strings.Replace(b, `"child_unique_id":1,`, "", 1), strings.Repeat("x", MaxRootChallengeSize+1)}
	for _, number := range []string{`"1"`, "1.0", "1e0", "-1", "18446744073709551616", "01"} {
		bad = append(bad, strings.Replace(b, `"child_unique_id":1`, `"child_unique_id":`+number, 1))
	}
	for i, data := range bad {
		if _, e := DecodeRootChallenge([]byte(data)); e == nil {
			t.Fatalf("accepted noncanonical %d", i)
		}
	}
	for _, mutate := range []func(*RootChallengeFields){
		func(f *RootChallengeFields) { f.ExpectedEpoch = 0 }, func(f *RootChallengeFields) { f.Version = "root-proof.v2" }, func(f *RootChallengeFields) { f.Purpose = "sign" }, func(f *RootChallengeFields) { f.GrantID = string(store) }, func(f *RootChallengeFields) { f.TranscriptSHA256 = strings.Repeat("a", 64) }, func(f *RootChallengeFields) { f.Purpose = RootConfirm }, func(f *RootChallengeFields) { f.Purpose = RootConfirm; f.TranscriptSHA256 = strings.Repeat("A", 64) }, func(f *RootChallengeFields) { f.Nonce = strings.TrimRight(f.Nonce, "=") }, func(f *RootChallengeFields) { f.ChildAudit = "" }, func(f *RootChallengeFields) { f.DaemonAudit += "\n" }, func(f *RootChallengeFields) { f.ControllerSPKI = base64.StdEncoding.EncodeToString(make([]byte, 44)) }, func(f *RootChallengeFields) { f.RequestID = strings.ToUpper(other[:14]) + "5" + other[15:] }, func(f *RootChallengeFields) { f.IncarnationID = "" },
	} {
		copy := f
		mutate(&copy)
		if _, e := NewRootChallenge(copy); e == nil {
			t.Fatal("accepted invalid schema")
		}
	}
}

// Literal cross-language vector: JSON integer tokens must never pass through
// float64/NSNumber.doubleValue. Python's json.dumps(sort_keys=True,separators=
// (',', ':')) produces these exact bytes, including all four UINT64_MAX values.
const maxRootChallengeVector = `{"child_audit":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","child_unique_id":18446744073709551615,"controller_spki":"MCowBQYDK2VwAyEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","daemon_audit":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","daemon_unique_id":18446744073709551615,"expected_epoch":18446744073709551615,"expires_unix_ms":18446744073709551615,"grant_id":"33333333-3333-4333-8333-333333333333","incarnation_id":"33333333-3333-4333-8333-333333333333","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","purpose":"confirm","request_id":"33333333-3333-4333-8333-333333333333","service_epoch":"22222222-2222-4222-8222-222222222222","store":"11111111-1111-4111-8111-111111111111","transcript_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"root-proof.v1"}`

func TestRootChallengeUint64CrossLanguageVector(t *testing.T) {
	c, err := DecodeRootChallenge([]byte(maxRootChallengeVector))
	if err != nil {
		t.Fatal(err)
	}
	f := c.Fields()
	if f.ChildUniqueID != ^uint64(0) || f.DaemonUniqueID != ^uint64(0) || f.ExpectedEpoch != ^uint64(0) || f.ExpiresUnixMS != ^uint64(0) {
		t.Fatal("uint64 precision lost")
	}
	if string(c.Canonical()) != maxRootChallengeVector {
		t.Fatal("vector changed")
	}
	// Independently computed with Python json + hashlib, not the Go encoder.
	if got := fmt.Sprintf("%x", sha256.Sum256(c.SigningBytes())); got != "74d39454b4e9bf69566ec9b4961e5cdae00250927f4b8c4443ab5ff45c73c56c" {
		t.Fatalf("cross-language signing digest changed: %s", got)
	}
}
