package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type identityFixture struct {
	Challenge    string `json:"challenge"`
	Reply        string `json:"reply"`
	Digest       []byte `json:"digest"`
	SigningBytes []byte `json:"signing_bytes"`
}

func identityVector(t *testing.T) (Key, LifecycleChildIdentityChallenge) {
	k, f := lifecycleChildVectorFields(t)
	c, e := NewLifecycleChildIdentityChallenge(LifecycleChildIdentityChallengeFields{Version: LifecycleChildIdentityVersion, Greeting: f.Greeting, ChildAudit: f.ChildAudit, ChildUniqueID: f.ChildUniqueID, DaemonAudit: f.DaemonAudit, Counter: f.Counter, Nonce: f.Nonce, RequestSHA256: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x12}, 32)), ExpiresUnixMS: f.ExpiresUnixMS})
	if e != nil {
		t.Fatal(e)
	}
	return k, c
}
func TestLifecycleChildIdentityFixture(t *testing.T) {
	k, c := identityVector(t)
	f := LifecycleChildIdentityReplyFields{LifecycleChildIdentityVersion, base64.StdEncoding.EncodeToString(c.Digest()), base64.StdEncoding.EncodeToString(make([]byte, 64))}
	r, e := NewLifecycleChildIdentityReply(f)
	if e != nil {
		t.Fatal(e)
	}
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.private(), r.SigningBytes()))
	r, e = NewLifecycleChildIdentityReply(f)
	if e != nil {
		t.Fatal(e)
	}
	fixture := identityFixture{string(c.Canonical()), string(r.Canonical()), c.Digest(), r.SigningBytes()}
	raw, e := json.MarshalIndent(fixture, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := "../../../Tests/Fixtures/storage-bootstrap/lifecycle-child-identity-v1.json"
	if os.Getenv("CENGINE_WRITE_LIFECYCLE_CHILD_IDENTITY_FIXTURE") == "1" {
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	got, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(got, raw) {
		t.Fatal("fixture drift", e)
	}
	if !r.Verifies(c) {
		t.Fatal("signature")
	}
	for _, b := range [][]byte{append(c.Canonical(), '\n'), []byte(strings.Replace(string(c.Canonical()), `"counter":`, `"unknown":`, 1)), []byte(strings.Replace(string(c.Canonical()), `"version":`, `"version":"wrong","version":`, 1)), []byte(strings.Replace(string(c.Canonical()), `"request_sha256":`, `"grant":`, 1))} {
		if _, e := DecodeLifecycleChildIdentityChallenge(b); e == nil {
			t.Fatal("open schema")
		}
	}
	if _, e := DecodeLifecycleChildChallenge(c.Canonical()); e == nil {
		t.Fatal("identity as grant")
	}
	if _, e := DecodeLifecycleChildReply(r.Canonical()); e == nil {
		t.Fatal("identity reply as grant")
	}
	cf := c.Fields()
	cf.RequestSHA256 = cf.Nonce
	changed, e := NewLifecycleChildIdentityChallenge(cf)
	if e != nil || r.Verifies(changed) {
		t.Fatal("request digest unbound", e)
	}
	cf = c.Fields()
	cf.ExpiresUnixMS = uint64(time.Now().UnixMilli()) + LifecycleChildLifetimeMS
	c, e = NewLifecycleChildIdentityChallenge(cf)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := k.SignLifecycleChildIdentityReply(c)
	if e != nil || !signed.Verifies(c) {
		t.Fatal("live signer", e)
	}
	wrong, e := NewControllerKey()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = wrong.SignLifecycleChildIdentityReply(c); e == nil {
		t.Fatal("wrong key")
	}
	if _, e = k.SignLifecycleChildIdentityReply(LifecycleChildIdentityChallenge{}); e == nil {
		t.Fatal("zero challenge")
	}
}
