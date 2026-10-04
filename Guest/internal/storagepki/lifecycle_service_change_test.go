package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

const lifecycleServiceChangeFixturePath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-service-change-v2.json"

type lifecycleServiceChangeVector struct {
	Value         SignedLifecycleServiceChange `json:"value"`
	SigningBytes  []byte                       `json:"signing_bytes"`
	Signature     []byte                       `json:"signature"`
	CanonicalJSON string                       `json:"canonical_json"`
}
type lifecycleServiceChangeFixture struct {
	Version       string                         `json:"version"`
	SeedHex       string                         `json:"seed_hex"`
	RootPublicKey []byte                         `json:"root_public_key"`
	Vectors       []lifecycleServiceChangeVector `json:"vectors"`
}

func lifecycleServiceChangeRoot(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(lifecycleChildRootSeed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// Predecessors for an initialize grant and a takeover grant, both bound to the
// RFC 8032 test ROOT as bootstrap key.
func lifecycleServiceChangeRequests(t *testing.T) []LifecycleServiceChangeRequest {
	t.Helper()
	fixture := buildLifecycleChildServiceFixture(t)
	result := *fixture.Vectors[0].Reply.ServiceResult
	boot := *fixture.Vectors[0].Challenge.Boot
	var out []LifecycleServiceChangeRequest
	for i, op := range []a.LifecycleOperation{a.LifecycleInitialize, a.LifecycleTakeover} {
		r := result
		r.Grant.Operation = op
		if op == a.LifecycleInitialize {
			r.Grant.ExpectedEpoch = 0
		} else if r.Grant.ExpectedEpoch == 0 {
			r.Grant.ExpectedEpoch = 41
		}
		r.ControllerEpoch = r.Grant.ExpectedEpoch + 1
		state, err := LifecycleServiceStateFromResult(r, boot)
		if err != nil {
			t.Fatal("predecessor", op, err)
		}
		ids := []string{"66666666-6666-4666-8666-666666666666", "88888888-8888-4888-8888-888888888888"}
		out = append(out, LifecycleServiceChangeRequest{OperationID: ids[i], Predecessor: state})
	}
	return out
}

func buildLifecycleServiceChangeFixture(t *testing.T) lifecycleServiceChangeFixture {
	t.Helper()
	key := lifecycleServiceChangeRoot(t)
	f := lifecycleServiceChangeFixture{Version: "storage-lifecycle-service-change.v2", SeedHex: lifecycleChildRootSeed, RootPublicKey: key.Public().(ed25519.PublicKey)}
	for _, r := range lifecycleServiceChangeRequests(t) {
		b, err := LifecycleServiceChangeSigningBytes(r)
		if err != nil {
			t.Fatal(err)
		}
		v := SignedLifecycleServiceChange{Request: r, Signature: ed25519.Sign(key, b)}
		canonical, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		f.Vectors = append(f.Vectors, lifecycleServiceChangeVector{v, b, bytes.Clone(v.Signature), string(canonical)})
	}
	return f
}

// Regenerate only this contract: UPDATE_LIFECYCLE_SERVICE_CHANGE_FIXTURE=1
// go test ./internal/storagepki -run '^TestLifecycleServiceChangeFixture$' -count=1
func TestLifecycleServiceChangeFixture(t *testing.T) {
	want := buildLifecycleServiceChangeFixture(t)
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("UPDATE_LIFECYCLE_SERVICE_CHANGE_FIXTURE") == "1" {
		if err = os.WriteFile(lifecycleServiceChangeFixturePath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(lifecycleServiceChangeFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var got lifecycleServiceChangeFixture
	if err = json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got, want) || !bytes.Equal(raw, encoded) {
		t.Fatal("lifecycle service change fixture drift", err)
	}
	if len(got.Vectors) < 2 || got.Vectors[0].Value.Request.Predecessor.Grant.Operation != a.LifecycleInitialize ||
		got.Vectors[1].Value.Request.Predecessor.Grant.Operation != a.LifecycleTakeover {
		t.Fatal("fixture must cover initialize and takeover predecessors")
	}
	for _, v := range got.Vectors {
		if v.Value.Verify(got.RootPublicKey) != nil || !bytes.Equal(v.Signature, v.Value.Signature) {
			t.Fatal("vector does not verify")
		}
		b, err := LifecycleServiceChangeSigningBytes(v.Value.Request)
		if err != nil || !bytes.Equal(b, v.SigningBytes) {
			t.Fatal("signing bytes drift")
		}
	}
}

func TestSignedLifecycleServiceChangeVerify(t *testing.T) {
	key := lifecycleServiceChangeRoot(t)
	root := key.Public().(ed25519.PublicKey)
	request := lifecycleServiceChangeRequests(t)[1]
	b, err := LifecycleServiceChangeSigningBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	good := SignedLifecycleServiceChange{Request: request, Signature: ed25519.Sign(key, b)}
	if good.Verify(root) != nil {
		t.Fatal("valid signature rejected")
	}
	// Domain alias: the service-result domain, an older version, and the bare
	// request JSON must not authorize a service change.
	body := b[len("cengine.storageauthority.lifecycle-service-change.v2\x00"):]
	for _, domain := range []string{"cengine.storageauthority.lifecycle-service-result.v2\x00", "cengine.storageauthority.lifecycle-service-change.v1\x00",
		"cengine.storageauthority.lifecycle-service-change.v2", ""} {
		alias := good
		alias.Signature = ed25519.Sign(key, append([]byte(domain), body...))
		if alias.Verify(root) == nil {
			t.Fatalf("domain alias %q verified", domain)
		}
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	for name, mutate := range map[string]func(*SignedLifecycleServiceChange, *ed25519.PublicKey){
		"absent":  func(s *SignedLifecycleServiceChange, _ *ed25519.PublicKey) { s.Signature = nil },
		"short":   func(s *SignedLifecycleServiceChange, _ *ed25519.PublicKey) { s.Signature = s.Signature[:63] },
		"zero":    func(s *SignedLifecycleServiceChange, _ *ed25519.PublicKey) { s.Signature = make([]byte, 64) },
		"flipped": func(s *SignedLifecycleServiceChange, _ *ed25519.PublicKey) { s.Signature[5] ^= 1 },
		"operation": func(s *SignedLifecycleServiceChange, _ *ed25519.PublicKey) {
			s.Request.OperationID = string(s.Request.Predecessor.Grant.ID)
		},
		"revision":    func(s *SignedLifecycleServiceChange, _ *ed25519.PublicKey) { s.Request.Predecessor.OpenRevision-- },
		"other_root":  func(_ *SignedLifecycleServiceChange, r *ed25519.PublicKey) { *r = other.Public().(ed25519.PublicKey) },
		"short_root":  func(_ *SignedLifecycleServiceChange, r *ed25519.PublicKey) { *r = (*r)[:31] },
		"other_signs": func(s *SignedLifecycleServiceChange, _ *ed25519.PublicKey) { s.Signature = ed25519.Sign(other, b) },
		"root_self_signed_other_boot": func(s *SignedLifecycleServiceChange, r *ed25519.PublicKey) {
			// A different ROOT that signs its own request still does not match the recorded bootstrap key.
			*r = other.Public().(ed25519.PublicKey)
			m, _ := LifecycleServiceChangeSigningBytes(s.Request)
			s.Signature = ed25519.Sign(other, m)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := *good.Clone()
			r := bytes.Clone(root)
			pub := ed25519.PublicKey(r)
			mutate(&bad, &pub)
			if bad.Verify(pub) == nil {
				t.Fatal("unauthorized change verified")
			}
		})
	}
	clone := good.Clone()
	clone.Signature[0] ^= 1
	if good.Verify(root) != nil || (*SignedLifecycleServiceChange)(nil).Clone() != nil {
		t.Fatal("clone aliases signature")
	}
	if _, err := LifecycleServiceChangeSigningBytes(LifecycleServiceChangeRequest{}); err == nil {
		t.Fatal("invalid request signed")
	}
}
