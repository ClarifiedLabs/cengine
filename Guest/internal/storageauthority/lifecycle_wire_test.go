package storageauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const lifecycleFixturePath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-v2.json"
const lifecycleTestSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
const lifecycleBindingJSON = `{"backing":{"identity":{"inode":9007199254740995,"volume_uuid":"dddddddd-dddd-1ddd-bddd-dddddddddddd"},"size":9007199254740997},"expected_ext4_uuid":"eeeeeeee-eeee-1eee-8eee-eeeeeeeeeeee","root":{"inode":18446744073709551615,"volume_uuid":"cccccccc-cccc-1ccc-accc-cccccccccccc"},"store_id":"bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb"}`

type lifecycleGrantVector struct {
	Grant         LifecycleGrant `json:"grant"`
	SigningBytes  []byte         `json:"signing_bytes"`
	Signature     []byte         `json:"signature"`
	CanonicalJSON string         `json:"canonical_json"`
}

type lifecycleReceiptVector struct {
	Value         LifecycleReceipt `json:"value"`
	SigningBytes  []byte           `json:"signing_bytes"`
	Signature     []byte           `json:"signature"`
	CanonicalJSON string           `json:"canonical_json"`
}

type lifecycleFixture struct {
	Version       string                 `json:"version"`
	SeedHex       string                 `json:"seed_hex"`
	RootPublicKey []byte                 `json:"root_public_key"`
	BindingJSON   string                 `json:"binding_json"`
	BindingDigest string                 `json:"binding_digest"`
	Vectors       []lifecycleGrantVector `json:"vectors"`
	Receipt       lifecycleReceiptVector `json:"receipt"`
}

// Canonical transport uses sorted object keys, but never a float64 intermediate.
func lifecycleCanonicalJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var object any
	if err = decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lifecycleTestFixture(t *testing.T) lifecycleFixture {
	t.Helper()
	seed, err := hex.DecodeString(lifecycleTestSeed)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	digest := sha256.Sum256(append([]byte("cengine.storageauthority.binding.v3\x00"), []byte(lifecycleBindingJSON)...))
	f := lifecycleFixture{
		Version: LifecycleVersion, SeedHex: lifecycleTestSeed, RootPublicKey: key.Public().(ed25519.PublicKey),
		BindingJSON: lifecycleBindingJSON, BindingDigest: hex.EncodeToString(digest[:]),
	}
	identity := LifecycleIdentity{"bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb", 9007199254740993, Fingerprint(f.BindingDigest)}
	for _, item := range []struct {
		op     LifecycleOperation
		serial uint64
		epoch  uint64
	}{
		{LifecycleInitialize, 1, 0},
		{LifecycleTakeover, 9007199254740993, 9007199254740993},
		{LifecycleRetire, ^uint64(0), ^uint64(0)},
	} {
		g := LifecycleGrant{item.op, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", identity, item.serial, item.epoch, Fingerprint(strings.Repeat("ab", 32))}
		b, err := LifecycleGrantSigningBytes(g)
		if err != nil {
			t.Fatal(err)
		}
		f.Vectors = append(f.Vectors, lifecycleGrantVector{g, b, ed25519.Sign(key, b), lifecycleCanonicalJSON(t, g)})
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	r := LifecycleReceipt{f.Vectors[2].Grant, nonce, "cccccccc-cccc-4ccc-accc-cccccccccccc", ^uint64(0)}
	b, err := LifecycleReceiptSigningBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	f.Receipt = lifecycleReceiptVector{r, b, ed25519.Sign(key, b), lifecycleCanonicalJSON(t, r)}
	return f
}

// Regenerate deliberately: CENGINE_UPDATE_LIFECYCLE_FIXTURE=1 go test -mod=vendor
// ./internal/storageauthority -run '^TestLifecycleFixture$' -count=1
func TestLifecycleFixture(t *testing.T) {
	f := lifecycleTestFixture(t)
	want, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if os.Getenv("CENGINE_UPDATE_LIFECYCLE_FIXTURE") == "1" {
		if err := os.WriteFile(lifecycleFixturePath, want, 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(lifecycleFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("shared lifecycle fixture differs from deterministic Go values/signatures")
	}
	for _, v := range f.Vectors {
		var decoded LifecycleGrant
		if err := json.Unmarshal([]byte(v.CanonicalJSON), &decoded); err != nil || decoded != v.Grant {
			t.Fatalf("UInt64 canonical round trip: %v", err)
		}
		if !ed25519.Verify(f.RootPublicKey, v.SigningBytes, v.Signature) {
			t.Fatal("signature")
		}
		for _, domain := range []string{"cengine.storageauthority.takeover.v1\x00", "cengine.storageauthority.lifecycle.v1\x00", "cengine.storageauthority.lifecycle-receipt.v2\x00"} {
			body := bytes.TrimPrefix(v.SigningBytes, []byte("cengine.storageauthority.lifecycle.v2\x00"))
			if ed25519.Verify(f.RootPublicKey, append([]byte(domain), body...), v.Signature) {
				t.Fatal("signature accepted a different version/domain")
			}
		}
	}
	if !ed25519.Verify(f.RootPublicKey, f.Receipt.SigningBytes, f.Receipt.Signature) {
		t.Fatal("receipt signature")
	}
}

func TestLifecycleGrantValidation(t *testing.T) {
	base := lifecycleTestFixture(t).Vectors[1].Grant
	for name, mutate := range map[string]func(*LifecycleGrant){
		"operation":          func(g *LifecycleGrant) { g.Operation = "open" },
		"id":                 func(g *LifecycleGrant) { g.ID = "" },
		"uppercase-id":       func(g *LifecycleGrant) { g.ID = ID(strings.ToUpper(string(g.ID))) },
		"store":              func(g *LifecycleGrant) { g.Identity.Store = "bbbbbbbb-bbbb-1bbb-9bbb-bbbbbbbbbbbb" },
		"variant":            func(g *LifecycleGrant) { g.Identity.Store = "bbbbbbbb-bbbb-4bbb-cbbb-bbbbbbbbbbbb" },
		"generation":         func(g *LifecycleGrant) { g.Identity.Generation = 0 },
		"binding":            func(g *LifecycleGrant) { g.Identity.Binding = Fingerprint(strings.Repeat("A", 64)) },
		"binding-length":     func(g *LifecycleGrant) { g.Identity.Binding = "ab" },
		"serial":             func(g *LifecycleGrant) { g.Serial = 0 },
		"key":                func(g *LifecycleGrant) { g.NewKey = Fingerprint(strings.Repeat("z", 64)) },
		"initialize-epoch":   func(g *LifecycleGrant) { g.Operation = LifecycleInitialize },
		"takeover-zero":      func(g *LifecycleGrant) { g.ExpectedEpoch = 0 },
		"takeover-exhausted": func(g *LifecycleGrant) { g.ExpectedEpoch = ^uint64(0) },
		"retire-zero":        func(g *LifecycleGrant) { g.Operation = LifecycleRetire; g.ExpectedEpoch = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := base
			mutate(&bad)
			if b, err := LifecycleGrantSigningBytes(bad); err != ErrInvalid || b != nil {
				t.Fatalf("invalid grant signed: %q %v", b, err)
			}
		})
	}
	for _, op := range []LifecycleOperation{LifecycleTakeover, LifecycleRetire} {
		for _, epoch := range []uint64{1, ^uint64(0) - 1} {
			g := base
			g.Operation, g.ExpectedEpoch = op, epoch
			g.Serial, g.Identity.Generation = ^uint64(0), ^uint64(0)
			if _, err := LifecycleGrantSigningBytes(g); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestLifecycleSignatureBindsEveryGrantField(t *testing.T) {
	f := lifecycleTestFixture(t)
	v := f.Vectors[1]
	for name, mutate := range map[string]func(*LifecycleGrant){
		"operation":  func(g *LifecycleGrant) { g.Operation = LifecycleRetire },
		"id":         func(g *LifecycleGrant) { g.ID = g.Identity.Store },
		"store":      func(g *LifecycleGrant) { g.Identity.Store = g.ID },
		"generation": func(g *LifecycleGrant) { g.Identity.Generation++ },
		"binding":    func(g *LifecycleGrant) { g.Identity.Binding = Fingerprint(strings.Repeat("0", 64)) },
		"serial":     func(g *LifecycleGrant) { g.Serial++ },
		"epoch":      func(g *LifecycleGrant) { g.ExpectedEpoch++ },
		"key":        func(g *LifecycleGrant) { g.NewKey = Fingerprint(strings.Repeat("0", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			g := v.Grant
			mutate(&g)
			b, err := LifecycleGrantSigningBytes(g)
			if err != nil || ed25519.Verify(f.RootPublicKey, b, v.Signature) {
				t.Fatalf("changed grant signature: %v", err)
			}
		})
	}
}

func TestLifecycleReceiptValidationAndBinding(t *testing.T) {
	f := lifecycleTestFixture(t)
	for name, mutate := range map[string]func(*LifecycleReceipt){
		"grant":         func(r *LifecycleReceipt) { r.Grant.Serial = 0 },
		"nonce-short":   func(r *LifecycleReceipt) { r.Nonce = make([]byte, 31) },
		"nonce-long":    func(r *LifecycleReceipt) { r.Nonce = make([]byte, 33) },
		"service-epoch": func(r *LifecycleReceipt) { r.ServiceEpoch = "cccccccc-cccc-1ccc-accc-cccccccccccc" },
		"revision":      func(r *LifecycleReceipt) { r.Revision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			r := f.Receipt.Value
			mutate(&r)
			if b, err := LifecycleReceiptSigningBytes(r); err != ErrInvalid || b != nil {
				t.Fatalf("invalid receipt signed: %q %v", b, err)
			}
		})
	}
	for _, mutate := range []func(*LifecycleReceipt){
		func(r *LifecycleReceipt) { r.Grant.Serial-- },
		func(r *LifecycleReceipt) { r.Nonce = bytes.Repeat([]byte{255}, 32) },
		func(r *LifecycleReceipt) { r.ServiceEpoch = r.Grant.ID },
		func(r *LifecycleReceipt) { r.Revision-- },
	} {
		r := f.Receipt.Value
		mutate(&r)
		b, err := LifecycleReceiptSigningBytes(r)
		if err != nil || ed25519.Verify(f.RootPublicKey, b, f.Receipt.Signature) {
			t.Fatalf("changed receipt signature: %v", err)
		}
	}
}
