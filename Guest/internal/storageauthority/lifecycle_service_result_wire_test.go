package storageauthority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

const lifecycleServiceResultFixturePath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-service-result-v2.json"

type lifecycleServiceResultVector struct {
	Value         LifecycleServiceResult `json:"value"`
	SigningBytes  []byte                 `json:"signing_bytes"`
	Signature     []byte                 `json:"signature"`
	CanonicalJSON string                 `json:"canonical_json"`
	RequestJSON   string                 `json:"request_json"`
	ResponseJSON  string                 `json:"response_json"`
}
type lifecycleServiceResultFixture struct {
	Version       string                         `json:"version"`
	SeedHex       string                         `json:"seed_hex"`
	RootPublicKey []byte                         `json:"root_public_key"`
	Vectors       []lifecycleServiceResultVector `json:"vectors"`
}

// Regenerate only this new contract: CENGINE_UPDATE_LIFECYCLE_SERVICE_RESULT_FIXTURE=1
// go test -mod=vendor ./internal/storageauthority -run '^TestLifecycleServiceResultFixture$' -count=1
func TestLifecycleServiceResultFixture(t *testing.T) {
	base := lifecycleTestFixture(t)
	seed, err := hex.DecodeString(lifecycleTestSeed)
	must(t, err)
	key := ed25519.NewKeyFromSeed(seed)
	f := lifecycleServiceResultFixture{Version: "storage-lifecycle-service-result.v2", SeedHex: lifecycleTestSeed, RootPublicKey: base.RootPublicKey}
	for _, grant := range []LifecycleGrant{base.Vectors[0].Grant, base.Vectors[1].Grant} {
		r := LifecycleServiceResult{grant.Identity, grant, bytes.Clone(base.Receipt.Value.Nonce), base.Receipt.Value.ServiceEpoch, grant.ExpectedEpoch + 1, grant.NewKey, ^uint64(0)}
		b, err := LifecycleServiceResultSigningBytes(r)
		must(t, err)
		request := map[string]any{"id": uint64(1), "service_result": map[string]any{"grant": grant, "nonce": r.Nonce}}
		response := map[string]any{"id": uint64(1), "service_result": r}
		v := lifecycleServiceResultVector{r, b, ed25519.Sign(key, b), lifecycleCanonicalJSON(t, r), lifecycleCanonicalJSON(t, request), lifecycleCanonicalJSON(t, response)}
		f.Vectors = append(f.Vectors, v)
		var decoded LifecycleServiceResult
		must(t, json.Unmarshal([]byte(v.CanonicalJSON), &decoded))
		if !reflect.DeepEqual(decoded, r) || !ed25519.Verify(key.Public().(ed25519.PublicKey), b, v.Signature) {
			t.Fatal("round trip/signature")
		}
		for _, domain := range []string{"cengine.storageauthority.lifecycle-receipt.v2\x00", "cengine.storageauthority.lifecycle.v2\x00", "cengine.storageauthority.lifecycle-service-result.v1\x00"} {
			body := bytes.TrimPrefix(b, []byte("cengine.storageauthority.lifecycle-service-result.v2\x00"))
			if ed25519.Verify(key.Public().(ed25519.PublicKey), append([]byte(domain), body...), v.Signature) {
				t.Fatal("domain alias")
			}
		}
	}
	want, err := json.MarshalIndent(f, "", "  ")
	must(t, err)
	want = append(want, '\n')
	if os.Getenv("CENGINE_UPDATE_LIFECYCLE_SERVICE_RESULT_FIXTURE") == "1" {
		must(t, os.WriteFile(lifecycleServiceResultFixturePath, want, 0644))
	}
	got, err := os.ReadFile(lifecycleServiceResultFixturePath)
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatal("frozen live-service signing/transport fixture drift")
	}
}

func TestLifecycleServiceResultValidationAndSigningBinding(t *testing.T) {
	f := lifecycleTestFixture(t)
	g := f.Vectors[1].Grant
	base := LifecycleServiceResult{g.Identity, g, bytes.Clone(f.Receipt.Value.Nonce), f.Receipt.Value.ServiceEpoch, g.ExpectedEpoch + 1, g.NewKey, ^uint64(0)}
	for name, change := range map[string]func(*LifecycleServiceResult){
		"identity":    func(r *LifecycleServiceResult) { r.Identity.Generation++ },
		"grant":       func(r *LifecycleServiceResult) { r.Grant.Serial = 0 },
		"retire":      func(r *LifecycleServiceResult) { r.Grant.Operation = LifecycleRetire },
		"operation":   func(r *LifecycleServiceResult) { r.Grant.Operation = "open" },
		"nonce-short": func(r *LifecycleServiceResult) { r.Nonce = make([]byte, 31) },
		"nonce-long":  func(r *LifecycleServiceResult) { r.Nonce = make([]byte, 33) },
		"E":           func(r *LifecycleServiceResult) { r.ServiceEpoch = "" },
		"C":           func(r *LifecycleServiceResult) { r.ControllerEpoch++ },
		"key":         func(r *LifecycleServiceResult) { r.ControllerKey = "" },
		"revision":    func(r *LifecycleServiceResult) { r.OpenRevision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			change(&r)
			b, err := LifecycleServiceResultSigningBytes(r)
			if err != ErrInvalid || b != nil {
				t.Fatal("invalid result signed", err)
			}
		})
	}
	seed, err := hex.DecodeString(lifecycleTestSeed)
	must(t, err)
	key := ed25519.NewKeyFromSeed(seed)
	b, err := LifecycleServiceResultSigningBytes(base)
	must(t, err)
	sig := ed25519.Sign(key, b)
	for _, change := range []func(*LifecycleServiceResult){
		func(r *LifecycleServiceResult) { r.Identity.Store = g.ID; r.Grant.Identity = r.Identity },
		func(r *LifecycleServiceResult) { r.Identity.Generation++; r.Grant.Identity = r.Identity },
		func(r *LifecycleServiceResult) { r.Identity.Binding = g.NewKey; r.Grant.Identity = r.Identity },
		func(r *LifecycleServiceResult) { r.Grant.ID = g.Identity.Store },
		func(r *LifecycleServiceResult) { r.Grant.Serial++ },
		func(r *LifecycleServiceResult) { r.Nonce = bytes.Repeat([]byte{255}, 32) },
		func(r *LifecycleServiceResult) { r.ServiceEpoch = g.ID },
		func(r *LifecycleServiceResult) { r.ControllerEpoch++; r.Grant.ExpectedEpoch++ },
		func(r *LifecycleServiceResult) {
			r.ControllerKey = g.Identity.Binding
			r.Grant.NewKey = r.ControllerKey
		},
		func(r *LifecycleServiceResult) { r.OpenRevision-- },
	} {
		r := base
		change(&r)
		b, err := LifecycleServiceResultSigningBytes(r)
		must(t, err)
		if ed25519.Verify(key.Public().(ed25519.PublicKey), b, sig) {
			t.Fatal("signature ignored field")
		}
	}
}
