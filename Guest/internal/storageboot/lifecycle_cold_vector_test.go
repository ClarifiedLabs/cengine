package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

const lifecycleColdVectorPath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-cold-open-v1.json"

type lifecycleColdVector struct {
	Version              string `json:"version"`
	RootSeed             []byte `json:"root_seed"`
	RootPublicKey        []byte `json:"root_public_key"`
	SigningBytes         []byte `json:"signing_bytes"`
	TakeoverSigningBytes []byte `json:"takeover_signing_bytes"`
	RequestSHA256        string `json:"request_sha256"`
	Signature            []byte `json:"signature"`
	CanonicalFrame       string `json:"canonical_frame"`
}

// All three keys and all IDs are deterministic. These are public test keys only.
func deterministicLifecycleColdVector(t *testing.T) lifecycleColdVector {
	t.Helper()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	root := ed25519.NewKeyFromSeed(seed)
	pin := func(seed byte) a.Fingerprint {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		p, err := a.PublicKeyFingerprint(key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	previous := a.LifecycleGrant{
		Operation: a.LifecycleTakeover, ID: "dddddddd-dddd-4ddd-bddd-dddddddddddd",
		Identity: a.LifecycleIdentity{Store: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Generation: 9007199254740993, Binding: a.Fingerprint(strings.Repeat("a", 64))},
		Serial:   ^uint64(0) - 1, ExpectedEpoch: 9007199254740992, NewKey: pin(8),
	}
	grant := previous
	grant.ID, grant.Serial, grant.ExpectedEpoch, grant.NewKey = "99999999-9999-4999-8999-999999999999", ^uint64(0), previous.ExpectedEpoch+1, pin(9)
	grantBytes, err := a.LifecycleGrantSigningBytes(grant)
	if err != nil {
		t.Fatal(err)
	}
	takeover := a.SignedLifecycleGrant{Grant: grant, Signature: ed25519.Sign(root, grantBytes)}
	binding := lifecycleTestBinding()
	binding.Bytes = 1<<63 - 1
	request := a.LifecycleColdOpenRequest{
		OperationID:    grant.ID,
		Predecessor:    a.LifecycleColdPredecessor{CurrentGrant: previous, ServiceEpoch: "ffffffff-ffff-4fff-9fff-ffffffffffff", ControllerEpoch: grant.ExpectedEpoch, ControllerKey: previous.NewKey, OpenRevision: ^uint64(0), BootstrapKey: pin(7)},
		Takeover:       takeover,
		Launch:         a.LifecycleColdLaunch{ShimLaunchUUID: a.ID(binding.ShimLaunchUUID), SpecSHA256: strings.Repeat("b", 64), InitramfsSHA256: strings.Repeat("c", 64), Ext4UUID: binding.Ext4UUID, Bytes: binding.Bytes},
		NowUnixSeconds: 1800000000, LifetimeSeconds: 3600,
	}
	msg, err := a.LifecycleColdOpenSigningBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	signed := a.SignedLifecycleColdOpen{Request: request, Signature: ed25519.Sign(root, msg)}
	frame := lifecycleFrame("configure", binding)
	frame.Configuration = &LifecycleConfiguration{Action: "cold-open-takeover", RootPublicKey: root.Public().(ed25519.PublicKey), Signed: takeover, NowUnixSeconds: request.NowUnixSeconds, LifetimeSeconds: request.LifetimeSeconds, Cold: &signed}
	raw, err := EncodeLifecycleFrame(&frame)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	return lifecycleColdVector{"lifecycle-cold-open.v1", seed, root.Public().(ed25519.PublicKey), msg, grantBytes, hex.EncodeToString(digest[:]), signed.Signature, string(raw[4:])}
}

func TestLifecycleColdSharedVector(t *testing.T) {
	want := deterministicLifecycleColdVector(t)
	if os.Getenv("UPDATE_LIFECYCLE_COLD_FIXTURE") == "1" {
		raw, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(lifecycleColdVectorPath, append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(lifecycleColdVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector lifecycleColdVector
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vector, want) {
		t.Fatal("deterministic signing bytes, digest, signatures or closed frame changed")
	}
	frame, err := DecodeLifecycleFrame([]byte(vector.CanonicalFrame))
	if err != nil {
		t.Fatal(err)
	}
	cold := frame.Configuration.Cold
	if err = a.VerifyLifecycleColdOpen(ed25519.PublicKey(vector.RootPublicKey), *cold); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(vector.RootPublicKey, vector.TakeoverSigningBytes, cold.Request.Takeover.Signature) {
		t.Fatal("inner signature")
	}
	encoded, err := EncodeLifecycleFrame(frame)
	if err != nil || string(encoded[4:]) != vector.CanonicalFrame {
		t.Fatal("canonical roundtrip", err)
	}
	if _, err = ReadLifecycleFrame(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2]string{
		"unknown":   {`"cold":{`, `"cold":{"unknown":true,`},
		"null":      {`"cold":{`, `"reopen":null,"cold":{`},
		"duplicate": {`"open_revision":18446744073709551615`, `"open_revision":18446744073709551615,"open_revision":18446744073709551615`},
		"exponent":  {`9007199254740993`, `9.007199254740993e15`},
		"fraction":  {`9007199254740993`, `9007199254740993.0`},
		"overflow":  {`18446744073709551615`, `18446744073709551616`},
		"action":    {`"cold-open-takeover"`, `"open"`},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.ReplaceAll(vector.CanonicalFrame, pair[0], pair[1])
			if bad == vector.CanonicalFrame {
				t.Fatal("mutation missed")
			}
			if _, err := DecodeLifecycleFrame([]byte(bad)); err == nil {
				t.Fatal("accepted mutation")
			}
		})
	}
}

func TestLifecycleColdVectorAuthorityAndBootTimeBounds(t *testing.T) {
	vector := deterministicLifecycleColdVector(t)
	frame, err := DecodeLifecycleFrame([]byte(vector.CanonicalFrame))
	if err != nil {
		t.Fatal(err)
	}
	cfg := frame.Configuration
	// Authority admits through year 9999 if the lifetime fits. Boot intentionally
	// reserves a full day, irrespective of the requested shorter lifetime.
	for _, tc := range []struct {
		now, lifetime   uint64
		authority, boot bool
	}{
		{253402214399, 86400, true, true}, {253402214400, 1, true, false},
		{253402300798, 1, true, false}, {253402300799, 1, false, false},
		{253402300798, 2, false, false}, {0, 1, false, false},
		{1800000000, 0, false, false}, {1800000000, 86401, false, false},
	} {
		c := copyLifecycleConfiguration(*cfg)
		c.NowUnixSeconds, c.LifetimeSeconds = tc.now, tc.lifetime
		c.Cold.Request.NowUnixSeconds, c.Cold.Request.LifetimeSeconds = tc.now, tc.lifetime
		msg, err := a.LifecycleColdOpenSigningBytes(c.Cold.Request)
		if (err == nil) != tc.authority {
			t.Fatalf("authority %v: %v", tc, err)
		}
		if err == nil {
			c.Cold.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(vector.RootSeed), msg)
		}
		if (c.validate() == nil) != tc.boot {
			t.Fatalf("boot %v", tc)
		}
	}
}
