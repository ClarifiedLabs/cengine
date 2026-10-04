package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

// resumeTestConfiguration builds the exact signed fresh-init resume
// configuration: ROOT signs the inner takeover grant and the outer resume-open
// request; the original initialize grant is unsigned by design.
func resumeTestConfiguration(t *testing.T) (ed25519.PrivateKey, LifecycleConfiguration) {
	t.Helper()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pin := func(seed byte) a.Fingerprint {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		p, err := a.PublicKeyFingerprint(key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	binding := lifecycleTestBinding()
	original := a.LifecycleGrant{
		Operation: a.LifecycleInitialize, ID: "11111111-1111-4111-8111-111111111111",
		Identity: a.LifecycleIdentity{Store: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Generation: 1, Binding: pin(3)},
		Serial:   1, ExpectedEpoch: 0, NewKey: pin(4),
	}
	takeoverGrant := a.LifecycleGrant{
		Operation: a.LifecycleTakeover, ID: "99999999-9999-4999-8999-999999999999",
		Identity: original.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: pin(9),
	}
	grantBytes, err := a.LifecycleGrantSigningBytes(takeoverGrant)
	if err != nil {
		t.Fatal(err)
	}
	takeover := a.SignedLifecycleGrant{Grant: takeoverGrant, Signature: ed25519.Sign(root, grantBytes)}
	request := a.LifecycleResumeOpenRequest{
		OperationID: takeoverGrant.ID,
		Original:    original,
		Takeover:    takeover,
		Launch: a.LifecycleColdLaunch{ShimLaunchUUID: a.ID(binding.ShimLaunchUUID), SpecSHA256: strings.Repeat("b", 64),
			InitramfsSHA256: strings.Repeat("c", 64), Ext4UUID: binding.Ext4UUID, Bytes: binding.Bytes},
		NowUnixSeconds: 1800000000, LifetimeSeconds: 3600,
	}
	msg, err := a.LifecycleResumeOpenSigningBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	signed := a.SignedLifecycleResumeOpen{Request: request, Signature: ed25519.Sign(root, msg)}
	return root, LifecycleConfiguration{Action: "resume-open-takeover", RootPublicKey: root.Public().(ed25519.PublicKey),
		Signed: takeover, NowUnixSeconds: request.NowUnixSeconds, LifetimeSeconds: request.LifetimeSeconds, Resume: &signed}
}

func TestLifecycleResumeOpenWireRoundTrip(t *testing.T) {
	root, cfg := resumeTestConfiguration(t)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyLifecycleResumeOpen(ed25519.PublicKey(cfg.RootPublicKey), *cfg.Resume); err != nil {
		t.Fatal(err)
	}
	frame := lifecycleFrame("configure", lifecycleTestBinding())
	frame.Configuration = &cfg
	raw, err := EncodeLifecycleFrame(&frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLifecycleFrame(raw[4:])
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeLifecycleFrame(decoded)
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("canonical roundtrip", err)
	}
	// Cold stays absent (closed optional tag): the frame must not grow a
	// "resume":null spelling for other actions, and cold frames stay valid.
	if strings.Contains(string(raw[4:]), `"cold"`) {
		t.Fatal("resume frame carries cold tag")
	}
	if !lifecycleColdBindingValid(cfg, frame.Binding) {
		t.Fatal("resume launch facts must match the 4105 binding")
	}
	wrongBinding := frame.Binding
	wrongBinding.Bytes++
	if lifecycleColdBindingValid(cfg, wrongBinding) {
		t.Fatal("binding mismatch admitted")
	}
	_ = root
}

func TestLifecycleResumeOpenWireRejectsMutations(t *testing.T) {
	_, cfg := resumeTestConfiguration(t)
	frame := lifecycleFrame("configure", lifecycleTestBinding())
	frame.Configuration = &cfg
	raw, err := EncodeLifecycleFrame(&frame)
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(raw[4:])
	for name, pair := range map[string][2]string{
		"action":       {`"resume-open-takeover"`, `"cold-open-takeover"`},
		"unknown":      {`"resume":{`, `"resume":{"unknown":true,`},
		"duplicate":    {`"operation_id":`, `"operation_id":"99999999-9999-4999-8999-999999999999","operation_id":`},
		"exponent":     {`"serial":2`, `"serial":2e0`},
		"fraction":     {`"bytes":104857600`, `"bytes":104857600.0`},
		"original-sig": {`"original":{`, `"original":{"signature":"AA==","`},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.ReplaceAll(canonical, pair[0], pair[1])
			if bad == canonical {
				t.Fatal("mutation missed")
			}
			if _, err := DecodeLifecycleFrame([]byte(bad)); err == nil {
				t.Fatal("accepted mutation")
			}
		})
	}
	// Structural mutations that survive transport decoding must fail validate.
	other := cfg
	other.Action = "initialize"
	if other.validate() == nil {
		t.Fatal("initialize action with resume authorization")
	}
	other = cfg
	other.Action = "open" // resume authorization cannot pose as a reopen
	other.Reopen = nil
	if other.validate() == nil {
		t.Fatal("open action with resume authorization")
	}
	other = cfg
	other.NowUnixSeconds++ // drifted from the signed request
	if other.validate() == nil {
		t.Fatal("clock drift from signed resume request")
	}
	other = cfg
	other.Signed.Grant.Serial++ // not the exact signed takeover
	if other.validate() == nil {
		t.Fatal("boot grant differs from resume takeover")
	}
}

func TestLifecycleResumeSupervisorReadyAdmission(t *testing.T) {
	// Exercise the actual supervisor, including the exact-genesis revision-2
	// branch, rather than mirroring its predicate in the test.
	_, cfg := resumeTestConfiguration(t)
	ok := func(epoch uint64, openRevision uint64, serviceEpoch string) bool {
		starter := &fakeLifecycleStarter{mutate: func(r *LifecycleReady) {
			r.ControllerEpoch, r.Revision, r.OpenRevision, r.ServiceEpoch = epoch, openRevision, openRevision, serviceEpoch
		}}
		supervisor, err := newLifecycleSupervisor(cfg, starter.start(t))
		if supervisor != nil {
			defer supervisor.close()
		}
		return err == nil
	}
	if !ok(2, 1, "ffffffff-ffff-4fff-9fff-ffffffffffff") {
		t.Fatal("exact resume successor refused")
	}
	if ok(1, 1, "ffffffff-ffff-4fff-9fff-ffffffffffff") {
		t.Fatal("controller epoch 1 admitted for resume")
	}
	if !ok(2, 2, "ffffffff-ffff-4fff-9fff-ffffffffffff") {
		t.Fatal("exact unused genesis successor refused")
	}
	if ok(2, 3, "ffffffff-ffff-4fff-9fff-ffffffffffff") {
		t.Fatal("advanced open revision admitted for resume")
	}
	if ok(2, 1, "") {
		t.Fatal("empty service epoch admitted for resume")
	}
}
