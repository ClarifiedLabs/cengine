package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

const lifecycleChildServiceFixturePath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-child-service-v2.json"

type lifecycleChildServiceVector struct {
	Name                   string                        `json:"name"`
	Challenge              LifecycleChildChallengeFields `json:"challenge"`
	Reply                  LifecycleChildReplyFields     `json:"reply"`
	ChallengeCanonicalJSON string                        `json:"challenge_canonical_json"`
	ReplyCanonicalJSON     string                        `json:"reply_canonical_json"`
	ChallengeSHA256        []byte                        `json:"challenge_sha256"`
	SigningBytes           []byte                        `json:"signing_bytes"`
}

type lifecycleChildServiceFixture struct {
	Version           string                        `json:"version"`
	ControllerSeedHex string                        `json:"controller_seed_hex"`
	RootSeedHex       string                        `json:"root_seed_hex"`
	Vectors           []lifecycleChildServiceVector `json:"vectors"`
}

func lifecycleChildServiceResult(c LifecycleChildChallenge, revision uint64) *a.LifecycleServiceResult {
	nonce, _ := base64.StdEncoding.DecodeString(c.fields.Nonce)
	return &a.LifecycleServiceResult{Identity: c.fields.Grant.Identity, Grant: c.fields.Grant, Nonce: nonce,
		ServiceEpoch: a.ID(c.fields.Boot.ServiceEpoch), ControllerEpoch: c.fields.Grant.ExpectedEpoch + 1,
		ControllerKey: c.fields.Grant.NewKey, OpenRevision: revision}
}

func lifecycleChildServiceVectorReply(t *testing.T, k Key, c LifecycleChildChallenge, result *a.LifecycleServiceResult) LifecycleChildReply {
	t.Helper()
	f := LifecycleChildReplyFields{Version: LifecycleChildVersion, ChallengeSHA256: base64.StdEncoding.EncodeToString(c.Digest()),
		ServiceResult: result, Signature: base64.StdEncoding.EncodeToString(make([]byte, 64))}
	r, err := NewLifecycleChildReply(f)
	if err != nil {
		t.Fatal(err)
	}
	// Historical public vectors bypass only the wall-clock check, inside tests.
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.private(), r.SigningBytes()))
	r, err = NewLifecycleChildReply(f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func buildLifecycleChildServiceFixture(t *testing.T) lifecycleChildServiceFixture {
	t.Helper()
	k, f := lifecycleChildVectorFields(t)
	f.Purpose = LifecycleChildServiceResult
	f.Boot = lifecycleChildTestBoot(t, f)
	fixture := lifecycleChildServiceFixture{Version: LifecycleChildVersion, ControllerSeedHex: lifecycleChildControllerSeed, RootSeedHex: lifecycleChildRootSeed}
	add := func(name string, revision uint64) LifecycleServiceState {
		c := lifecycleChildTestChallenge(t, f)
		result := lifecycleChildServiceResult(c, revision)
		r := lifecycleChildServiceVectorReply(t, k, c, result)
		state, err := LifecycleServiceStateFromResult(*result, *f.Boot)
		if err != nil || !r.Verifies(c) {
			t.Fatal("service vector", err)
		}
		fixture.Vectors = append(fixture.Vectors, lifecycleChildServiceVector{Name: name, Challenge: c.Fields(), Reply: r.Fields(),
			ChallengeCanonicalJSON: string(c.Canonical()), ReplyCanonicalJSON: string(r.Canonical()), ChallengeSHA256: c.Digest(), SigningBytes: r.SigningBytes()})
		return state
	}
	prior := add("service_result", 9007199254740993)
	f.ChangeRequest = &LifecycleServiceChangeRequest{OperationID: "66666666-6666-4666-8666-666666666666", Predecessor: prior}
	f.Boot.ServiceEpoch = "77777777-7777-4777-8777-777777777777"
	f.Boot.TLSRootSHA256 = strings.Repeat("12", 32)
	f.Boot.ServerSPKI = strings.Repeat("34", 32)
	f.Counter++
	f.Nonce = f.ChildAudit
	successor := add("service_change_result", ^uint64(0))
	f.Purpose = LifecycleChildServiceCommit
	f.Confirmation = &LifecycleServiceChangeConfirmation{Request: *f.ChangeRequest, Successor: successor}
	f.ChangeRequest = nil
	f.Counter++
	f.Nonce = f.DaemonAudit
	add("service_commit", ^uint64(0))
	return fixture
}

// Regenerate only public vectors:
// CENGINE_WRITE_LIFECYCLE_CHILD_SERVICE_FIXTURE=1 go test ./internal/storagepki -run '^TestLifecycleChildServiceFixture$' -count=1
func TestLifecycleChildServiceFixture(t *testing.T) {
	want := buildLifecycleChildServiceFixture(t)
	expected, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	if os.Getenv("CENGINE_WRITE_LIFECYCLE_CHILD_SERVICE_FIXTURE") == "1" {
		if err := os.WriteFile(lifecycleChildServiceFixturePath, expected, 0644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(lifecycleChildServiceFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, expected) {
		t.Fatal("lifecycle child service fixture changed")
	}
	var fixture lifecycleChildServiceFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			c, err := DecodeLifecycleChildChallenge([]byte(v.ChallengeCanonicalJSON))
			if err != nil {
				t.Fatal(err)
			}
			r, err := DecodeLifecycleChildReply([]byte(v.ReplyCanonicalJSON))
			if err != nil || !r.Verifies(c) {
				t.Fatal("signature/correlation", err)
			}
			if !bytes.Equal(c.Digest(), v.ChallengeSHA256) || !bytes.Equal(r.SigningBytes(), v.SigningBytes) {
				t.Fatal("digest/signing bytes")
			}
			resultBytes, err := a.LifecycleServiceResultSigningBytes(*r.Fields().ServiceResult)
			if err != nil {
				t.Fatal(err)
			}
			prefix := append([]byte(lifecycleChildReplyDomain), c.Digest()...)
			prefix = append(prefix, []byte("service-result\x00")...)
			if !bytes.Equal(r.SigningBytes(), append(prefix, resultBytes...)) || strings.Contains(v.ReplyCanonicalJSON, `"receipt"`) {
				t.Fatal("wrong service signing domain or union")
			}
			if r.fields.ServiceResult.ControllerEpoch != ^uint64(0) || r.fields.ServiceResult.Identity.Generation != 9007199254740993 {
				t.Fatal("lost integer precision")
			}
		})
	}
}

func TestLifecycleChildServiceSigningAndOwnership(t *testing.T) {
	k, _ := lifecycleChildVectorFields(t)
	fixture := buildLifecycleChildServiceFixture(t)
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			f := v.Challenge
			f.ExpiresUnixMS = uint64(time.Now().UnixMilli()) + 20_000
			c := lifecycleChildTestChallenge(t, f)
			result := lifecycleChildServiceResult(c, v.Reply.ServiceResult.OpenRevision)
			r, err := k.SignLifecycleChildServiceReply(c, result)
			if err != nil || !r.Verifies(c) {
				t.Fatal("typed signing", err)
			}
			original := r.Canonical()
			result.Nonce[0] ^= 1
			result.OpenRevision = 0
			exposed := r.Fields()
			exposed.ServiceResult.Nonce[0] ^= 1
			exposed.ServiceResult.Grant.Serial--
			cf := c.Fields()
			cf.Boot.ServiceEpoch = string(cf.Grant.ID)
			if f.ChangeRequest != nil {
				f.ChangeRequest.Predecessor.OpenRevision = 0
				cf.ChangeRequest.OperationID = "bad"
			}
			if f.Confirmation != nil {
				f.Confirmation.Successor.OpenRevision = 0
				cf.Confirmation.Request.OperationID = "bad"
			}
			clear(r.Canonical())
			clear(r.SigningBytes())
			clear(c.Canonical())
			clear(c.Digest())
			if !bytes.Equal(original, r.Canonical()) || !r.Verifies(c) {
				t.Fatal("caller mutated frozen service values")
			}
			if _, err := k.SignLifecycleChildServiceReply(c, nil); err == nil {
				t.Fatal("signed nil service result")
			}
			if _, err := k.SignLifecycleChildReply(c, nil); err == nil {
				t.Fatal("old API signed service purpose")
			}
			for _, role := range []Role{ServerRole, PrepareRole, RuntimeRole, ""} {
				wrong := k
				wrong.role = role
				if _, err := wrong.SignLifecycleChildServiceReply(c, lifecycleChildServiceResult(c, v.Reply.ServiceResult.OpenRevision)); err == nil {
					t.Fatal("wrong role signed")
				}
			}
			wrong, err := NewControllerKey()
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []Key{{}, wrong} {
				if _, err := key.SignLifecycleChildServiceReply(c, lifecycleChildServiceResult(c, v.Reply.ServiceResult.OpenRevision)); err == nil {
					t.Fatal("wrong key signed")
				}
			}
			for _, expiry := range []uint64{1, uint64(time.Now().Add(-time.Second).UnixMilli()), uint64(time.Now().Add(time.Minute).UnixMilli()), ^uint64(0)} {
				cf := c.Fields()
				cf.ExpiresUnixMS = expiry
				if _, err := k.SignLifecycleChildServiceReply(lifecycleChildTestChallenge(t, cf), lifecycleChildServiceResult(c, v.Reply.ServiceResult.OpenRevision)); err == nil {
					t.Fatal("stale/future service proof signed")
				}
			}
		})
	}
	_, f := lifecycleChildVectorFields(t)
	f.ExpiresUnixMS = uint64(time.Now().UnixMilli()) + 20_000
	if _, err := k.SignLifecycleChildServiceReply(lifecycleChildTestChallenge(t, f), nil); err == nil {
		t.Fatal("service API signed candidate")
	}
}

func TestLifecycleChildServiceReplayAndResultBinding(t *testing.T) {
	k, _ := lifecycleChildVectorFields(t)
	for _, v := range buildLifecycleChildServiceFixture(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			f := v.Challenge
			f.ExpiresUnixMS = uint64(time.Now().UnixMilli()) + 20_000
			c := lifecycleChildTestChallenge(t, f)
			r := lifecycleChildServiceVectorReply(t, k, c, v.Reply.ServiceResult)
			for _, mutate := range []func(*LifecycleChildChallengeFields){
				func(f *LifecycleChildChallengeFields) { f.Counter++ },
				func(f *LifecycleChildChallengeFields) { f.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
				func(f *LifecycleChildChallengeFields) { f.Greeting.ChannelID = f.Greeting.IncarnationID },
				func(f *LifecycleChildChallengeFields) { f.Greeting.IncarnationID = f.Greeting.ChannelID },
				func(f *LifecycleChildChallengeFields) { f.ChildUniqueID-- },
				func(f *LifecycleChildChallengeFields) { f.Greeting.DaemonUniqueID++ },
				func(f *LifecycleChildChallengeFields) { f.ChildAudit = f.DaemonAudit },
				func(f *LifecycleChildChallengeFields) { f.ExpiresUnixMS-- },
			} {
				f := c.Fields()
				mutate(&f)
				if r.Verifies(lifecycleChildTestChallenge(t, f)) {
					t.Fatal("replayed service proof accepted")
				}
			}
			for _, mutate := range []func(*a.LifecycleServiceResult){
				func(r *a.LifecycleServiceResult) { r.Identity.Generation++ },
				func(r *a.LifecycleServiceResult) { r.Grant.Identity.Generation++; r.Identity = r.Grant.Identity },
				func(r *a.LifecycleServiceResult) { r.Grant.Serial-- },
				func(r *a.LifecycleServiceResult) { r.Nonce[0] ^= 1 },
				func(r *a.LifecycleServiceResult) { r.ServiceEpoch = r.Grant.ID },
				func(r *a.LifecycleServiceResult) { r.ControllerEpoch-- },
				func(r *a.LifecycleServiceResult) { r.ControllerKey = r.Identity.Binding },
				func(r *a.LifecycleServiceResult) { r.OpenRevision = 0 },
			} {
				bad := cloneLifecycleChildServiceResult(v.Reply.ServiceResult)
				mutate(bad)
				if _, err := k.SignLifecycleChildServiceReply(c, bad); err == nil {
					t.Fatal("signed mismatched result")
				}
				if bad.Validate() == nil && lifecycleChildServiceVectorReply(t, k, c, bad).Verifies(c) {
					t.Fatal("accepted signed mismatched result")
				}
			}
			if c.fields.ChangeRequest != nil || c.fields.Confirmation != nil {
				bad := cloneLifecycleChildServiceResult(v.Reply.ServiceResult)
				bad.OpenRevision = 9007199254740993
				if _, err := k.SignLifecycleChildServiceReply(c, bad); err == nil || lifecycleChildServiceVectorReply(t, k, c, bad).Verifies(c) {
					t.Fatal("accepted old open revision")
				}
			}
			fields := r.Fields()
			fields.ServiceResult.OpenRevision--
			changed, err := NewLifecycleChildReply(fields)
			if err != nil || changed.Verifies(c) {
				t.Fatal("unsigned mutation accepted", err)
			}
		})
	}
	fixture := buildLifecycleChildServiceFixture(t)
	for i, v := range fixture.Vectors {
		r, _ := NewLifecycleChildReply(v.Reply)
		for j, other := range fixture.Vectors {
			if i != j && r.Verifies(lifecycleChildTestChallenge(t, other.Challenge)) {
				t.Fatal("cross-purpose reply replay")
			}
		}
	}
}

func TestLifecycleChildServiceFieldsAndClosedWire(t *testing.T) {
	fixture := buildLifecycleChildServiceFixture(t)
	request := fixture.Vectors[1].Challenge.ChangeRequest
	confirmation := fixture.Vectors[2].Challenge.Confirmation
	for name, mutate := range map[string]func(*LifecycleChildChallengeFields){
		"missing_boot":   func(f *LifecycleChildChallengeFields) { f.Boot = nil },
		"wrong_identity": func(f *LifecycleChildChallengeFields) { f.Boot.Identity.Generation++ },
		"wrong_root":     func(f *LifecycleChildChallengeFields) { f.Boot.BootstrapKey = f.Boot.ServerSPKI },
		"candidate_change": func(f *LifecycleChildChallengeFields) {
			f.Purpose = LifecycleChildCandidate
			f.Boot = nil
			f.ChangeRequest = request
		},
		"result_change":               func(f *LifecycleChildChallengeFields) { f.Purpose = LifecycleChildResult; f.ChangeRequest = request },
		"service_result_confirmation": func(f *LifecycleChildChallengeFields) { f.Confirmation = confirmation },
		"missing_confirmation":        func(f *LifecycleChildChallengeFields) { f.Purpose = LifecycleChildServiceCommit },
		"unchanged_boot":              func(f *LifecycleChildChallengeFields) { f.ChangeRequest = request },
		"commit_wrong_boot": func(f *LifecycleChildChallengeFields) {
			f.Purpose = LifecycleChildServiceCommit
			f.Confirmation = confirmation
		},
		"retire": func(f *LifecycleChildChallengeFields) { f.Grant.Operation = a.LifecycleRetire; f.Grant.ExpectedEpoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			c := lifecycleChildTestChallenge(t, fixture.Vectors[0].Challenge)
			f := c.Fields()
			mutate(&f)
			if _, err := NewLifecycleChildChallenge(f); err == nil {
				t.Fatal("invalid service challenge accepted")
			}
		})
	}
	for _, v := range fixture.Vectors[1:] {
		c := lifecycleChildTestChallenge(t, v.Challenge)
		f := c.Fields()
		if f.ChangeRequest != nil {
			f.ChangeRequest.Predecessor.Grant.Serial--
		} else {
			f.Confirmation.Request.Predecessor.Grant.Serial--
			f.Confirmation.Successor.Grant.Serial--
		}
		if _, err := NewLifecycleChildChallenge(f); err == nil {
			t.Fatal("mismatched nested grant accepted")
		}
		f = c.Fields()
		if f.Confirmation != nil {
			f.ChangeRequest = request
			if _, err := NewLifecycleChildChallenge(f); err == nil {
				t.Fatal("commit with change request accepted")
			}
		}
	}
	for _, v := range fixture.Vectors {
		f := v.Reply
		f.Receipt = &a.LifecycleReceipt{Grant: f.ServiceResult.Grant, Nonce: f.ServiceResult.Nonce, ServiceEpoch: f.ServiceResult.ServiceEpoch, Revision: 1}
		if _, err := NewLifecycleChildReply(f); err == nil {
			t.Fatal("receipt/service union accepted")
		}
		for _, wire := range []struct {
			text  string
			reply bool
		}{{v.ChallengeCanonicalJSON, false}, {v.ReplyCanonicalJSON, true}} {
			b := wire.text
			bad := []string{b + "\n", " " + b, b + "{}", "null", "{}", strings.Replace(b, `"version":`, `"extra":null,"version":`, 1),
				strings.Replace(b, `"version":`, `"version":"`+LifecycleChildVersion+`","version":`, 1),
				strings.Replace(b, `"version":`, `"receipt":null,"version":`, 1),
				strings.Replace(b, `"version":`, `"service_result":null,"version":`, 1),
				strings.Replace(b, `"version":`, `"change_request":null,"version":`, 1),
				strings.Replace(b, `"version":`, `"confirmation":null,"version":`, 1),
				strings.Replace(b, `"nonce":"`, `"nonce":"\n`, 1)}
			for _, token := range []string{`"change_request":{`, `"confirmation":{`, `"request":{`, `"predecessor":{`, `"successor":{`, `"context":{`, `"boot":{`, `"identity":{`, `"grant":{`, `"service_result":{`} {
				if strings.Contains(b, token) {
					bad = append(bad, strings.Replace(b, token, token+`"unknown":0,`, 1), strings.Replace(b, token, token+`"unknown":null,`, 1))
				}
			}
			// Exercise every UInt64 at every depth without float64 conversion.
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
			for _, text := range bad {
				var err error
				if wire.reply {
					_, err = DecodeLifecycleChildReply([]byte(text))
				} else {
					_, err = DecodeLifecycleChildChallenge([]byte(text))
				}
				if err == nil {
					t.Fatalf("accepted noncanonical service wire: %s", text)
				}
			}
		}
	}
}
