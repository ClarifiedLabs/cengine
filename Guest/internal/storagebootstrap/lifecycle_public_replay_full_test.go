//go:build cengine_prepare_full_compat

package storagebootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

// Join two honest TLS takeovers, retaining only public OLD between generations.
func publicReplayFixture(t *testing.T) (*lifecycleSessionFixture, a.SignedLifecycleGrant) {
	t.Helper()
	f := newLifecycleSessionFixture(t, true)
	f.connect(t)
	check(t, f.s.takeover(t.Context()))
	old := f.owner
	f.s.close()
	f.cfg.expectedEpoch = 2
	var err error
	f.s, err = newLifecycleSession(f.cfg)
	check(t, err)
	t.Cleanup(f.s.close)
	g := old.Grant
	g.ID, g.Serial, g.ExpectedEpoch, g.NewKey = lifecycleSessionID(t), g.Serial+1, 2, a.Fingerprint(lifecycleSessionPin(t, f.s).String())
	f.owner = lifecycleSessionSign(t, f.rootPrivate, g)
	lifecycleSessionProof(t, f, f.challenge(t, 1, p.LifecycleChildCandidate, g))
	check(t, f.s.bindGrant(f.owner))
	serverKey, err := p.NewServerKey()
	check(t, err)
	binding, err := p.NewServerBinding(p.StoreID(g.Identity.Store), p.ServiceEpoch(f.authority.Epoch()))
	check(t, err)
	csr, err := serverKey.CSR(binding)
	check(t, err)
	cert, err := f.issuer.IssueServer(csr, binding, f.now, time.Hour)
	check(t, err)
	identity, err := cert.WithKey(serverKey)
	check(t, err)
	pin, err := serverKey.Fingerprint()
	check(t, err)
	controllerBinding, err := p.NewControllerBinding(p.StoreID(g.Identity.Store), 3)
	check(t, err)
	csr, err = f.s.controllerCSR()
	check(t, err)
	controllerCert, err := f.issuer.IssueController(csr, controllerBinding, f.now, time.Hour)
	check(t, err)
	f.boot = lifecycleBoot{identity: g.Identity, signed: f.owner, serviceEpoch: f.authority.Epoch(), root: f.issuer.Root(), serverPin: pin, certificate: controllerCert}
	var oldPin p.Fingerprint
	// The server's immutable known current configuration is the previously applied OLD.
	oldPinBytes, err := hex.DecodeString(string(old.Grant.NewKey))
	check(t, err)
	copy(oldPin[:], oldPinBytes)
	f.server, err = c.NewLifecycleServer(f.authority, c.LifecycleServerConfig{Identity: identity, ClientRoot: f.issuer.Root(), ServiceEpoch: f.authority.Epoch(), CurrentGrant: old.Grant, ControllerKey: oldPin, SuccessorGrant: g, SuccessorKey: lifecycleSessionPin(t, f.s)})
	check(t, err)
	f.connect(t)
	return f, old
}
func replayBody(t *testing.T, old a.SignedLifecycleGrant) []byte {
	t.Helper()
	b, err := canonicalBytes(lifecyclePublicReplayRequest{1, string(lifecycleSessionID(t)), old})
	check(t, err)
	return b
}
func TestLifecyclePublicReplayActualTLSThenNormalTakeover(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("mixed profiles disabled")
	}
	f, old := publicReplayFixture(t)
	before, err := f.authority.LifecycleMetadata()
	check(t, err)
	// Normal Takeover must still reject OLD locally.
	if _, err := f.s.client.Takeover(t.Context(), old); err == nil {
		t.Fatal("local OLD accepted")
	}
	body := replayBody(t, old)
	raw, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("public-takeover-replay", body), nil)
	check(t, err)
	var observation lifecyclePublicReplayObservation
	check(t, canonical(raw, &observation))
	if observation.Error != c.Unauthorized || observation.Old.Grant != old.Grant || !bytes.Equal(observation.Pending.Signature, f.owner.Signature) {
		t.Fatal("uncorrelated observation")
	}
	after, err := f.authority.LifecycleMetadata()
	check(t, err)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("replay mutated state")
	}
	if _, err := f.s.publicTakeoverReplay(t.Context(), body); err == nil {
		t.Fatal("repeat")
	}
	check(t, f.s.takeover(t.Context()))
	lifecycleSessionProof(t, f, f.challenge(t, 2, p.LifecycleChildResult, f.owner.Grant))
}
func TestLifecyclePublicReplayRefusals(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("mixed profiles disabled")
	}
	for _, kind := range []string{"signature", "pending-signature", "pending-candidate", "same-id", "identity", "initialize", "epoch", "serial", "key", "normal-attempt", "post-takeover", "rebind", "retired", "revoked", "cancel", "eof", "unknown", "duplicate", "null", "fraction", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			f, old := publicReplayFixture(t)
			ctx := t.Context()
			switch kind {
			case "pending-signature":
				f.s.owner.Signature = bytes.Repeat([]byte{1}, 64)
			case "pending-candidate":
				f.s.candidateOwner.ID = lifecycleSessionID(t)
			case "same-id":
				old.Grant.ID = f.owner.Grant.ID
				old = lifecycleSessionSign(t, f.rootPrivate, old.Grant)
			case "signature":
				old.Signature = bytes.Repeat([]byte{1}, 64)
			case "identity":
				old.Grant.Identity.Generation++
				old = lifecycleSessionSign(t, f.rootPrivate, old.Grant)
			case "initialize":
				old.Grant.Operation = a.LifecycleInitialize
				old.Grant.ExpectedEpoch = 0
				old = lifecycleSessionSign(t, f.rootPrivate, old.Grant)
			case "epoch":
				old.Grant.ExpectedEpoch++
				old = lifecycleSessionSign(t, f.rootPrivate, old.Grant)
			case "serial":
				old.Grant.Serial = f.owner.Grant.Serial
				old = lifecycleSessionSign(t, f.rootPrivate, old.Grant)
			case "key":
				old.Grant.NewKey = f.owner.Grant.NewKey
				old = lifecycleSessionSign(t, f.rootPrivate, old.Grant)
			case "normal-attempt":
				f.s.normalTakeoverAttempted = true
			case "post-takeover":
				check(t, f.s.takeover(ctx))
			case "rebind":
				f.s.pendingRebind = &lifecyclePendingRebind{}
			case "retired":
				f.s.retirement = f.owner
			case "revoked":
				f.s.close()
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "eof":
				f.peer.Close()
			}
			body := replayBody(t, old)
			switch kind {
			case "unknown":
				body = append([]byte(`{"extra":0,`), body[1:]...)
			case "duplicate":
				body = bytes.Replace(body, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			case "null":
				body = bytes.Replace(body, []byte(`"version":1`), []byte(`"version":null`), 1)
			case "fraction":
				body = bytes.Replace(body, []byte(`"version":1`), []byte(`"version":1.0`), 1)
			case "oversize":
				body = bytes.Repeat([]byte{' '}, 4097)
			}
			if raw, err := f.s.publicTakeoverReplay(ctx, body); err == nil || len(raw) != 0 {
				t.Fatal("bad probe passed")
			}
			if kind == "eof" && !f.s.publicTakeoverReplayUsed {
				t.Fatal("failed IO not consumed")
			}
		})
	}
}

func TestLifecyclePublicReplayMixedProfilesRefuse(t *testing.T) {
	if pc.CurrentProfile() == pc.FullProfile {
		t.Skip("single full profile")
	}
	var s lifecycleSession
	if raw, err := s.publicTakeoverReplay(t.Context(), []byte(`{}`)); err == nil || len(raw) != 0 || s.publicTakeoverReplayUsed {
		t.Fatal("mixed profile admitted replay")
	}
}
