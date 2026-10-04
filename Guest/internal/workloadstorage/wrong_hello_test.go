package workloadstorage

import (
	cc "dev.cengine/guest/internal/consumercompat"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	"encoding/json"
	"testing"
	"time"
)

func TestOriginalWrongHelloVersionAndCurrentTrust(t *testing.T) {
	_, _, _, scope, peer := originalIdentities(t)
	for _, name := range []string{cc.WrongVolume, cc.WrongKey, cc.WrongRole, cc.WrongMode, cc.WrongEpoch} {
		arm := originalTestArm()
		arm.Version = 2
		arm.CaseName = name
		arm.Scope = scope
		if !arm.valid() {
			t.Fatal(name)
		}
		old := arm
		old.Version = 1
		if old.valid() {
			t.Fatal("version downgrade")
		}
		owner := &originalConsumer{arm: arm, peer: peer}
		q := OriginalConsumerProbe{Arm: arm, Scope: scope, Peer: peer}
		if !owner.validTrust(q) {
			t.Fatal("current trust rejected")
		}
		q.Scope.ServiceEpoch = arm.Binding.ShimLaunchUUID
		if owner.validTrust(q) {
			t.Fatal("successor trust accepted")
		}
		q.Scope = scope
		q.Peer.ServerDER = append([]byte{}, peer.ServerDER...)
		q.Peer.ServerDER[0] ^= 1
		if owner.validTrust(q) {
			t.Fatal("changed exact server accepted")
		}
	}
}
func TestOriginalWrongHelloSealedSelectionRefusesMissingIssuedSlots(t *testing.T) {
	s, arm, _ := originalInstalledSession(t)
	e := s.entries[arm.TargetAttachment]
	key, err := e.key.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	h := a.DataHello{Epoch: a.ID(s.scope.ServiceEpoch), Binding: a.Binding{Store: a.ID(s.scope.Store), Volume: a.ID(e.slot.Volume), Attachment: a.ID(e.slot.Attachment), Container: a.ContainerID(s.scope.Container), Launch: a.ID(s.scope.Launch), Key: a.Fingerprint(key.String()), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	for _, name := range []string{cc.WrongVolume, cc.WrongKey, cc.WrongRole, cc.WrongMode} {
		if _, err := s.selectOriginalHello(name, h); err == nil {
			t.Fatal("invented issued selection", name)
		}
	}
	changed, err := s.selectOriginalHello(cc.WrongEpoch, h)
	if err != nil || !cc.WrongHelloMatches(cc.WrongEpoch, cc.OriginalFor(h), changed) {
		t.Fatal("invalid epoch", err)
	}
	evidence := OriginalConsumerEvidence{Arm: arm, Hello: &changed}
	raw, _ := json.Marshal(evidence)
	var decoded OriginalConsumerEvidence
	if originalDecode(raw, &decoded) != nil || decoded.Hello == nil || *decoded.Hello != changed {
		t.Fatal("closed new evidence shape")
	}
}

func TestOriginalWrongHelloSealedRealIssuedSelection(t *testing.T) {
	issuer := originalIssuer(t)
	arm := originalTestArm()
	s := &Session{scope: arm.Scope, root: issuer.Root(), entries: map[string]*sessionAttachment{}}
	makeEntry := func(slot Slot) *sessionAttachment {
		binding, err := sessionBinding(s.scope, slot)
		if err != nil {
			t.Fatal(err)
		}
		key, err := p.NewAttachmentKey(p.Role(slot.Role))
		if err != nil {
			t.Fatal(err)
		}
		csr, err := key.CSR(binding)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := issuer.IssueAttachment(csr, binding, time.Now().Add(-time.Second), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := cert.WithKey(key)
		if err != nil {
			t.Fatal(err)
		}
		entry := &sessionAttachment{slot: slot, binding: binding, key: key, identity: identity, installed: true, mounted: slot.Role == "runtime", attachment: &sessionAttachmentFake{done: make(chan struct{})}}
		s.entries[slot.Attachment] = entry
		return entry
	}
	original := makeEntry(Slot{Attachment: arm.TargetAttachment, Volume: arm.TargetAttachment, Role: "runtime", Mode: "read-only"})
	other := makeEntry(Slot{Attachment: "33333333-3333-4333-8333-333333333333", Volume: "44444444-4444-4444-8444-444444444444", Role: "runtime", Mode: "read-write"})
	prepare := makeEntry(Slot{Attachment: "11111111-1111-4111-8111-111111111111", Volume: arm.TargetAttachment, Role: "prepare", Mode: "read-write"})
	key, _ := original.key.Fingerprint()
	h := a.DataHello{Epoch: a.ID(s.scope.ServiceEpoch), Binding: a.Binding{Store: a.ID(s.scope.Store), Volume: a.ID(original.slot.Volume), Attachment: a.ID(original.slot.Attachment), Container: a.ContainerID(s.scope.Container), Launch: a.ID(s.scope.Launch), Key: a.Fingerprint(key.String()), Role: a.RuntimeRole, Mode: a.ReadOnly}}
	for _, name := range []string{cc.WrongVolume, cc.WrongKey, cc.WrongRole, cc.WrongMode, cc.WrongEpoch} {
		changed, err := s.selectOriginalHello(name, h)
		if err != nil || !cc.WrongHelloMatches(name, cc.OriginalFor(h), changed) {
			t.Fatal(name, err)
		}
		if name == cc.WrongVolume && changed.Binding.Volume != a.ID(other.slot.Volume) {
			t.Fatal("not actual second volume")
		}
		if name == cc.WrongKey {
			pin, _ := prepare.key.Fingerprint()
			if changed.Binding.Key != a.Fingerprint(pin.String()) {
				t.Fatal("not real drained prepare key")
			}
		}
		if name == cc.WrongRole && changed.Binding.Prepare != a.ID(s.scope.Prepare) {
			t.Fatal("not original P")
		}
	}
	for _, name := range []string{"missing", "unmounted", "uninstalled", "joined", "wrong-key", "wrong-leaf", "non-primary", "third-live", "same-volume"} {
		t.Run(name, func(t *testing.T) {
			saved := *other
			defer func() { *other = saved; s.entries[other.slot.Attachment] = other }()
			candidate := h
			switch name {
			case "missing":
				delete(s.entries, other.slot.Attachment)
			case "unmounted":
				other.mounted = false
			case "uninstalled":
				other.installed = false
			case "joined":
				done := make(chan struct{})
				close(done)
				other.attachment = &sessionAttachmentFake{done: done}
			case "wrong-key":
				other.key = original.key
			case "wrong-leaf":
				other.identity = original.identity
			case "non-primary":
				candidate.Binding.Attachment = a.ID(other.slot.Attachment)
				candidate.Binding.Volume = a.ID(other.slot.Volume)
				k, _ := other.key.Fingerprint()
				candidate.Binding.Key = a.Fingerprint(k.String())
				candidate.Binding.Mode = a.ReadWrite
			case "third-live":
				extra := makeEntry(Slot{Attachment: "55555555-5555-4555-8555-555555555555", Volume: "66666666-6666-4666-8666-666666666666", Role: "runtime", Mode: "read-write"})
				defer delete(s.entries, extra.slot.Attachment)
			case "same-volume":
				other = makeEntry(Slot{Attachment: saved.slot.Attachment, Volume: original.slot.Volume, Role: "runtime", Mode: "read-write"})
			}
			if _, err := s.selectOriginalHello(cc.WrongVolume, candidate); err == nil {
				t.Fatal("ambiguous/dead issued selection accepted")
			}
		})
	}
	prepare.installed = false
	delete(s.entries, other.slot.Attachment)
	for _, name := range []string{cc.WrongVolume, cc.WrongKey, cc.WrongRole} {
		if _, err := s.selectOriginalHello(name, h); err == nil {
			t.Fatal("uninstalled selection accepted", name)
		}
	}
}
