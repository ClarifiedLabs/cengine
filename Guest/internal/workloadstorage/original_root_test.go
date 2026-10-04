package workloadstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	p "dev.cengine/guest/internal/storagepki"
)

// These fakes exercise failure/ownership boundaries, not a positive native READ.
// In particular End returns NO opaque client grant: actual host pread success
// must not become an armed observation without the independent wire witness.
type rootNoWireAttachment struct {
	sessionAttachmentFake
	began bool
}

func (m *rootNoWireAttachment) OriginalConsumerRootAttempt(context.Context, a.DataHello) (c.OriginalConsumerRootRequest, error) {
	return c.OriginalConsumerRootRequest{Node: 1, RequestSequence: 1}, nil
}
func (m *rootNoWireAttachment) BeginOriginalConsumerRead(a.DataHello) error {
	m.began = true
	return nil
}
func (m *rootNoWireAttachment) EndOriginalConsumerRead(a.DataHello) (*c.OriginalConsumerReadGrant, error) {
	return nil, nil
}
func (m *rootNoWireAttachment) ReplayOriginalConsumerRead(context.Context, a.DataHello, *c.OriginalConsumerReadGrant, *c.OriginalConsumerReadGrant) (c.OriginalConsumerRootReplay, error) {
	return c.OriginalConsumerRootReplay{}, ErrInvalidFrame
}

type rootSessionFactory struct {
	*originalFactoryFake
	roots         map[Attachment]string
	owners        []*retainedFDOwner
	aborted       atomic.Int32
	block         func()
	secondMissing bool
}

func (f *rootSessionFactory) newOriginalReadFD(attachment Attachment) *retainedFDOwner {
	if f.secondMissing && len(f.owners) == 1 {
		return nil
	}
	owner := newRetainedFDOwner(func() (*os.File, error) {
		if f.block != nil {
			f.block()
		}
		return os.Open(f.roots[attachment])
	}, func() { f.aborted.Add(1) }, attachment.Done())
	f.owners = append(f.owners, owner)
	return owner
}
func rootInstalledSession(t *testing.T) (*Session, OriginalConsumerArm, *rootSessionFactory, [2]*sessionAttachment) {
	t.Helper()
	arm := originalTestArm()
	arm.Version = 6
	arm.CaseName = "cross-mount-root-grant"
	issuer := originalIssuer(t)
	f := &rootSessionFactory{originalFactoryFake: &originalFactoryFake{observer: &originalConsumer{}}, roots: map[Attachment]string{}}
	s := &Session{binding: arm.Binding, scope: arm.Scope, root: issuer.Root(), phase: "running", activeRole: "runtime", factory: f, entries: map[string]*sessionAttachment{}}
	var entries [2]*sessionAttachment
	for i, slot := range []Slot{{Attachment: arm.TargetAttachment, Volume: arm.TargetAttachment, Role: "runtime", Mode: "read-only"}, {Attachment: "33333333-3333-4333-8333-333333333333", Volume: "44444444-4444-4444-8444-444444444444", Role: "runtime", Mode: "read-only"}} {
		binding, err := sessionBinding(s.scope, slot)
		if err != nil {
			t.Fatal(err)
		}
		key, err := p.NewAttachmentKey(p.RuntimeRole)
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
		m := &rootNoWireAttachment{sessionAttachmentFake: sessionAttachmentFake{done: make(chan struct{})}}
		entries[i] = &sessionAttachment{slot: slot, binding: binding, key: key, identity: identity, installed: true, mounted: true, attachment: m}
		s.entries[slot.Attachment] = entries[i]
		dir := t.TempDir()
		retainedTestFile(t, filepath.Join(dir, retainedReadName), bytes.Repeat([]byte{byte('A' + i)}, 32))
		f.roots[m] = dir
	}
	arm.LeafSHA256 = SpecificationDigest(entries[0].identity.Certificate().DER())
	t.Cleanup(func() { f.observer.stop() })
	return s, arm, f, entries
}
func rootSourceHello(s *Session, e *sessionAttachment) a.DataHello {
	key, _ := e.key.Fingerprint()
	return a.DataHello{Epoch: a.ID(s.scope.ServiceEpoch), Binding: a.Binding{Store: a.ID(s.scope.Store), Volume: a.ID(e.slot.Volume), Attachment: a.ID(e.slot.Attachment), Container: a.ContainerID(s.scope.Container), Launch: a.ID(s.scope.Launch), Key: a.Fingerprint(key.String()), Role: a.RuntimeRole, Mode: a.Mode(e.slot.Mode)}}
}
func TestOriginalRootSessionActualIssuedPairSelection(t *testing.T) {
	for _, name := range []string{"valid", "stopped", "missing", "unmounted", "uninstalled", "closed", "wrong-key", "wrong-leaf", "same-volume", "nonprimary", "third"} {
		t.Run(name, func(t *testing.T) {
			s, _, _, entries := rootInstalledSession(t)
			source, target := entries[0], entries[1]
			hello := rootSourceHello(s, source)
			switch name {
			case "stopped":
				s.stopped = true
			case "missing":
				delete(s.entries, target.slot.Attachment)
			case "unmounted":
				target.mounted = false
			case "uninstalled":
				target.installed = false
			case "closed":
				close(target.attachment.(*rootNoWireAttachment).done)
			case "wrong-key":
				target.key = source.key
			case "wrong-leaf":
				target.identity = source.identity
			case "same-volume":
				target.slot.Volume = source.slot.Volume
			case "nonprimary":
				hello = rootSourceHello(s, target)
			case "third":
				s.entries["55555555-5555-4555-8555-555555555555"] = target
			}
			selected, err := s.originalRootTarget(hello)
			if name == "valid" {
				if err != nil || selected != target {
					t.Fatal("not actual issued target", err)
				}
			} else if err == nil || selected != nil {
				t.Fatal("ambiguous/dead target admitted", name)
			}
		})
	}
}
func TestOriginalRootSessionCacheOrFixtureReadCannotReplaceWire(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile")
	}
	s, arm, f, entries := rootInstalledSession(t)
	raw, _ := json.Marshal(arm)
	if response, err := s.originalConsumerControl("original-consumer-arm", raw); err == nil || response != nil {
		t.Fatal("host pread/no actual READ grant became positive")
	}
	if !entries[0].attachment.(*rootNoWireAttachment).began || !f.observer.stopped || f.observer.roots != nil || len(f.owners) != 2 {
		t.Fatal("acquisition/cleanup not joined")
	}
	for _, owner := range f.owners {
		select {
		case <-owner.done:
		default:
			t.Fatal("lost owned worker")
		}
	}
	if f.aborted.Load() != 0 {
		t.Fatal("clean error used mount abort")
	}
}
func TestOriginalRootSessionReleaseDuringAcquisitionKeepsBoth(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile")
	}
	s, arm, f, _ := rootInstalledSession(t)
	entered, unblock := make(chan struct{}), make(chan struct{})
	f.block = func() { close(entered); <-unblock }
	raw, _ := json.Marshal(arm)
	done := make(chan error, 1)
	go func() { _, err := s.originalConsumerControl("original-consumer-arm", raw); done <- err }()
	<-entered
	if response, err := s.originalConsumerControl("original-consumer-release", raw); err == nil || response != nil || f.observer.roots == nil || f.aborted.Load() != 2 {
		t.Fatal("unjoined release accepted", err)
	}
	close(unblock)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled arm passed")
		}
	case <-time.After(time.Second):
		t.Fatal("arm unbounded")
	}
	for _, owner := range f.owners {
		select {
		case <-owner.done:
		case <-time.After(time.Second):
			t.Fatal("worker not joined")
		}
	}
	if f.observer.roots == nil {
		t.Fatal("failed join discarded pair")
	}
}
func TestOriginalRootSessionPartialConstructionClosesFirst(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile")
	}
	s, arm, f, _ := rootInstalledSession(t)
	f.secondMissing = true
	raw, _ := json.Marshal(arm)
	if _, err := s.originalConsumerControl("original-consumer-arm", raw); err == nil {
		t.Fatal("partial owner accepted")
	}
	if len(f.owners) != 1 || f.observer.roots != nil {
		t.Fatal("partial owner lost")
	}
	select {
	case <-f.owners[0].done:
	default:
		t.Fatal("first owner not joined")
	}
}
func TestOriginalRootSessionClosedVersionAndEvidenceShape(t *testing.T) {
	arm := originalTestArm()
	arm.Version = 6
	for _, name := range []string{"cross-mount-root-grant", "retired-root-grant-replay"} {
		arm.CaseName = name
		if !arm.valid() {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"same-e-existing-data", "same-e-retained-fd", "wrong-volume", "attachment-key-reuse"} {
		arm.CaseName = name
		if arm.valid() {
			t.Fatal("version6 alias", name)
		}
	}
	value := OriginalConsumerEvidence{Roots: &OriginalRootEvidence{Source: OriginalRootPositive{IdentitySHA256: strings.Repeat("a", 64)}}}
	raw, _ := json.Marshal(value)
	var out OriginalConsumerEvidence
	if originalDecode(raw, &out) != nil {
		t.Fatal("root shape roundtrip")
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"roots":{`), []byte(`"roots":null,"extra":{`), 1), bytes.Replace(raw, []byte(`"size":0`), []byte(`"size":0.0`), 1), bytes.Replace(raw, []byte(`"identitySHA256":`), []byte(`"unknown":`), 1)} {
		if originalDecode(bad, &out) == nil {
			t.Fatal("open root schema")
		}
	}
}
