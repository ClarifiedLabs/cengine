package storagepki_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	p "dev.cengine/guest/internal/storagepki"
)

// Exercise the exported private-init/host-bridge surface across a real byte
// boundary, without accessing any private implementation fields or exporting
// the attachment private key to the bridge.
func TestPublicOnlyBridgeRoundTrip(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := p.NewBootstrapPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	issuer, err := p.NewIssuer(now, p.MaxValidity, boot)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	binding, err := p.NewAttachmentBinding(p.StoreID(id), p.ServiceEpoch(id), p.AttachmentTuple{Attachment: p.AttachmentID(id), Volume: p.VolumeID(id), Role: p.RuntimeRole, Mode: p.ReadWrite, Container: p.ContainerID(strings.Repeat("a", 64)), Launch: p.LaunchID(id)})
	if err != nil {
		t.Fatal(err)
	}
	guestKey, err := p.NewAttachmentKey(p.RuntimeRole)
	if err != nil {
		t.Fatal(err)
	}
	request, err := guestKey.CSR(binding)
	if err != nil {
		t.Fatal(err)
	}
	response, err := issuer.IssueAttachment(request, binding, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, parse := range []func() (p.Certificate, error){func() (p.Certificate, error) { return p.ParseCertificateDER(response.DER(), binding) }, func() (p.Certificate, error) { return p.ParseCertificatePEM(response.PEM(), binding) }} {
		cert, err := parse()
		if err != nil {
			t.Fatal(err)
		}
		identity, err := cert.WithKey(guestKey)
		if err != nil {
			t.Fatal(err)
		}
		if identity.Certificate().Binding() != binding {
			t.Fatal("lost binding")
		}
		other, err := p.NewAttachmentKey(p.RuntimeRole)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cert.WithKey(other); err == nil {
			t.Fatal("wrong guest key")
		}
	}
	if _, err := p.ParseCertificateDER(append(response.DER(), 0), binding); err == nil {
		t.Fatal("trailing DER")
	}
	if _, err := p.ParseCertificatePEM(append(response.PEM(), response.PEM()...), binding); err == nil {
		t.Fatal("duplicate cert")
	}
	if _, err := p.ParseCertificateDER(response.DER(), p.Binding{}); err == nil {
		t.Fatal("wrong expected scope")
	}
}
