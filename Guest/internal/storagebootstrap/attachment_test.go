package storagebootstrap

import (
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	"encoding/json"
	"strings"
	"testing"
)

func TestAttachmentClosedRequestBounds(t *testing.T) {
	key, e := p.NewAttachmentKey(p.RuntimeRole)
	check(t, e)
	pin, e := key.Fingerprint()
	check(t, e)
	h := a.DataHello{Epoch: a.ID(attachmentID(t)), Binding: a.Binding{Store: a.ID(attachmentID(t)), Volume: a.ID(attachmentID(t)), Attachment: a.ID(attachmentID(t)), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: a.ID(attachmentID(t)), Key: a.Fingerprint(pin.String()), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	b, e := d.AttachmentBinding(h)
	check(t, e)
	csr, e := key.CSR(b)
	check(t, e)
	r := LifecycleAttachmentCertificateRequest{Attachment: h, ControllerEpoch: ^uint64(0), CSR: csr}
	check(t, validateAttachmentCertificate(r.Attachment, r.ControllerEpoch, r.CSR))
	data, e := canonicalBytes(r)
	check(t, e)
	var decoded LifecycleAttachmentCertificateRequest
	check(t, canonical(data, &decoded))
	if decoded.ControllerEpoch != ^uint64(0) {
		t.Fatal("epoch rounded")
	}
	var tree map[string]any
	check(t, json.Unmarshal(data, &tree))
	tree["root_der"] = "override"
	bad, e := canonicalBytes(tree)
	check(t, e)
	if canonical(bad, &decoded) == nil {
		t.Fatal("trust override accepted")
	}
	for _, change := range []func(*LifecycleAttachmentCertificateRequest){func(r *LifecycleAttachmentCertificateRequest) { r.CSR = make([]byte, p.MaxDERSize+1) }, func(r *LifecycleAttachmentCertificateRequest) { r.ControllerEpoch = 0 }, func(r *LifecycleAttachmentCertificateRequest) { r.Attachment.Binding.Prepare = a.ID(attachmentID(t)) }, func(r *LifecycleAttachmentCertificateRequest) {
		r.Attachment.Binding.Key = a.Fingerprint(strings.Repeat("b", 64))
	}} {
		bad := r
		change(&bad)
		if validateAttachmentCertificate(bad.Attachment, bad.ControllerEpoch, bad.CSR) == nil {
			t.Fatal("invalid scope accepted")
		}
	}
}
