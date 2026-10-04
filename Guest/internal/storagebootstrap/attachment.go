package storagebootstrap

import (
	"crypto/ed25519"
	"crypto/x509"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

type AttachmentCertificateReply struct {
	Certificate []byte `json:"certificate,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Validate only public CSR material and its exact registry binding. Trust anchors
// and endpoints are owned by the lifecycle session, never supplied here.
func validateAttachmentCertificate(attachment a.DataHello, controllerEpoch uint64, csrDER []byte) error {
	if controllerEpoch == 0 || len(csrDER) == 0 || len(csrDER) > p.MaxDERSize {
		return ErrProtocol
	}
	if _, err := d.AttachmentBinding(attachment); err != nil {
		return ErrProtocol
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return ErrProtocol
	}
	public, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ErrProtocol
	}
	pin, err := p.PublicKeyFingerprint(public)
	if err != nil || a.Fingerprint(pin.String()) != attachment.Binding.Key {
		return ErrProtocol
	}
	return nil
}
