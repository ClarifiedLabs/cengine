package storageservice

import (
	"context"
	"net"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

// Dedicated one-exchange closed wire. Canonical encoding rejects duplicate or
// unknown fields, trailing values, noncanonical numbers, and unbounded payloads.
// No signer, endpoint, CA override, filesystem operation, or raw key is accepted.
type attachmentCSRRequest struct {
	Version    int         `json:"version"`
	Controller c.Hello     `json:"controller"`
	Attachment a.DataHello `json:"attachment"`
	CSR        []byte      `json:"csr"`
}
type attachmentCSRReply struct {
	Version     int    `json:"version"`
	Certificate []byte `json:"certificate"`
}

// requestLegacyAttachmentCertificate sends the retired wire only to verify its
// rejection by the real lifecycle credential endpoint. It is not a fixture
// server, a supported workload client, or a protocol fallback.
func requestLegacyAttachmentCertificate(ctx context.Context, raw net.Conn, identity p.Identity, ready Ready, h a.DataHello, csr []byte) (p.Certificate, error) {
	if raw == nil {
		return p.Certificate{}, ErrConfiguration
	}
	defer raw.Close()
	if ctx == nil || h.Binding.Store != ready.Store.ID || h.Epoch != ready.ServiceEpoch {
		return p.Certificate{}, ErrConfiguration
	}
	binding, err := d.AttachmentBinding(h)
	if err != nil {
		return p.Certificate{}, err
	}
	if err = csrPin(csr, h.Binding.Key); err != nil {
		return p.Certificate{}, err
	}
	controller, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	if err != nil || identity.Certificate().Binding() != controller {
		return p.Certificate{}, ErrConfiguration
	}
	key, err := certificatePin(identity.Certificate())
	if err != nil || a.Fingerprint(key.String()) != ready.Controller.Key {
		return p.Certificate{}, ErrConfiguration
	}
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	if err != nil {
		return p.Certificate{}, err
	}
	root, err := p.ParseRootDER(ready.TLSRootDER)
	if err != nil {
		return p.Certificate{}, err
	}
	conn, err := p.NewControllerTLSClient(raw, identity, root, server, ready.ServerKey)
	if err != nil {
		return p.Certificate{}, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if err = raw.SetDeadline(time.Now().Add(credentialTimeout)); err != nil {
		return p.Certificate{}, err
	}
	if err = conn.HandshakeContext(ctx); err != nil {
		return p.Certificate{}, err
	}
	hello := c.Hello{Version: 2, Role: c.Controller, ControllerEpoch: ready.Controller.Epoch, Store: ready.Store.ID, ServiceEpoch: ready.ServiceEpoch}
	if err = writeCredential(conn, attachmentCSRRequest{Version: 1, Controller: hello, Attachment: h, CSR: csr}); err != nil {
		return p.Certificate{}, err
	}
	var reply attachmentCSRReply
	if err = readCredential(conn, &reply); err != nil {
		return p.Certificate{}, err
	}
	if reply.Version != 1 {
		return p.Certificate{}, ErrConfiguration
	}
	cert, err := p.ParseCertificateDER(reply.Certificate, binding)
	if err != nil {
		return p.Certificate{}, err
	}
	actual, err := certificatePin(cert)
	if err != nil || a.Fingerprint(actual.String()) != h.Binding.Key {
		return p.Certificate{}, a.ErrUnauthorized
	}
	return cert, nil
}
