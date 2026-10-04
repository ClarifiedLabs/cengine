package storageservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

const credentialFrameLimit = 64 << 10
const credentialTimeout = 10 * time.Second

// Lifecycle credentials are a separate, strict wire: no v1 negotiation/fallback.
const lifecycleCredentialVersion = 3

type lifecycleAttachmentCSRRequest struct {
	Version    int         `json:"version"`
	Controller c.Hello     `json:"controller"`
	Attachment a.DataHello `json:"attachment"`
	CSR        []byte      `json:"csr"`
}
type lifecycleAttachmentCSRReply struct {
	Version     int    `json:"version"`
	Certificate []byte `json:"certificate"`
}

func lifecycleCredentialHello(identity a.LifecycleIdentity, epoch a.ID, controller uint64) c.Hello {
	return c.Hello{Version: c.LifecycleWorkloadVersion, Role: c.Controller, ControllerEpoch: controller,
		Store: identity.Store, ServiceEpoch: epoch, LifecycleIdentity: &identity}
}

// Validate live authority and the complete registered tuple, not just an old TLS
// principal. Called both before and after issuance; pending policy blocks issuance
// even before takeover/retirement has reached the authority journal.
func (s *LifecycleService) validateAttachmentCSR(ctx context.Context, conn *tls.Conn, request lifecycleAttachmentCSRRequest) (a.LifecycleMetadata, error) {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	meta, err := s.current()
	if err != nil {
		return meta, err
	}
	if ctx.Err() != nil {
		return meta, ctx.Err()
	}
	h := request.Controller
	if o.closed || meta.Sealed || s.pending != (a.LifecycleGrant{}) || s.retirement != (a.LifecycleGrant{}) ||
		request.Version != lifecycleCredentialVersion || h.Version != c.LifecycleWorkloadVersion || h.Role != c.Controller ||
		h.LifecycleIdentity == nil || *h.LifecycleIdentity != meta.Identity || h.Store != meta.Identity.Store ||
		h.ServiceEpoch != meta.Epoch || h.ControllerEpoch != meta.Controller.Epoch ||
		request.Attachment.Epoch != meta.Epoch || request.Attachment.Binding.Store != meta.Identity.Store {
		return meta, a.ErrUnauthorized
	}
	controller, err := p.NewControllerBinding(p.StoreID(meta.Store.ID), p.ControllerEpoch(meta.Controller.Epoch))
	if err != nil {
		return meta, err
	}
	key, err := pin(meta.Controller.Key)
	if err != nil || p.VerifyController(conn.ConnectionState(), o.issuer.Root(), controller, key) != nil {
		return meta, a.ErrUnauthorized
	}
	principal, err := o.authority.AuthenticateController(ctx, conn, meta.Controller.Epoch)
	if err != nil {
		return meta, err
	}
	snapshot, err := o.authority.Query(principal)
	if err != nil {
		return meta, err
	}
	record, ok := snapshot.Attachments[request.Attachment.Binding.Attachment]
	if snapshot.Schema != a.LifecycleSchemaVersion || snapshot.Store != meta.Store || snapshot.Epoch != meta.Epoch || snapshot.Controller != meta.Controller ||
		!ok || record.Binding != request.Attachment.Binding || (record.Phase != a.Active && record.Phase != a.Reserved) {
		return meta, a.ErrUnauthorized
	}
	if err = csrPin(request.CSR, record.Binding.Key); err != nil {
		return meta, err
	}
	latest, err := s.current()
	if err != nil {
		return meta, err
	}
	if latest.Identity != meta.Identity || latest.Epoch != meta.Epoch || latest.Controller != meta.Controller || latest.CurrentGrant != meta.CurrentGrant || latest.Sealed {
		return meta, a.ErrUnauthorized
	}
	return latest, nil
}

func (s *LifecycleService) serveLifecycleAttachmentCSR(ctx context.Context, raw net.Conn) error {
	o := s.owner
	done, err := o.begin(raw, true)
	if err != nil {
		return err
	}
	defer done()
	defer raw.Close()
	if ctx == nil {
		return ErrConfiguration
	}
	if _, wrapped := raw.(*tls.Conn); wrapped {
		return ErrConfiguration
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if err = raw.SetDeadline(time.Now().Add(credentialTimeout)); err != nil {
		return err
	}
	conn := tls.Server(raw, o.credentialTLS)
	if err = conn.HandshakeContext(ctx); err != nil {
		return err
	}
	var request lifecycleAttachmentCSRRequest
	if err = readCredential(conn, &request); err != nil {
		return err
	}
	before, err := s.validateAttachmentCSR(ctx, conn, request)
	if err != nil {
		return err
	}
	binding, err := d.AttachmentBinding(request.Attachment)
	if err != nil {
		return err
	}
	cert, err := o.issuer.IssueAttachment(request.CSR, binding, o.config.Now, o.config.Lifetime)
	if err != nil {
		return err
	}
	if err = o.rememberPrepareCertificate(request.Attachment, cert.DER()); err != nil {
		return err
	}
	after, err := s.validateAttachmentCSR(ctx, conn, request)
	if err != nil {
		return err
	}
	if after.Identity != before.Identity || after.Epoch != before.Epoch || after.Controller != before.Controller || after.CurrentGrant != before.CurrentGrant {
		return a.ErrUnauthorized
	}
	return writeCredential(conn, lifecycleAttachmentCSRReply{Version: lifecycleCredentialVersion, Certificate: cert.DER()})
}

// RequestLifecycleAttachmentCertificate consumes raw on every path. Full lifecycle
// identity and Ready must be independently reconciled private boot values. TLS,
// current controller key/URI, exact attachment URI/SPKI and v3 reply are mandatory.
func RequestLifecycleAttachmentCertificate(ctx context.Context, raw net.Conn, identity p.Identity, ready Ready, scope a.LifecycleIdentity, h a.DataHello, csr []byte) (p.Certificate, error) {
	if raw == nil {
		return p.Certificate{}, ErrConfiguration
	}
	defer raw.Close()
	if ctx == nil || scope.Validate() != nil || scope.Store != ready.Store.ID || h.Binding.Store != scope.Store || h.Epoch != ready.ServiceEpoch {
		return p.Certificate{}, ErrConfiguration
	}
	if _, wrapped := raw.(*tls.Conn); wrapped {
		return p.Certificate{}, ErrConfiguration
	}
	binding, err := d.AttachmentBinding(h)
	if err != nil {
		return p.Certificate{}, err
	}
	if err = csrPin(csr, h.Binding.Key); err != nil {
		return p.Certificate{}, err
	}
	controller, err := p.NewControllerBinding(p.StoreID(scope.Store), p.ControllerEpoch(ready.Controller.Epoch))
	if err != nil || identity.Certificate().Binding() != controller {
		return p.Certificate{}, ErrConfiguration
	}
	key, err := certificatePin(identity.Certificate())
	if err != nil || a.Fingerprint(key.String()) != ready.Controller.Key {
		return p.Certificate{}, ErrConfiguration
	}
	server, err := p.NewServerBinding(p.StoreID(scope.Store), p.ServiceEpoch(ready.ServiceEpoch))
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
	hello := lifecycleCredentialHello(scope, ready.ServiceEpoch, ready.Controller.Epoch)
	if err = writeCredential(conn, lifecycleAttachmentCSRRequest{Version: lifecycleCredentialVersion, Controller: hello, Attachment: h, CSR: csr}); err != nil {
		return p.Certificate{}, err
	}
	var reply lifecycleAttachmentCSRReply
	if err = readCredential(conn, &reply); err != nil {
		return p.Certificate{}, err
	}
	if reply.Version != lifecycleCredentialVersion {
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
	if err = ctx.Err(); err != nil {
		return p.Certificate{}, err
	}
	return cert, nil
}

func readCredential(r io.Reader, out any) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > credentialFrameLimit {
		return ErrConfiguration
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return ErrConfiguration
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(body, canonical) {
		return ErrConfiguration
	}
	return nil
}
func writeCredential(w io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) == 0 || len(body) > credentialFrameLimit {
		return ErrConfiguration
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(body)))
	_, err = io.Copy(w, bytes.NewReader(append(head[:], body...)))
	return err
}
