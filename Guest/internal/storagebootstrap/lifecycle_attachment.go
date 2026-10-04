package storagebootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	service "dev.cengine/guest/internal/storageservice"
)

// LifecycleAttachmentCertificateRequest is the closed, sorted-canonical private
// body. No TLS root, controller credential/key, endpoint or authority is supplied.
type LifecycleAttachmentCertificateRequest struct {
	Attachment      a.DataHello         `json:"attachment"`
	ControllerEpoch uint64              `json:"controller_epoch"`
	CSR             []byte              `json:"csr"`
	Identity        a.LifecycleIdentity `json:"identity"`
}

// Own one connected stream, serialized with all lifecycle/workload IO. The child
// uses only its frozen boot credentials after ROOT validated that exact boot.
func (s *lifecycleSession) attachmentCertificate(ctx context.Context, raw net.Conn, request LifecycleAttachmentCertificateRequest) (AttachmentCertificateReply, error) {
	if raw == nil {
		return AttachmentCertificateReply{}, ErrProtocol
	}
	defer raw.Close()
	if request.Identity.Validate() != nil || validateAttachmentCertificate(request.Attachment, request.ControllerEpoch, request.CSR) != nil {
		return AttachmentCertificateReply{}, ErrProtocol
	}
	if err := s.acquireOperation(ctx); err != nil {
		return AttachmentCertificateReply{}, err
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	cfg, client, grant := s.privateBootConfig, s.client, s.owner.Grant
	if s.revoked || s.pendingRebind != nil || client == nil || !s.rootBootSeen || s.retirement.Grant != (a.LifecycleGrant{}) ||
		request.Identity != grant.Identity || request.Identity != cfg.Hello.Identity ||
		request.ControllerEpoch != cfg.Hello.ControllerEpoch || request.ControllerEpoch != grant.ExpectedEpoch+1 ||
		request.Attachment.Epoch != cfg.Hello.ServiceEpoch || request.Attachment.Binding.Store != grant.Identity.Store {
		s.mu.Unlock()
		return AttachmentCertificateReply{Error: "rejected"}, nil
	}
	s.attachmentRaw = raw // close interrupts this one-shot handshake/exchange too.
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.attachmentRaw = nil; s.mu.Unlock() }()

	// A parent assertion or an old ROOT result cannot establish current ownership.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return AttachmentCertificateReply{}, err
	}
	live, err := client.ServiceResult(ctx, grant, nonce)
	if err != nil {
		return lifecycleAttachmentFailure(err)
	}
	ready := service.Ready{Store: a.Store{ID: grant.Identity.Store}, ServiceEpoch: cfg.Hello.ServiceEpoch,
		Controller: a.Controller{Epoch: cfg.Hello.ControllerEpoch, Key: grant.NewKey}, TLSRootDER: cfg.ServerRoot.DER(), ServerKey: cfg.ServerKey}
	cert, err := service.RequestLifecycleAttachmentCertificate(ctx, raw, cfg.Identity, ready, grant.Identity, request.Attachment, request.CSR)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.currentServiceMatches(client, cfg, grant, live) {
		return AttachmentCertificateReply{}, errLifecycleSession
	}
	if ctx.Err() != nil {
		return lifecycleAttachmentFailure(ctx.Err())
	}
	if err != nil {
		return lifecycleAttachmentFailure(err)
	}
	der := cert.DER()
	if len(der) == 0 || len(der) > p.MaxDERSize {
		return AttachmentCertificateReply{}, ErrProtocol
	}
	return AttachmentCertificateReply{Certificate: der}, nil
}

func lifecycleAttachmentFailure(err error) (AttachmentCertificateReply, error) {
	// A denial closes the service wire; EOF is unavailable, NOT authenticated
	// rejection. Truncated/malformed TLS or a frozen trust violation fences child.
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return AttachmentCertificateReply{}, err
	}
	var network net.Error
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) {
		return AttachmentCertificateReply{Error: "unavailable"}, nil
	}
	if errors.Is(err, a.ErrUnauthorized) {
		return AttachmentCertificateReply{Error: "rejected"}, nil
	}
	return AttachmentCertificateReply{}, err
}
