package storagebootstrap

// Workload composition accepts no listener, key import, caller TLS policy,
// receipt input, signing command or successor admission. Boot inputs never come
// from connect-workload; the private boot connection freezes them.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"syscall"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
)

// Only an established workload exchange may produce this private recovery signal.
// It never authorizes replay or reconnects the lifecycle/ROOT transport.
type lifecycleWorkloadUnavailable struct{ cause error }

func (e *lifecycleWorkloadUnavailable) Error() string {
	return "storagebootstrap: workload unavailable"
}
func (e *lifecycleWorkloadUnavailable) Unwrap() error { return e.cause }

// A non-boundary transport failure preserves ROOT for service replacement, but
// permanently fences this service's workload lane. It grants no replay/reconnect.
type lifecycleWorkloadFailed struct{ cause error }

func (e *lifecycleWorkloadFailed) Error() string { return "storagebootstrap: workload failed" }
func (e *lifecycleWorkloadFailed) Unwrap() error { return e.cause }

func lifecycleWorkloadPermanentTransportLoss(err error) bool {
	return lifecycleWorkloadTransportError(err) && (errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET))
}

// Narrow the shared closed transport classifier to clean response-boundary EOF.
// CONTROL normalizes partial-frame EOF to ErrUnexpectedEOF, but preserves reset
// and closed-pipe errors even mid-frame. Those cannot safely prove a boundary;
// Non-boundary failures must never enter this retry-capable signal.
func lifecycleWorkloadTransportLoss(err error) bool {
	return lifecycleWorkloadTransportError(err) && ordinaryServiceLoss(err) && errors.Is(err, io.EOF) &&
		!lifecycleWorkloadPermanentTransportLoss(err)
}

func lifecycleWorkloadTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrProtocol) || errors.Is(err, c.ErrProtocol) || errors.Is(err, c.ErrLimit) {
		return false
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return false
	}
	return true
}

const lifecycleWorkloadRequestLimit = 256 << 10
const lifecycleWorkloadResponseLimit = 4 << 20

// The response envelope contains base64 data, not an unsigned lifecycle proof.
const lifecycleWorkloadReplyLimit = lifecycleWorkloadResponseLimit*4/3 + 1024

func lifecycleStreamOperation(operation string) bool {
	return operation == "stage-service-rebind" || operation == "connect-boot" || operation == "connect-workload" || operation == "attachment-certificate"
}

func lifecycleCanonical(raw []byte, value any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return ErrProtocol
	}
	encoded, err := canonicalBytes(value)
	if err != nil || !bytes.Equal(encoded, raw) {
		return ErrProtocol
	}
	return nil
}

func decodeLifecyclePrivateRequest(raw []byte, request *lifecyclePrivateRequest) error {
	if lifecycleCanonical(raw, request, lifecycleWorkloadRequestLimit) != nil {
		return ErrProtocol
	}
	if request.Operation != "workload-command" && len(raw) > MaximumPayload {
		return ErrProtocol
	}
	return nil
}

func writeLifecyclePrivateReply(w io.Writer, reply any, workload bool) error {
	if !workload {
		return WriteFrame(w, reply)
	}
	raw, err := canonicalBytes(reply)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > lifecycleWorkloadReplyLimit {
		return ErrProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	for _, part := range [][]byte{header[:], raw} {
		for len(part) != 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}

// Owns raw on every path. One latest connection, serialized with lifecycle and
// workload exchanges; replacement never rebinds boot credentials or identity.
// Transport loss during connect fences this service's workload lane while
// preserving ROOT for a committed successor. It never permits a connect retry.
func (s *lifecycleSession) connectWorkload(ctx context.Context, raw net.Conn) (err error) {
	defer func() {
		if err != nil && raw != nil {
			raw.Close()
		}
	}()
	if err = s.acquireOperation(ctx); err != nil {
		return err
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	if s.revoked || s.workloadFailed || s.pendingRebind != nil || s.retirement.Grant != (a.LifecycleGrant{}) || raw == nil || s.client == nil || !s.rootBootSeen {
		s.mu.Unlock()
		return errLifecycleSession
	}
	previous, previousRaw := s.workload, s.workloadRaw
	s.workload, s.workloadRaw = nil, raw // close can interrupt the handshake
	cfg, lifecycle, grant := s.privateBootConfig, s.client, s.owner.Grant
	trust, state := s.bootTrust, s.serviceState
	s.mu.Unlock()
	// Failure is recoverable only for this exact frozen, ROOT-authorized session.
	// A lost ServiceResult need not produce a live result, but cannot replace the
	// original trust with parent assertions or authorize reconnect to this service.
	connectFailure := func(cause error) error {
		s.mu.Lock()
		current := !s.revoked && !s.workloadFailed && s.pendingRebind == nil && s.rootBootSeen &&
			s.client == lifecycle && s.privateBootConfig == cfg && s.owner.Grant == grant &&
			s.bootTrust == trust && s.serviceState == state && s.workloadRaw == raw &&
			s.retirement.Grant == (a.LifecycleGrant{})
		s.workload, s.workloadRaw = nil, nil
		failed := current && ctx.Err() == nil && !errors.Is(cause, io.ErrUnexpectedEOF) &&
			(lifecycleWorkloadTransportLoss(cause) || lifecycleWorkloadPermanentTransportLoss(cause))
		if failed {
			s.workloadFailed = true
		}
		s.mu.Unlock()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !current {
			return errLifecycleSession
		}
		if failed {
			return &lifecycleWorkloadFailed{cause: cause}
		}
		return cause
	}
	if previousRaw != nil {
		previousRaw.Close()
	}
	if previous != nil {
		previous.Close()
	}
	// No cached proof/receipt or parent assertion establishes current ownership.
	// ServiceResult verifies the live open, never the immutable applied receipt.
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	live, err := lifecycle.ServiceResult(ctx, grant, nonce)
	if err != nil {
		return connectFailure(err)
	}
	s.mu.Lock()
	valid := ctx.Err() == nil && s.bootTrust == trust && s.serviceState == state && s.currentServiceMatches(lifecycle, cfg, grant, live)
	s.mu.Unlock()
	if !valid {
		return connectFailure(errLifecycleSession)
	}
	limits := c.DefaultLimits()
	limits.Connections, limits.RequestBytes, limits.ResponseBytes = 1, lifecycleWorkloadRequestLimit, lifecycleWorkloadResponseLimit
	client, err := c.NewPKILifecycleWorkloadClient(ctx, raw, c.PKILifecycleWorkloadClientConfig{
		Identity: cfg.Identity, ServerRoot: cfg.ServerRoot, ServerKey: cfg.ServerKey,
		LifecycleIdentity: cfg.Hello.Identity, ServiceEpoch: cfg.Hello.ServiceEpoch,
		CurrentController: a.Controller{Epoch: cfg.Hello.ControllerEpoch, Key: grant.NewKey}, Limits: limits,
	})
	if err != nil {
		return connectFailure(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !s.currentServiceMatches(lifecycle, cfg, grant, live) {
		client.Close()
		return errLifecycleSession
	}
	s.workload = client
	return nil
}

// Existing closed typed CONTROL request, with takeover deliberately removed.
// Query is the real v3 schema-4 query; ordinary mutation receipts remain schema 3.
func (s *lifecycleSession) workloadCommand(ctx context.Context, request c.Request) ([]byte, error) {
	count := 0
	for _, present := range []bool{request.Query != nil, request.ReservePrepare != nil, request.RegisterAttachment != nil,
		request.Retire != nil, request.CompletePrepare != nil, request.ReplacePrepare != nil,
		request.CreateVolume != nil, request.DeleteVolume != nil} {
		if present {
			count++
		}
	}
	if request.ID != 0 || request.Takeover != nil || count != 1 {
		return nil, ErrProtocol
	}
	encoded, err := canonicalBytes(request)
	if err != nil || len(encoded) > lifecycleWorkloadRequestLimit {
		return nil, ErrProtocol
	}
	if err = s.acquireOperation(ctx); err != nil {
		return nil, err
	}
	defer func() { <-s.op }()
	s.mu.Lock()
	client := s.workload
	if s.revoked || s.workloadFailed || s.pendingRebind != nil || client == nil {
		s.mu.Unlock()
		return nil, errLifecycleSession
	}
	s.mu.Unlock()
	response, err := client.Call(ctx, request)
	if err != nil {
		var remote *c.RemoteError
		if !errors.As(err, &remote) || response.ID == 0 || response.Error != remote.Code {
			s.mu.Lock()
			raw := s.workloadRaw
			s.workload, s.workloadRaw = nil, nil
			revoked := s.revoked
			failed := !revoked && ctx.Err() == nil && lifecycleWorkloadPermanentTransportLoss(err)
			if failed {
				s.workloadFailed = true
			}
			s.mu.Unlock()
			client.Close()
			if raw != nil {
				raw.Close()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if failed {
				return nil, &lifecycleWorkloadFailed{cause: err}
			}
			if !revoked && lifecycleWorkloadTransportLoss(err) {
				return nil, &lifecycleWorkloadUnavailable{cause: err}
			}
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || ctx.Err() != nil {
		return nil, errLifecycleSession
	}
	result, err := canonicalBytes(response)
	if err != nil || len(result) > lifecycleWorkloadResponseLimit {
		return nil, ErrProtocol
	}
	return result, nil
}
