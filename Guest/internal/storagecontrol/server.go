package storagecontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

type Server struct {
	authority *a.Authority
	config    workloadServerConfig
	slots     chan struct{}
	memory    budget
	queries   chan struct{}
	policy    workloadPolicy
	pki       *workloadPKIServerConfig // private immutable policy, never a caller TLS config
	// Private blocking-IO seam; production construction always binds the real core.
	createVolume func(*a.ControllerPrincipal, a.CreateVolumeRequest) (a.VolumeReceipt, error)
}

// Serve owns raw (never an already wrapped TLS connection). The caller supplies
// its own listener/forwarder. Each accepted worker retains its slot until the
// synchronous authority method returns, even if timeout/cancellation closes raw.
// No socket event releases guards or fabricates retirement evidence.
func (s *Server) Serve(ctx context.Context, raw net.Conn) error {
	if raw == nil {
		return ErrConfiguration
	}
	defer raw.Close()
	if ctx == nil {
		return ErrConfiguration
	}
	if _, ok := raw.(*tls.Conn); ok {
		return ErrConfiguration
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return ErrLimit
	}
	defer func() { <-s.slots }()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	c := tls.Server(raw, s.config.TLS)
	l := s.config.Limits
	if err := c.SetDeadline(time.Now().Add(l.HandshakeTimeout)); err != nil {
		return err
	}
	hctx, cancel := context.WithTimeout(ctx, l.HandshakeTimeout)
	defer cancel()
	if err := c.HandshakeContext(hctx); err != nil {
		return err
	}
	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 || !validLeaf(state.PeerCertificates[0], x509.ExtKeyUsageClientAuth) {
		return a.ErrUnauthorized
	}
	var h Hello
	if err := readFrame(c, &h, 4096, &s.memory); err != nil {
		return err
	}
	if !s.policy.validHello(h) || h.Store != s.config.Store || h.ServiceEpoch != s.authority.Epoch() {
		return ErrProtocol
	}
	if s.pki != nil {
		if err := s.pki.verifyPeer(state, h); err != nil {
			return err
		}
	}
	var controller *a.ControllerPrincipal
	var err error
	controller, err = s.authority.AuthenticateController(hctx, c, h.ControllerEpoch)
	if err == nil {
		err = s.checkStore(controller, h.Store)
	}
	reply := HelloReply{Version: s.policy.version(), Store: s.config.Store, ServiceEpoch: s.authority.Epoch(), LifecycleIdentity: s.policy.identityCopy()}
	if err != nil {
		reply.Error = errorCode(err)
	}
	if e := writeFrame(c, reply, 4096, &s.memory); e != nil {
		return e
	}
	if err != nil {
		return err
	}
	for id := uint64(1); id != 0; id++ {
		// Authenticated idle time is not a partial request. Keep its bounded
		// worker slot but allocate no frame storage. Cancellation closes raw.
		if err = c.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		var first [1]byte
		if _, err = io.ReadFull(c, first[:]); err != nil {
			return err
		}
		// One absolute deadline covers the remaining header and entire body,
		// starting at the first decrypted control-frame byte, not each chunk.
		if err = c.SetReadDeadline(time.Now().Add(l.ReadTimeout)); err != nil {
			return err
		}
		var req Request
		if err = readFrame(io.MultiReader(bytes.NewReader(first[:]), c), &req, l.RequestBytes, &s.memory); err != nil {
			return err
		}
		if !req.valid() || req.ID != id {
			return ErrProtocol
		}
		err = func() error {
			if req.Query != nil {
				select {
				case s.queries <- struct{}{}:
					defer func() { <-s.queries }()
				default:
					if e := c.SetWriteDeadline(time.Now().Add(l.WriteTimeout)); e != nil {
						return e
					}
					return writeFrame(c, Response{ID: id, Error: Limit}, 1024, &s.memory)
				}
			}
			opctx, done := context.WithTimeout(ctx, l.OperationTimeout)
			closeTimer := time.AfterFunc(l.OperationTimeout, func() { raw.Close() })
			response := Response{ID: id}
			// No goroutine is abandoned around a blocking authority method.
			if err = opctx.Err(); err == nil {
				err = s.dispatch(opctx, controller, req, &response)
			}
			expired := opctx.Err()
			done()
			closeTimer.Stop()
			if expired != nil {
				return expired
			}
			if err != nil {
				response = Response{ID: id, Error: errorCode(err)}
			}
			if req.Retire != nil && response.Receipt != nil && response.Error == "" && s.authority.PrepareCompatibilityRetireReply(*req.Retire, *response.Receipt) {
				return io.ErrUnexpectedEOF
			}
			if err = c.SetWriteDeadline(time.Now().Add(l.WriteTimeout)); err != nil {
				return err
			}
			err = writeFrame(c, response, l.ResponseBytes, &s.memory)
			if errors.Is(err, ErrLimit) {
				err = writeFrame(c, Response{ID: id, Error: Limit}, 1024, &s.memory)
			}
			if err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}

	}
	return ErrProtocol
}
func (s *Server) dispatch(ctx context.Context, p *a.ControllerPrincipal, q Request, r *Response) (err error) {
	if p == nil || q.Takeover != nil {
		return a.ErrUnauthorized
	}
	switch {
	case q.Query != nil:
		var v a.Snapshot
		v, err = s.authority.Query(p)
		if err == nil {
			if !s.policy.validSnapshot(&v) {
				return a.ErrUnauthorized
			}
			r.Snapshot = &v
			r.LifecycleIdentity = s.policy.identityCopy()
		}
	case q.ReservePrepare != nil:
		err = s.authority.ReservePrepare(p, *q.ReservePrepare)
		r.OK = &Empty{}
	case q.RegisterAttachment != nil:
		err = s.authority.RegisterAttachment(p, *q.RegisterAttachment)
		r.OK = &Empty{}
	case q.Retire != nil:
		var v a.Receipt
		v, err = s.authority.Retire(ctx, p, *q.Retire)
		if err == nil {
			r.Receipt = &v
		}
	case q.CompletePrepare != nil:
		err = s.authority.CompletePrepare(p, *q.CompletePrepare)
		r.OK = &Empty{}
	case q.ReplacePrepare != nil:
		err = s.authority.ReplacePrepare(p, *q.ReplacePrepare)
		r.OK = &Empty{}
	case q.CreateVolume != nil:
		var v a.VolumeReceipt
		v, err = s.createVolume(p, *q.CreateVolume)
		if err == nil {
			r.VolumeReceipt = &v
		}
	case q.DeleteVolume != nil:
		var v a.VolumeReceipt
		v, err = s.authority.DeleteVolume(p, *q.DeleteVolume)
		if err == nil {
			r.VolumeReceipt = &v
		}
	default:
		err = ErrProtocol
	}
	return
}
func validID(id a.ID) bool {
	s := string(id)
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s[14] != '4' || !stringsContains("89ab", s[19]) {
		return false
	}
	for i, c := range []byte(s) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func stringsContains(s string, b byte) bool {
	for i := range s {
		if s[i] == b {
			return true
		}
	}
	return false
}

// Query has no scalar authenticated Store accessor. Serialize and retain the
// query lease through reply encoding/writing so only one full snapshot is live.
func (s *Server) checkStore(p *a.ControllerPrincipal, want a.ID) error {
	select {
	case s.queries <- struct{}{}:
		defer func() { <-s.queries }()
	default:
		return ErrLimit
	}
	snapshot, err := s.authority.Query(p)
	if err == nil && (snapshot.Store.ID != want || !s.policy.validSnapshot(&snapshot)) {
		return a.ErrUnauthorized
	}
	return err
}
