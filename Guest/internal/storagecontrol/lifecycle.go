package storagecontrol

// This endpoint serves signed lifecycle operations on an existing Authority.
// It does not listen, dial, initialize/open a registry, or expose workload/volume
// control. Owners explicitly supply the Authority.
// In particular it cannot drain workloads: retirement must already be quiescent.
// Receipts are authenticated transport results, not independently signed proofs.
// TLS proves neither key nonexportability nor recipient/process death: the trusted
// ROOT/direct-child owner must enforce those constraints separately. Authenticated
// idle sessions intentionally persist until cancellation or explicit close.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

const LifecycleControlVersion = "storage-lifecycle-control.v2"
const lifecycleFrameBytes = 16 << 10

// LifecycleHello binds the entire registry incarnation, service and controller.
// Certificate URI role is always storagepki.ControllerRole, never a data role.
// Identity.Binding is the host StoreBinding digest, NOT the server SPKI; the
// independently supplied server pin authenticates this endpoint's live key.
type LifecycleHello struct {
	Version         string              `json:"version"`
	Identity        a.LifecycleIdentity `json:"identity"`
	ServiceEpoch    a.ID                `json:"service_epoch"`
	ControllerEpoch uint64              `json:"controller_epoch"`
}

type lifecycleResultRequest struct {
	Grant a.LifecycleGrant `json:"grant"`
	Nonce []byte           `json:"nonce"`
}
type lifecycleRequest struct {
	ID            uint64                  `json:"id"`
	Result        *lifecycleResultRequest `json:"result,omitempty"`
	ServiceResult *lifecycleResultRequest `json:"service_result,omitempty"`
	Takeover      *a.SignedLifecycleGrant `json:"takeover,omitempty"`
	Retire        *a.SignedLifecycleGrant `json:"retire,omitempty"`
}
type lifecycleResponse struct {
	ID            uint64                    `json:"id"`
	Error         Code                      `json:"error,omitempty"`
	Receipt       *a.LifecycleReceipt       `json:"receipt,omitempty"`
	ServiceResult *a.LifecycleServiceResult `json:"service_result,omitempty"`
	Controller    *a.Controller             `json:"controller,omitempty"`
	OK            *Empty                    `json:"ok,omitempty"`
}

func (q lifecycleRequest) valid() bool {
	n := 0
	if q.Result != nil {
		n++
	}
	if q.ServiceResult != nil {
		n++
	}
	if q.Takeover != nil {
		n++
	}
	if q.Retire != nil {
		n++
	}
	return q.ID != 0 && n == 1
}
func lifecycleEpoch(g a.LifecycleGrant) uint64 {
	if g.Operation == a.LifecycleInitialize {
		return 1
	}
	if g.Operation == a.LifecycleTakeover {
		return g.ExpectedEpoch + 1
	}
	return g.ExpectedEpoch
}
func lifecycleHelloValid(h LifecycleHello) bool {
	return h.Version == LifecycleControlVersion && h.Identity.Validate() == nil && validID(h.ServiceEpoch) && h.ControllerEpoch > 0
}
func lifecycleLimits(l Limits) (Limits, error) {
	if l == (Limits{}) {
		l = DefaultLimits()
		l.RequestBytes = lifecycleFrameBytes
		l.ResponseBytes = lifecycleFrameBytes
	}
	l, err := limits(l)
	if err != nil || l.RequestBytes > lifecycleFrameBytes || l.ResponseBytes > lifecycleFrameBytes || l.HandshakeTimeout > time.Minute || l.ReadTimeout > time.Minute || l.WriteTimeout > time.Minute || l.OperationTimeout > time.Minute {
		return l, ErrConfiguration
	}
	return l, nil
}

// LifecycleServerConfig freezes identity, epochs, pins and exact current/successor
// grants, not just projected IDs or keys. CurrentGrant is initialization or a
// reconciled takeover. SuccessorGrant authorizes only its exact next epoch/key.
// RetireGrant optionally seeds the one write-once retirement arm, for either
// configured controller. ArmRetirement may fill an empty arm on live sessions;
// it cannot change any frozen policy, replace the arm, or retain grant history.
// Signatures are never trusted here: actual Authority methods verify ROOT.
// All credentials are immutable storagepki values; no TLS callbacks/principals.
// With a successor configured, at least two connection slots are required and
// current-epoch sessions may occupy at most Connections-1. This reserves capacity
// from authenticated idle current owners, not from unauthenticated handshake DoS:
// the global pre-TLS cap and HandshakeTimeout still bound those contenders.
type LifecycleServerConfig struct {
	Identity       p.Identity
	ClientRoot     p.Root
	ServiceEpoch   a.ID
	CurrentGrant   a.LifecycleGrant
	ControllerKey  p.Fingerprint
	SuccessorGrant a.LifecycleGrant
	SuccessorKey   p.Fingerprint
	RetireGrant    a.LifecycleGrant
	Limits         Limits
}
type LifecycleServer struct {
	authority    *a.Authority
	config       LifecycleServerConfig
	tls          *tls.Config
	slots        chan struct{}
	currentSlots chan struct{}
	memory       budget
	retireMu     sync.Mutex
	retireGrant  a.LifecycleGrant
}

func NewLifecycleServer(authority *a.Authority, c LifecycleServerConfig) (*LifecycleServer, error) {
	if authority == nil || c.ServiceEpoch != authority.Epoch() || c.CurrentGrant.Validate() != nil || c.CurrentGrant.Operation == a.LifecycleRetire || c.ControllerKey == (p.Fingerprint{}) || c.CurrentGrant.NewKey != a.Fingerprint(c.ControllerKey.String()) {
		return nil, ErrConfiguration
	}
	server, err := p.NewServerBinding(p.StoreID(c.CurrentGrant.Identity.Store), p.ServiceEpoch(c.ServiceEpoch))
	if err != nil || c.Identity.Certificate().Binding() != server {
		return nil, ErrConfiguration
	}
	if c.SuccessorGrant != (a.LifecycleGrant{}) || c.SuccessorKey != (p.Fingerprint{}) {
		g := c.SuccessorGrant
		if g.Validate() != nil || g.Operation != a.LifecycleTakeover || g.Identity != c.CurrentGrant.Identity || g.ExpectedEpoch != lifecycleEpoch(c.CurrentGrant) || g.Serial <= c.CurrentGrant.Serial || g.ID == c.CurrentGrant.ID || c.SuccessorKey == (p.Fingerprint{}) || c.SuccessorKey == c.ControllerKey || g.NewKey != a.Fingerprint(c.SuccessorKey.String()) {
			return nil, ErrConfiguration
		}
	}
	if c.RetireGrant != (a.LifecycleGrant{}) && !validLifecycleRetirement(c, c.RetireGrant) {
		return nil, ErrConfiguration
	}
	c.Limits, err = lifecycleLimits(c.Limits)
	if err != nil {
		return nil, err
	}
	currentLimit := c.Limits.Connections
	if c.SuccessorGrant != (a.LifecycleGrant{}) {
		if currentLimit < 2 {
			return nil, ErrConfiguration
		}
		currentLimit--
	}
	cfg, err := p.ServerTLSConfig(c.Identity, c.ClientRoot)
	if err != nil {
		return nil, ErrConfiguration
	}
	return &LifecycleServer{authority: authority, config: c, tls: cfg, slots: make(chan struct{}, c.Limits.Connections), currentSlots: make(chan struct{}, currentLimit), retireGrant: c.RetireGrant}, nil
}

func validLifecycleRetirement(c LifecycleServerConfig, g a.LifecycleGrant) bool {
	previous := c.CurrentGrant
	if c.SuccessorGrant != (a.LifecycleGrant{}) && g.ExpectedEpoch == lifecycleEpoch(c.SuccessorGrant) {
		previous = c.SuccessorGrant
	}
	return g.Validate() == nil && g.Operation == a.LifecycleRetire && g.Identity == previous.Identity && g.ExpectedEpoch == lifecycleEpoch(previous) && g.NewKey == previous.NewKey && g.Serial > previous.Serial && g.ID != previous.ID
}

// ArmRetirement is the sole monotonic policy amendment: empty -> one exact
// terminal grant. The trusted service must verify ROOT before calling; this is
// not proof of retirement. RetireLifecycle independently authenticates the live
// controller, verifies ROOT again and enforces the actual resource barrier.
// Exact repeats are harmless; replacement/unarming is impossible. No lock is held
// across TLS or authority IO. LifecycleServer must not be copied.
func (s *LifecycleServer) ArmRetirement(g a.LifecycleGrant) error {
	if s == nil || s.authority == nil {
		return ErrConfiguration
	}
	s.retireMu.Lock()
	defer s.retireMu.Unlock()
	if s.retireGrant != (a.LifecycleGrant{}) {
		if s.retireGrant == g {
			return nil
		}
		return a.ErrConflict
	}
	if !validLifecycleRetirement(s.config, g) {
		return ErrConfiguration
	}
	s.retireGrant = g
	return nil
}

func (s *LifecycleServer) retirement() a.LifecycleGrant {
	s.retireMu.Lock()
	defer s.retireMu.Unlock()
	return s.retireGrant
}

func (s *LifecycleServer) verify(conn *tls.Conn, h LifecycleHello) error {
	c := s.config
	if !lifecycleHelloValid(h) || h.Identity != c.CurrentGrant.Identity || h.ServiceEpoch != c.ServiceEpoch || h.ServiceEpoch != s.authority.Epoch() {
		return a.ErrUnauthorized
	}
	pin := c.ControllerKey
	if h.ControllerEpoch != lifecycleEpoch(c.CurrentGrant) {
		if c.SuccessorGrant == (a.LifecycleGrant{}) || h.ControllerEpoch != lifecycleEpoch(c.SuccessorGrant) {
			return a.ErrUnauthorized
		}
		pin = c.SuccessorKey
	}
	binding, err := p.NewControllerBinding(p.StoreID(h.Identity.Store), p.ControllerEpoch(h.ControllerEpoch))
	if err != nil || p.VerifyController(conn.ConnectionState(), c.ClientRoot, binding, pin) != nil {
		return a.ErrUnauthorized
	}
	return nil
}

// authenticateHello follows exact PKI verification, never a caller principal.
// AuthenticateSuccessor alone verifies possession/availability, NOT whether the
// grant is still pending; the detached metadata check below restricts that path
// to the frozen current controller. All later operations authenticate again.
func (s *LifecycleServer) authenticateHello(ctx context.Context, conn *tls.Conn, h LifecycleHello) error {
	if h.ControllerEpoch == lifecycleEpoch(s.config.CurrentGrant) {
		_, err := s.authority.AuthenticateLifecycleResult(ctx, conn, h.ControllerEpoch)
		return err
	}
	if s.config.SuccessorGrant == (a.LifecycleGrant{}) || h.ControllerEpoch != lifecycleEpoch(s.config.SuccessorGrant) {
		return a.ErrUnauthorized
	}
	// The exact configured successor may already have been promoted, including
	// to a now-sealed owner. Never send a stale configured current down this path.
	if _, err := s.authority.AuthenticateLifecycleResult(ctx, conn, h.ControllerEpoch); err == nil {
		return nil
	} else if err != a.ErrUnauthorized {
		return err
	}
	if _, err := s.authority.AuthenticateSuccessor(ctx, conn); err != nil {
		return err
	}
	metadata, err := s.authority.StartupMetadata()
	if err != nil {
		return err
	}
	current := a.Controller{Epoch: lifecycleEpoch(s.config.CurrentGrant), Key: s.config.CurrentGrant.NewKey}
	if metadata.Controller != current || metadata.Store.ID != h.Identity.Store || metadata.Epoch != h.ServiceEpoch {
		return a.ErrUnauthorized
	}
	return nil
}

// Serve owns raw. Cancellation closes IO, but retains the bounded connection
// slot until the synchronous authority operation returns. No abandoned authority
// goroutine or timeout may fabricate completion of disk IO/resource barriers.
func (s *LifecycleServer) Serve(ctx context.Context, raw net.Conn) error {
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
	conn := tls.Server(raw, s.tls)
	l := s.config.Limits
	hctx, cancel := context.WithTimeout(ctx, l.HandshakeTimeout)
	defer cancel()
	if err := conn.SetDeadline(time.Now().Add(l.HandshakeTimeout)); err != nil {
		return err
	}
	if err := conn.HandshakeContext(hctx); err != nil {
		return err
	}
	var h LifecycleHello
	if err := readFrame(conn, &h, 4096, &s.memory); err != nil {
		return err
	}
	if err := s.verify(conn, h); err != nil {
		return err
	}
	if h.ControllerEpoch == lifecycleEpoch(s.config.CurrentGrant) {
		select {
		case s.currentSlots <- struct{}{}:
		default:
			return ErrLimit
		}
		defer func() { <-s.currentSlots }()
	}
	if err := s.authenticateHello(hctx, conn, h); err != nil {
		return err
	}
	if err := writeFrame(conn, h, 4096, &s.memory); err != nil {
		return err
	}
	cancel()
	// Constant-space ordering has no completed-use ceiling; only uint64
	// exhaustion ends the session before an ID could wrap to zero.
	for id := uint64(1); id != 0; id++ {
		// Authenticated idle time is not a partial request. Retain the bounded
		// slot, allocate no frame storage, and let cancellation close raw.
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		var first [1]byte
		if _, err := io.ReadFull(conn, first[:]); err != nil {
			return err
		}
		// One absolute deadline covers the rest of the header and body from
		// the first decrypted frame byte; later chunks cannot extend it.
		if err := conn.SetReadDeadline(time.Now().Add(l.ReadTimeout)); err != nil {
			return err
		}
		var q lifecycleRequest
		if err := readFrame(io.MultiReader(bytes.NewReader(first[:]), conn), &q, l.RequestBytes, &s.memory); err != nil {
			return err
		}
		if !q.valid() || q.ID != id {
			return ErrProtocol
		}
		opctx, done := context.WithTimeout(ctx, l.OperationTimeout)
		closeIO := context.AfterFunc(opctx, func() { raw.Close() })
		r, err := s.operation(opctx, conn, h, q)
		if err != nil {
			r = lifecycleResponse{ID: q.ID, Error: errorCode(err)}
		}
		if opctx.Err() != nil {
			closeIO()
			done()
			return opctx.Err()
		}
		if err = conn.SetWriteDeadline(time.Now().Add(l.WriteTimeout)); err == nil {
			err = writeFrame(conn, r, l.ResponseBytes, &s.memory)
		}
		closeIO()
		done()
		if err != nil {
			return err
		}
	}
	return ErrLimit
}
func (s *LifecycleServer) operation(ctx context.Context, conn *tls.Conn, h LifecycleHello, q lifecycleRequest) (lifecycleResponse, error) {
	r := lifecycleResponse{ID: q.ID}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	// Fresh role/URI/pin/root/time verification AND fresh authority authentication
	// for every operation. Hello is never a cached authorization capability.
	if err := s.verify(conn, h); err != nil {
		return r, err
	}
	c := s.config
	retirement := s.retirement()
	switch {
	case q.ServiceResult != nil:
		g := q.ServiceResult.Grant
		if (g != c.CurrentGrant && g != c.SuccessorGrant) || g.Validate() != nil || len(q.ServiceResult.Nonce) != 32 || lifecycleEpoch(g) != h.ControllerEpoch {
			return r, a.ErrUnauthorized
		}
		principal, err := s.authority.AuthenticateController(ctx, conn, h.ControllerEpoch)
		if err != nil {
			return r, err
		}
		// AuthenticateController above rejects a merely pending successor. Once
		// actually promoted, that same persistent TLS session is the live owner.
		// Linearize the memory-only result with the monotonic retirement arm;
		// do not hold this lock across TLS authentication or journal IO.
		s.retireMu.Lock()
		defer s.retireMu.Unlock()
		if s.retireGrant != (a.LifecycleGrant{}) {
			return r, a.ErrBlocked
		}
		result, err := s.authority.LifecycleServiceResult(principal, g, q.ServiceResult.Nonce)
		if err != nil {
			return r, err
		}
		if result.Validate() != nil || result.Identity != h.Identity || result.Grant != g || !bytes.Equal(result.Nonce, q.ServiceResult.Nonce) || result.ServiceEpoch != h.ServiceEpoch || result.ControllerEpoch != h.ControllerEpoch || result.ControllerKey != g.NewKey {
			return r, a.ErrUnauthorized
		}
		r.ServiceResult = &result
	case q.Result != nil:
		g := q.Result.Grant
		if g.Validate() != nil || len(q.Result.Nonce) != 32 || (g != c.CurrentGrant && g != c.SuccessorGrant && g != retirement) || lifecycleEpoch(g) != h.ControllerEpoch {
			return r, a.ErrUnauthorized
		}
		principal, err := s.authority.AuthenticateLifecycleResult(ctx, conn, h.ControllerEpoch)
		if err != nil {
			return r, err
		}
		receipt, err := s.authority.LifecycleResult(principal, g, q.Result.Nonce)
		if err != nil {
			return r, err
		}
		if receipt.Validate() != nil || receipt.Grant != g || !bytes.Equal(receipt.Nonce, q.Result.Nonce) || receipt.ServiceEpoch != h.ServiceEpoch {
			return r, a.ErrUnauthorized
		}
		r.Receipt = &receipt
	case q.Takeover != nil:
		g := q.Takeover.Grant
		// A cold-open service already committed its configured current takeover.
		// Admit an exact retry, but still authenticate TLS and ask the authority
		// to verify ROOT and prove its real idempotent transition below.
		if g.Operation != a.LifecycleTakeover || (g != c.SuccessorGrant && g != c.CurrentGrant) || h.ControllerEpoch != lifecycleEpoch(g) {
			return r, a.ErrUnauthorized
		}
		principal, err := s.authority.AuthenticateSuccessor(ctx, conn)
		if err != nil {
			return r, err
		}
		controller, err := s.authority.TakeoverLifecycle(principal, *q.Takeover)
		if err != nil {
			return r, err
		}
		r.Controller = &controller
	case q.Retire != nil:
		if q.Retire.Grant != retirement || retirement == (a.LifecycleGrant{}) || h.ControllerEpoch != lifecycleEpoch(retirement) {
			return r, a.ErrUnauthorized
		}
		principal, err := s.authority.AuthenticateController(ctx, conn, h.ControllerEpoch)
		if err != nil {
			return r, err
		}
		if err := s.authority.RetireLifecycle(principal, *q.Retire); err != nil {
			return r, err
		}
		r.OK = &Empty{}
	default:
		return r, ErrProtocol
	}
	return r, nil
}
