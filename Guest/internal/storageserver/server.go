// Package storageserver implements the disabled managed-v3 DATA transport.
// It opens no listener and is not wired into guest startup.
package storageserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
)

var (
	ErrConfiguration = errors.New("storageserver: unsafe or invalid configuration")
	ErrOverload      = errors.New("storageserver: bounded capacity exhausted")
	ErrStorage       = errors.New("storageserver: terminal storage failure")
)

// Limits bound concurrent connections (including retirement callbacks), complete
// received requests, and per-connection output bytes/messages. Zero selects defaults.
// Payload receipt reserves MaxFrame bytes after the fixed-size frame header and
// through execution; codec copies have a bounded multiplier of that input budget.
// ReadTimeout applies only once a frame starts. Idle connections own no payload
// reservation and have no inactivity deadline.
type Limits struct {
	Connections      int
	ReceiveFrames    int
	WriterMessages   int
	WriterBytes      int
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
}

// ValidateLimits permits service owners to reject configuration before opening
// authority (which durably rotates E). It normalizes only the all-zero default.
func ValidateLimits(l Limits) (Limits, error) {
	if l == (Limits{}) {
		l = DefaultLimits()
	}
	if l.Connections < 1 || l.Connections > 1024 || l.ReceiveFrames < 1 || l.ReceiveFrames > 1024 || l.WriterMessages < 1 || l.WriterMessages > 4096 || l.WriterBytes < w.MaxFrame+4 || l.WriterBytes > 64*w.MaxFrame || l.HandshakeTimeout <= 0 || l.ReadTimeout <= 0 || l.WriteTimeout <= 0 {
		return l, ErrConfiguration
	}
	return l, nil
}

func DefaultLimits() Limits {
	return Limits{32, 16, 64, 4 * w.MaxFrame, 10 * time.Second, 30 * time.Second, 10 * time.Second}
}

type Config struct {
	// TLSConfig is validated and copied into a private, server-side-only snapshot.
	// Only static certificates with standard, exportable private keys are accepted.
	// RootCAs and ClientCAs must both be nil; pool constraints cannot be snapshotted.
	TLSConfig *tls.Config
	// ClientRoots is the sole client trust input: a nonempty list of DER anchors.
	// New copies and reparses DER into a private pool without caller-owned hooks.
	ClientRoots [][]byte
	Limits      Limits
	// RequestRetirement runs once, asynchronously, for a successfully authenticated
	// attachment on every terminal failure, including EOF. It must arrange control-
	// plane retirement of this exact A,E; it is NOT itself a drain receipt. Connection
	// capacity remains charged until it returns, bounding even blocked callbacks.
	RequestRetirement func(a.DataHello, error)
}

type executor interface {
	Dispatch(*a.Guard, w.Request) (m.Result, error)
}
type sessionFactory func(*a.Guard, *a.DataPrincipal, a.Binding) (executor, w.Entry, error)

// Server must not be copied. Create it before opening Authority so Config.Barrier
// can be set to server.Barrier. All Serve calls must use that same Authority.
type Server struct {
	config       Config
	resources    *Resources
	pki          *PKIConfig
	factory      sessionFactory  // internal-only seam; no public authentication bypass
	copyHooks    *copyFenceHooks // internal test synchronization; immutable once Serve starts
	connections  chan struct{}
	receive      chan struct{}
	mu           sync.Mutex
	authority    *a.Authority
	serveStarted bool // under mu; permanent install boundary, not connection liveness
	// Serializes FS completion and bounded output handoff across attachments. It is
	// distinct from Registry's namespace gate and never waits for network I/O.
	dispatch sync.Mutex
	peers    map[*peer]struct{} // protected by dispatch
	events   w.SequenceTracker  // managed global event sequence, protected by dispatch
}

func New(c Config) (*Server, error) {
	r, err := NewResources()
	if err != nil {
		return nil, err
	}
	return NewWithResources(r, c)
}

// NewWithResources consumes r once, after it has supplied the authority barrier.
// Generic TLS policy remains strictly callback/pool-free.
func NewWithResources(r *Resources, c Config) (*Server, error) {
	ownedTLS, err := snapshotTLS(c.TLSConfig, c.ClientRoots)
	if err != nil {
		return nil, err
	}
	return newOwned(r, c, ownedTLS)
}

func newOwned(r *Resources, c Config, ownedTLS *tls.Config) (*Server, error) {
	if c.RequestRetirement == nil {
		return nil, ErrConfiguration
	}
	l, err := ValidateLimits(c.Limits)
	if err != nil {
		return nil, err
	}
	c.Limits = l
	c.TLSConfig = ownedTLS
	c.ClientRoots = nil // no caller-owned certificate bytes survive construction
	if r == nil {
		return nil, ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.registry == nil || r.claimed {
		return nil, ErrConfiguration
	}
	r.claimed = true
	s := &Server{config: c, resources: r, connections: make(chan struct{}, l.Connections), receive: make(chan struct{}, l.ReceiveFrames), peers: make(map[*peer]struct{})}
	s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		exec, entry, err := m.New(g, p, b, &r.gate, &r.worker, r.registry)
		// New closes all setup resources on failure. On success the still-held
		// guard prevents Barrier from racing this ownership registration.
		if err == nil {
			r.mu.Lock()
			r.live[b.Attachment] = true
			r.mu.Unlock()
		}
		return exec, entry, err
	}
	return s, nil
}

// Barrier is only for storageauthority.Config.Barrier. Authority must fence and
// join all admitted work first. Socket close and RELEASE never call this directly.
func (s *Server) Barrier(b a.Binding, root *os.File) error { return s.resources.Barrier(b, root) }

// Serve takes ownership of a raw transport and constructs server-side TLS using
// its privately owned configuration. Already-wrapped TLS connections are rejected.
// Cancellation terminates transport, but cannot cancel or release admitted work.
// Serve joins every admitted RPC and its retirement callback before returning.
func (s *Server) Serve(ctx context.Context, authority *a.Authority, raw net.Conn) error {
	if raw == nil {
		return ErrConfiguration
	}
	defer raw.Close()
	if ctx == nil || authority == nil {
		return ErrConfiguration
	}
	if _, wrapped := raw.(*tls.Conn); wrapped {
		return ErrConfiguration
	}
	select {
	case s.connections <- struct{}{}:
	default:
		return ErrOverload
	}
	defer func() { <-s.connections }()
	s.mu.Lock()
	s.serveStarted = true
	if s.authority == nil {
		s.authority = authority
	}
	same := s.authority == authority
	s.mu.Unlock()
	if !same {
		return ErrConfiguration
	}
	transport, observation := s.observeTLSFailure(ctx, raw)
	conn := tls.Server(transport, s.config.TLSConfig)
	p := &peer{consumer: consumerFrom(ctx), server: s, conn: conn, done: make(chan struct{}), inputStopped: make(chan struct{}), rootWritten: make(chan struct{}), retired: make(chan struct{}), wake: make(chan struct{}, 1)}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.fail(ctx.Err())
		case <-stopped:
		}
	}()
	defer close(stopped)
	// Handshake deadlines cover TLS and all three protocol messages. Root setup is
	// admitted synchronous work: a deadline closes transport but never abandons it.
	timer := time.AfterFunc(s.config.Limits.HandshakeTimeout, func() { p.fail(context.DeadlineExceeded) })
	defer timer.Stop()
	err := p.handshake(ctx, authority, observation)
	if err != nil {
		p.fail(err)
		s.dispatch.Lock()
		delete(s.peers, p)
		s.dispatch.Unlock()
		p.joinRetirement()
		return p.failure()
	}
	writerDone := make(chan struct{})
	go func() { defer close(writerDone); p.writeLoop() }()
	// The handshake is not complete merely because its root frame was queued.
	// No RPC can execute until the complete RootReply has reached the TLS writer.
	select {
	case <-p.rootWritten:
	case <-p.done:
		<-writerDone
		s.dispatch.Lock()
		delete(s.peers, p)
		s.dispatch.Unlock()
		p.joinRetirement()
		return p.failure()
	}
	if p.consumer != nil {
		p.consumer.established = time.Now()
	}
	timer.Stop()
	p.mu.Lock()
	if !p.inputClosed {
		err = p.conn.SetReadDeadline(time.Time{})
	}
	p.mu.Unlock()
	if err != nil {
		p.fail(err)
	}
	jobs := make(chan task, 1)
	readerDone := make(chan struct{})
	go func() { defer close(readerDone); defer close(jobs); p.readLoop(authority, jobs) }()
	for job := range jobs {
		// PREPARE begins under dispatch too, so the successful check and actual
		// execution are ordered against BeginCopy. Never park while owning the
		// service-wide completion/publication lock.
		fenceErr := s.lockCopyDispatch(job.guard)
		var result m.Result
		var err error
		if fenceErr != nil {
			err = fenceErr
		} else {
			result, err = p.executor.Dispatch(job.guard, job.request)
		}
		dropBind := false
		if req, ok := job.request.Body.(w.PrepareRequest); ok && req.Action == w.BindCopyTransaction && err == nil && result.Reply.Errno == 0 {
			if reply, ok := result.Reply.Body.(w.PrepareReply); ok {
				dropBind = job.guard.PrepareCompatibilityBoundReply(job.request.Sequence, reply.Intent)
			}
		}
		// Dispatch has joined identity callbacks and transferred every retained FD to
		// Registry barrier ownership. No slow output path may keep this guard alive.
		job.guard.Release()
		<-p.receivePool()
		replyErr := w.ValidateReplyFor(job.request, result.Reply)
		publishErr := s.publish(p, job.request, result, replyErr == nil && !dropBind, err)
		if dropBind {
			p.fail(ErrStorage)
		} // reply loss, not a volume durability fault
		err = errors.Join(err, replyErr, publishErr)
		if err != nil {
			p.stopForStorage(err)
			// A managed durability fault is volume-sticky; close every affected
			// attachment rather than waiting for each to issue another RPC.
			if errors.Is(err, m.ErrVolumeFault) || publishErr != nil {
				for other := range s.peers {
					if other.hello.Binding.Volume == p.hello.Binding.Volume {
						other.stopForStorage(err)
					}
				}
			}
		}
		s.dispatch.Unlock()
	}
	<-readerDone
	p.finishWrites()
	<-writerDone
	s.dispatch.Lock()
	delete(s.peers, p)
	s.dispatch.Unlock()
	p.joinRetirement()
	return p.failure()
}

func (p *peer) handshake(ctx context.Context, authority *a.Authority, observation *tlsFailureReadObserver) error {
	if err := p.conn.SetDeadline(time.Now().Add(p.server.config.Limits.HandshakeTimeout)); err != nil {
		return err
	}
	if err := p.conn.HandshakeContext(ctx); err != nil {
		// Snapshot the actual raw read prefix before fail closes this transport.
		return observation.failure(err)
	}
	defer observation.stop()
	state := p.conn.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return a.ErrUnauthorized
	}
	p.consumerLeaf = sha256.Sum256(state.PeerCertificates[0].Raw)
	hello := w.ServerHello{Epoch: authority.Epoch(), Version: w.Version, Profile: w.RequiredProfile()}
	if err := w.WriteFrame(p.conn, &hello); err != nil {
		return err
	}
	var client w.ClientHello
	if err := w.ReadFrame(p.conn, &client); err != nil {
		return err
	}
	if p.server.pki != nil {
		if err := p.server.pki.verifyPeer(state, client.Authority); err != nil {
			return observation.peerFailure(state, client.Authority, err)
		}
	}
	observation.stop()
	principal, err := authority.AuthenticateData(ctx, p.conn, client.Authority)
	if p.server.pki != nil {
		// Passive result boundary: verified current TLS/PKI, before any root grant.
		p.consumer.authentication(ctx, client.Authority, p.consumerLeaf, p.server.pki.Store, p.server.pki.ServiceEpoch, err)
	}
	if err != nil {
		return err
	}
	binding, err := principal.Binding()
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.principal = principal
	p.hello = a.DataHello{Epoch: hello.Epoch, Binding: binding}
	p.mu.Unlock()
	if binding.Role == a.PrepareRole {
		// One reserved frame per authenticated PREPARE connection prevents
		// fenced runtime requests from consuming the owner's progress capacity.
		// Charged by the existing connection bound; not a timeout increase.
		p.prepareReceive = make(chan struct{}, 1)
	}
	// A deadline may race successful authentication: still retire the exact binding.
	if err = p.failure(); err != nil {
		p.requestRetirement()
		return err
	}
	g, err := authority.Admit(principal, binding.Volume, false)
	if err != nil {
		return err
	}
	p.server.dispatch.Lock()
	defer p.server.dispatch.Unlock()
	exec, root, err := p.server.factory(g, principal, binding)
	g.Release()
	if err != nil {
		return err
	}
	p.executor = exec
	if p.consumer != nil {
		p.consumer.rootNode = root.Node
	}
	if err = p.enqueueMessage(&w.RootReply{Root: root}); err != nil {
		return err
	}
	p.server.peers[p] = struct{}{}
	return nil
}

func (s *Server) publish(origin *peer, request w.Request, result m.Result, includeReply bool, dispatchErr error) error {
	// Reply precedes this RPC's invalidations on its origin, so new node ownership
	// is installed before ObjectID translation. All events, including partial-error
	// mutations, precede any subsequent dispatch result on every recipient.
	var reply []byte
	if includeReply {
		var err error
		reply, err = frame(&result.Reply)
		if err != nil {
			return err
		}
	}
	events := make([][]byte, 0, len(result.Events))
	for i := range result.Events {
		e := &result.Events[i]
		if e.Volume != origin.hello.Binding.Volume {
			return fmt.Errorf("%w: event volume", ErrStorage)
		}
		b, err := frame(e)
		if err != nil {
			return err
		}
		if err := s.events.Accept(e.EventSequence); err != nil {
			return err
		}
		events = append(events, b)
	}
	// Decide only after validating every event and consuming its global sequence,
	// including DATA events that will not be echoed to the successful origin.
	omitOriginData := includeReply && dispatchErr == nil && originMaintainsData(request, result.Reply)
	// enqueue handles its own peer-local failure: it terminates that exact
	// attachment and requests retirement. Do not promote slow output to a volume
	// filesystem fault or stop delivery to healthy recipients.
	if reply != nil {
		_ = origin.enqueue(reply)
	}
	for peer := range s.peers {
		if peer.hello.Binding.Volume != origin.hello.Binding.Volume {
			continue
		}
		for i, event := range events {
			if peer == origin && omitOriginData && result.Events[i].Kind == w.InvalidateData {
				continue
			}
			_ = peer.enqueue(event)
		}
	}
	return nil
}

type task struct {
	guard   *a.Guard
	request w.Request
}

func (p *peer) readLoop(authority *a.Authority, jobs chan<- task) {
	var sequence w.SequenceTracker
	for {
		request, err := p.readRequest()
		p.mu.Lock()
		stopped := p.inputClosed
		p.mu.Unlock()
		if err != nil {
			if !stopped {
				p.fail(err)
			}
			return
		}
		release := func() { <-p.receivePool() }
		if stopped {
			release()
			return
		}
		if err = sequence.Accept(request.Sequence); err != nil {
			release()
			p.fail(err)
			return
		}
		if begin, ok := request.Body.(w.PrepareRequest); ok && begin.Action == w.BeginCopy {
			authority.PrepareCompatibilityAdmission(p.hello, request.Sequence, nil)
		}
		// Read-only policy failures still need an admitted nonmutating error reply.
		mutates := request.Mutates() && p.hello.Binding.Mode != a.ReadOnly
		guard, err := authority.Admit(p.principal, p.hello.Binding.Volume, mutates)
		p.consumer.admission(p.hello, p.consumerLeaf, request, err)
		if begin, ok := request.Body.(w.PrepareRequest); ok && begin.Action == w.BeginCopy {
			authority.PrepareCompatibilityAdmissionResult(p.hello, request.Sequence, err)
			if err == nil {
				authority.PrepareCompatibilityAdmission(p.hello, request.Sequence, guard)
			}
		}
		if err != nil {
			release()
			p.fail(err)
			return
		}
		if hooks := p.server.copyHooks; hooks != nil && hooks.admitted != nil {
			hooks.admitted(p.hello.Binding, guard, request)
		}
		// Admission is irrevocable. The receive reservation bounds this handoff,
		// including its blocked sender; Serve drains jobs even after socket loss.
		// Never select cancellation or release/drop an already-admitted request.
		jobs <- task{guard, request}
	}
}
