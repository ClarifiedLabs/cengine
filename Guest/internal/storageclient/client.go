// Package storageclient implements the disabled managed-v3 client core only.
// It does not mount FUSE, activate a listener, reconnect, or certify a drain.
package storageclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

var (
	ErrClosed     = errors.New("storageclient: terminal connection")
	ErrCapacity   = errors.New("storageclient: bounded capacity exhausted")
	ErrProtocol   = errors.New("storageclient: protocol or grant invariant failure")
	ErrGrant      = errors.New("storageclient: unknown or incompatible live grant")
	ErrIncomplete = errors.New("storageclient: incomplete local cleanup")
)

type Limits struct{ Requests, Events, Nodes, Handles int }

func DefaultLimits() Limits { return Limits{16, 32, 4096, 4096} }

// Config transfers exclusive ownership of an already-handshaken client TLS Conn.
// TLSConfig must be the unmodified settings used to create that connection.
// Go cannot recover those settings from a tls.Conn: their provenance and mutual
// authentication by the server remain the supplying transport's responsibility.
// New validates both settings and observed state; it never dials or handshakes TLS.
type Config struct {
	PrepareCompatibility *preparecompat.Witness
	Conn                 *tls.Conn
	TLSConfig            *tls.Config
	ServerPin            a.Fingerprint
	Authority            a.DataHello
	Version              uint32
	Profile              w.Profile
	SupportedCaps        uint64
	Limits               Limits
	Timeout              time.Duration
	// Invalidate runs on one separate bounded worker. It must honor cancellation,
	// return only after kernel notification completes, and must not call either
	// Close or CloseGracefully.
	Invalidate func(context.Context, Notification) error
}

type Result struct {
	Reply w.Reply
	// Local IDs are allocated only for successful grants, before returning to FUSE.
	Node   LocalNode
	Handle LocalHandle
}
type outcome struct {
	result Result
	err    error
}
type work struct {
	req                        w.Request
	done                       chan outcome
	reserveNode, reserveHandle bool
	cleanup                    bool
	forget                     *nodeState
	// Fixed original-consumer observation only; execute publishes before done.
	observedSequence *uint64
}

type Client struct {
	prepareCompatibility                     *preparecompat.Witness
	localCertificateDER                      []byte
	conn                                     *tls.Conn
	authority                                a.DataHello
	root                                     w.Entry
	timeout                                  time.Duration
	supportedCaps                            uint64
	limits                                   Limits
	invalidate                               func(context.Context, Notification) error
	ctx                                      context.Context
	cancel                                   context.CancelFunc
	mu                                       sync.Mutex
	err                                      error
	completionErr                            error
	originalRead                             *originalConsumerRead      // guarded by mu; one fixed read witness
	originalFile                             *originalConsumerFile      // guarded by mu; one bounded passive trace
	pendingProbes                            map[xattrProbeKey]struct{} // guarded by mu; bounded by Limits.Requests
	prepareReadDir                           *prepareReadDirRetry       // guarded by mu; bounded replay completion evidence
	sealed, stopping                         bool
	processing, replyPending                 bool
	pendingEvents, captures                  int
	changed, joined                          chan struct{}
	terminal                                 chan struct{}
	wake                                     chan struct{}
	queue                                    []*work
	requests, reservedNodes, reservedHandles int
	pins                                     uint64
	sequence                                 uint64
	outstanding                              *w.Request
	replies                                  chan w.Reply
	replyApplied                             chan struct{}
	credentialSlots                          chan struct{}
	events                                   chan *eventWork
	eventTail                                *eventWork // guarded by mu; never the running callback
	wg                                       sync.WaitGroup
	nodes                                    map[LocalNode]*nodeState
	wireNodes                                map[w.NodeID]*nodeState
	handles                                  map[LocalHandle]*handleState
	wireHandles                              map[w.HandleID]*handleState
	nextNode, nextHandle                     uint64
}

func New(cfg Config) (_ *Client, err error) {
	if cfg.Conn == nil {
		return nil, ErrProtocol
	}
	// Close the underlying transport directly: TLS close_notify may otherwise wait
	// on a blocked writer. All terminal paths are bounded by transport closure.
	defer func() {
		if err != nil {
			_ = cfg.Conn.NetConn().Close()
		}
	}()
	t := cfg.TLSConfig
	if t == nil || t.MinVersion != tls.VersionTLS13 || t.MaxVersion != tls.VersionTLS13 || !t.SessionTicketsDisabled || t.ClientSessionCache != nil || t.InsecureSkipVerify || len(t.Certificates) != 1 || len(t.Certificates[0].Certificate) == 0 || t.GetClientCertificate != nil {
		return nil, ErrProtocol
	}
	local, e := x509.ParseCertificate(t.Certificates[0].Certificate[0])
	if e != nil {
		return nil, e
	}
	key, e := a.PublicKeyFingerprint(local.PublicKey)
	if e != nil || key != cfg.Authority.Binding.Key {
		return nil, ErrProtocol
	}
	if cfg.PrepareCompatibility != nil && cfg.PrepareCompatibility.ValidateDataAuthority(cfg.Authority, local.Raw) != nil {
		return nil, ErrProtocol
	}
	state := cfg.Conn.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return nil, ErrProtocol
	}
	leaf := state.PeerCertificates[0]
	verified, server := false, false
	for _, chain := range state.VerifiedChains {
		if len(chain) > 0 && chain[0].Equal(leaf) {
			verified = true
		}
	}
	for _, use := range leaf.ExtKeyUsage {
		if use == x509.ExtKeyUsageServerAuth {
			server = true
		}
	}
	pin, e := a.PublicKeyFingerprint(leaf.PublicKey)
	if e != nil || !verified || !server || pin != cfg.ServerPin {
		return nil, ErrProtocol
	}
	if cfg.Version != w.Version || cfg.Profile != w.RequiredProfile() || cfg.SupportedCaps == 0 || cfg.Timeout <= 0 || cfg.Invalidate == nil {
		return nil, ErrProtocol
	}
	l := cfg.Limits
	if l.Requests < 1 || l.Requests > 1024 || l.Events < 1 || l.Events > 1024 || l.Nodes < 1 || l.Nodes > 65536 || l.Handles < 1 || l.Handles > 65536 {
		return nil, ErrCapacity
	}
	hello := w.ClientHello{Authority: cfg.Authority, Profile: cfg.Profile}
	if err = hello.Validate(); err != nil {
		return nil, err
	}
	if err = cfg.Conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return nil, err
	}
	var sh w.ServerHello
	if err = w.ReadFrame(cfg.Conn, &sh); err != nil {
		return nil, err
	}
	if sh.Epoch != cfg.Authority.Epoch || sh.Version != cfg.Version || sh.Profile != cfg.Profile {
		return nil, ErrProtocol
	}
	if err = w.WriteFrame(cfg.Conn, &hello); err != nil {
		return nil, err
	}
	var root w.RootReply
	if err = w.ReadFrame(cfg.Conn, &root); err != nil {
		return nil, err
	}
	if err = cfg.Conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{prepareCompatibility: cfg.PrepareCompatibility, localCertificateDER: append([]byte(nil), local.Raw...), conn: cfg.Conn, authority: cfg.Authority, root: root.Root, timeout: cfg.Timeout, supportedCaps: cfg.SupportedCaps, limits: l, invalidate: cfg.Invalidate, ctx: ctx, cancel: cancel, terminal: make(chan struct{}), changed: make(chan struct{}), joined: make(chan struct{}), wake: make(chan struct{}, 1), replies: make(chan w.Reply, 1), replyApplied: make(chan struct{}, 1), credentialSlots: make(chan struct{}, l.Requests), events: make(chan *eventWork, l.Events), nodes: make(map[LocalNode]*nodeState), wireNodes: make(map[w.NodeID]*nodeState), handles: make(map[LocalHandle]*handleState), wireHandles: make(map[w.HandleID]*handleState), nextNode: 1}
	n := &nodeState{local: 1, entry: root.Root, pinned: true}
	c.nodes[1], c.wireNodes[root.Root.Node] = n, n
	c.pins = 1 // lifetime root pin; not consumable by FORGET
	c.wg.Add(4)
	go func() { defer c.wg.Done(); <-c.ctx.Done(); _ = c.conn.NetConn().Close() }()
	go c.execute()
	go c.receive()
	go c.notify()
	go func() { c.wg.Wait(); close(c.joined) }()
	return c, nil
}

// Authority returns immutable session metadata, not an admission/drain receipt.
func (c *Client) Authority() a.DataHello     { return c.authority }
func (c *Client) Root() (LocalNode, w.Entry) { return 1, c.root }

// Terminal closes on any terminal failure. Its consumer must abort this exact
// mount and request attachment retirement. That consumer must never infer drain.
func (c *Client) Terminal() <-chan struct{} { return c.terminal }
func (c *Client) Err() error                { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
func (c *Client) failLocked(err error) {
	if p := c.originalFile; p != nil && (err == ErrClosed && !c.completedCapabilityFailure() || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrProtocol) || errors.Is(err, w.ErrInvalid)) {
		p.invalid = true
	}
	if c.err == nil {
		c.err = errors.Join(ErrClosed, c.completionError(), err)
		close(c.terminal)
		c.cancel()
	} else if !errors.Is(c.err, err) {
		// In particular, Close must not hide a concurrent adapter Abort reason.
		c.err = errors.Join(c.err, err)
	}
	c.broadcastLocked()
}
func (c *Client) fail(err error) { c.mu.Lock(); defer c.mu.Unlock(); c.failLocked(err) }

// Abort records terminal delivery/adapter failure without waiting or socket I/O.
// The owner must still join with Close and request authority retirement.
func (c *Client) Abort(reason error) {
	c.mu.Lock()
	if c.originalFile != nil && !(c.completedCapabilityFailure() && reason == c.err) {
		c.originalFile.invalid = true
	}
	c.mu.Unlock()
	if reason == nil {
		reason = ErrClosed
	}
	c.fail(reason)
}

// Close joins transport work and invalidation callbacks, not server-side admitted
// operations. Remote mutations may still own authority guards after socket loss.
func (c *Client) Close() error { c.fail(ErrClosed); c.wg.Wait(); return c.Err() }
func (c *Client) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Do is synchronous and FIFO by admission under the client lock. It has no
// cancellation after enqueue and never retries. none must be zero for PRESENT;
// for captured NONE it must explicitly select an allowed grant/metadata/lifecycle
// provenance. Body uses wire tokens obtained from Node/Handle, not local IDs.
// Request bytes/credentials are copied before admission; callers must not mutate
// input during this call. FORGET is exclusively through Forget below.
func (c *Client) Do(s Snapshot, none w.AuthKind, body w.RequestBody) (Result, error) {
	return c.do(s, none, body, nil)
}

func (c *Client) do(s Snapshot, none w.AuthKind, body w.RequestBody, sequence *uint64) (result Result, callErr error) {
	c.mu.Lock()
	if p := c.originalRead; p != nil {
		p.calls++
		defer func() {
			c.mu.Lock()
			p.calls--
			if callErr != nil {
				p.reject(OriginalReadReply)
			}
			c.mu.Unlock()
		}()
		switch b := body.(type) {
		case w.GetAttrRequest:
			// Linux fuse_file_read_iter refreshes the open file's attributes
			// before issuing READ. Allow ONE joined, same-object prelude, never
			// arbitrary metadata or a replacement for the actual READ witness.
			if p.attempted || p.metadataCalled || p.calls != 1 {
				p.reject(OriginalReadGetAttr)
			}
			p.metadataCalled = true
		case w.ReadRequest:
			if p.attempted {
				p.reject(OriginalReadRepeated)
			} else if b.Offset != 0 || b.Size == 0 || b.Size > 4096 || !originalReadFlags(b.IOFlags) {
				p.reject(OriginalReadShape)
			}
			if p.calls != 1 || p.metadataCalled && p.metadata == nil {
				p.reject(OriginalReadUnjoined)
			}
			p.attempted = true
		case w.ReleaseDirRequest:
			p.reject(OriginalReadReleaseDir)
		default:
			p.reject(OriginalReadTraffic)
		}
	}
	if p := c.originalFile; p != nil {
		p.calls++
		defer func() {
			c.mu.Lock()
			p.calls--
			if callErr != nil && c.err == nil {
				p.invalid = true
			}
			c.mu.Unlock()
		}()
		if p.capability {
			switch b := body.(type) {
			case w.GetXAttrRequest:
				if p.capabilityCalled || p.syncCalled || b.Node == 0 || string(b.Name) != "security.capability" {
					p.invalid = true
				}
				p.capabilityCalled = true
			case w.FsyncRequest:
				v := p.trace.Capability
				if p.syncCalled || v == nil || !p.capabilityDone || c.err == nil || b.DataOnly || uint64(b.Node) != v.Node || b.Handle == 0 {
					p.invalid = true
				}
				p.syncCalled = true
			default:
				p.invalid = true
			}
		} else {
			switch b := body.(type) {
			case w.WriteRequest:
				want := byte(0x5a)
				if p.positive {
					want = 0xa5
				}
				if p.writeCalled || p.syncCalled || b.Offset != 0 || len(b.Data) != 1 || b.Data[0] != want {
					p.invalid = true
				}
				p.writeCalled = true
			case w.FsyncRequest:
				if p.syncCalled {
					p.invalid = true
				}
				p.syncCalled = true
				v := p.trace.Write
				if v == nil || b.DataOnly || uint64(b.Node) != v.Node || uint64(b.Handle) != v.Handle {
					p.invalid = true
				}
			default:
				if (w.Request{Body: body}).Mutates() {
					p.invalid = true
				}
			}
		}
	}
	if err := c.admissionLocked(); err != nil {
		c.mu.Unlock()
		return Result{}, err
	}
	cleanup := false
	switch body.(type) {
	case w.ReleaseRequest, w.ReleaseDirRequest:
		cleanup = true
	}
	reject := func(err error) (Result, error) {
		if cleanup {
			c.failLocked(err)
			err = c.err
		}
		c.mu.Unlock()
		return Result{}, err
	}
	auth, err := c.auth(s, none)
	if err != nil {
		return reject(err)
	}
	// Kernel metadata and credentials are one immutable capture. Builders cannot
	// assert even an equal value, nor use a metadata capture for another opcode.
	if b, ok := body.(w.SetAttrRequest); ok {
		if b.Semantics != 0 || !s.present || s.semantics&w.MetadataValid == 0 {
			return reject(ErrCredentials)
		}
		b.Semantics = s.semantics
		body = b
	} else if s.semantics != 0 {
		return reject(ErrCredentials)
	}
	req := w.Request{Sequence: 1, Auth: auth, Body: body}
	if err = req.ValidateBinding(c.authority.Binding); err != nil {
		return reject(err)
	}
	if _, ok := body.(w.ForgetRequest); ok {
		c.mu.Unlock()
		return Result{}, ErrGrant
	}
	job := &work{req: req, done: make(chan outcome, 1), observedSequence: sequence}
	job.cleanup = cleanup
	if !job.cleanup && c.requests >= c.limits.Requests {
		c.mu.Unlock()
		return Result{}, ErrCapacity
	}
	if err = c.checkRequest(req); err != nil {
		if job.cleanup {
			c.failLocked(err)
		}
		c.mu.Unlock()
		return Result{}, err
	}
	job.reserveNode, job.reserveHandle = grantCapacity(body.Operation())
	if job.reserveNode && (len(c.nodes)+c.reservedNodes >= c.limits.Nodes || c.pins+uint64(c.reservedNodes) >= uint64(c.limits.Nodes)) || job.reserveHandle && len(c.handles)+c.reservedHandles >= c.limits.Handles {
		c.mu.Unlock()
		return Result{}, ErrCapacity
	}
	encoded, err := w.Marshal(&req)
	if err == nil {
		err = w.Unmarshal(encoded, &job.req)
	}
	if err != nil {
		c.mu.Unlock()
		return Result{}, err
	}
	if job.reserveNode {
		c.reservedNodes++
	}
	if job.reserveHandle {
		c.reservedHandles++
	}
	if job.cleanup {
		_, h := operands(req.Body)
		c.wireHandles[h].releasing = true
	} else {
		c.requests++
	}
	c.queue = append(c.queue, job)
	c.broadcastLocked()
	c.signal()
	c.mu.Unlock()
	out := <-job.done
	return out.result, out.err
}

func (c *Client) execute() {
	defer c.wg.Done()
	for {
		c.mu.Lock()
		if c.err != nil || c.stopping {
			for _, j := range c.queue {
				if j.done != nil {
					j.done <- outcome{err: c.err}
				}
			}
			c.queue = nil
			c.mu.Unlock()
			return
		}
		if len(c.queue) == 0 {
			c.mu.Unlock()
			select {
			case <-c.wake:
			case <-c.ctx.Done():
			}
			continue
		}
		c.processing = true
		j := c.queue[0]
		c.queue[0] = nil
		c.queue = c.queue[1:]
		if j.forget != nil {
			if j.forget.pending == j {
				j.forget.pending = nil
			}
			body := j.req.Body.(w.ForgetRequest)
			// Only adjacent cleanup records can batch; never move cleanup past an RPC.
			for len(c.queue) > 0 && c.queue[0].forget != nil && len(body.Entries) < w.MaxForget {
				next := c.queue[0]
				e := next.req.Body.(w.ForgetRequest).Entries[0]
				duplicate := false
				for _, existing := range body.Entries {
					if existing.Node == e.Node {
						duplicate = true
						break
					}
				}
				if duplicate {
					break
				}
				if next.forget.pending == next {
					next.forget.pending = nil
				}
				body.Entries = append(body.Entries, e)
				c.queue[0] = nil
				c.queue = c.queue[1:]
			}
			j.req.Body = body
		}
		if c.sequence == math.MaxUint64 {
			c.failLocked(ErrProtocol)
			if j.done != nil {
				j.done <- outcome{err: c.err}
			}
			c.processing = false
			c.broadcastLocked()
			c.mu.Unlock()
			continue
		}
		c.sequence++
		j.req.Sequence = c.sequence
		if j.observedSequence != nil {
			*j.observedSequence = c.sequence
		}
		c.observeOriginalFileRequest(j.req)
		c.outstanding = &j.req
		c.mu.Unlock()
		err := c.conn.SetDeadline(time.Now().Add(c.timeout))
		if err == nil {
			err = c.writeRequest(&j.req)
		}
		var reply w.Reply
		if err == nil {
			select {
			case reply = <-c.replies:
			case <-c.ctx.Done():
				err = c.Err()
			}
		}
		if err == nil {
			err = c.conn.SetDeadline(time.Time{})
		}
		c.mu.Lock()
		result := Result{Reply: reply}
		if err == nil && c.err != nil {
			err = c.err
		}
		if err == nil {
			err = c.apply(j, &result)
		}
		if err != nil {
			c.failLocked(err)
			err = c.err
		}
		c.observeOriginalFileCompletion(j.req, reply, err)
		c.observeOriginalReadCompletion(j.req, reply, err)
		if j.reserveNode {
			c.reservedNodes--
		}
		if j.reserveHandle {
			c.reservedHandles--
		}
		if !j.cleanup {
			c.requests--
		}
		c.mu.Unlock()
		if err == nil {
			select {
			case c.replyApplied <- struct{}{}:
			case <-c.ctx.Done():
			}
		}
		if j.done != nil {
			j.done <- outcome{result: result, err: err}
		}
		c.mu.Lock()
		c.processing = false
		c.broadcastLocked()
		c.mu.Unlock()
	}
}

func (c *Client) receive() {
	defer c.wg.Done()
	var replies, events w.SequenceTracker
	for {
		message, err := w.ReadServerFrame(c.conn)
		if err != nil {
			c.mu.Lock()
			// Only our intentional transport close is benign; peer EOF is not.
			if !c.stopping || !(errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)) {
				c.failLocked(err)
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		// The reader owns this decoded frame even if shutdown won the lock.
		// Validate it before joining: stopping cannot turn a known protocol
		// violation into clean completion. Admission remains sealed below.
		switch v := message.(type) {
		case *w.Reply:
			if c.outstanding == nil {
				err = ErrProtocol
			} else if err = replies.Accept(v.Sequence); err == nil {
				err = w.ValidateReplyFor(*c.outstanding, *v)
			}
			if err == nil && c.err == nil && !c.stopping {
				c.outstanding = nil
				c.replyPending = true
				select {
				case c.replies <- *v:
				default:
					err = ErrProtocol
				}
			}
		case *w.Event:
			if v.Volume != c.authority.Binding.Volume {
				err = ErrProtocol
			} else {
				err = events.Accept(v.EventSequence)
			}
			if err == nil && c.err == nil && !c.stopping {
				err = c.enqueueEvent(*v)
			}
		default:
			err = ErrProtocol
		}
		if err != nil {
			if c.originalFile != nil {
				c.originalFile.invalid = true
			}
			c.failLocked(err)
		}
		terminal := c.err != nil || c.stopping
		c.broadcastLocked()
		c.mu.Unlock()
		if terminal {
			return // never read another packet or admit callbacks after stop
		}
		if _, ok := message.(*w.Reply); ok {
			// Publish grants before any following object event can be mapped locally.
			select {
			case <-c.replyApplied:
				c.mu.Lock()
				c.replyPending = false
				c.broadcastLocked()
				c.mu.Unlock()
			case <-c.ctx.Done():
				return
			}
		}
	}
}
func (c *Client) notify() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case event := <-c.events:
			c.mu.Lock()
			if c.err != nil || c.stopping {
				c.mu.Unlock()
				return
			}
			if c.eventTail == event {
				c.eventTail = nil
			}
			// The cell is now immutable: later invalidations cannot be covered by
			// a kernel notification that has already begun.
			n := c.notification(event.event)
			c.mu.Unlock()
			err := c.invalidate(c.ctx, n)
			c.mu.Lock()
			if event.count <= 0 || c.pendingEvents < event.count {
				err = errors.Join(err, ErrProtocol)
			} else {
				c.pendingEvents -= event.count
			}
			if err != nil {
				c.failLocked(err)
			}
			c.broadcastLocked()
			c.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}
