package storageserver

import (
	"context"
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"encoding/hex"
	"sync"
	"time"
)

// ConsumerObservation is a bounded, passive recorder. No method returns a guard,
// changes authentication, cancels work, or installs executable caller callbacks.
// It is allocated at Service construction, before any DATA connection is started.
type ConsumerObservation struct {
	mu       sync.Mutex
	status   *cc.Status
	armedAt  time.Time
	timer    *time.Timer
	selected *consumerConnection
}
type consumerKey struct{}
type consumerConnection struct {
	owner             *ConsumerObservation
	established       time.Time
	rootNode          w.NodeID // actual RootReply token; set before readLoop starts
	tlsSelected       bool
	reconnectSelected bool
}

func NewConsumerObservation() *ConsumerObservation { return &ConsumerObservation{} }
func (o *ConsumerObservation) fail(reason string) {
	if o.status == nil || o.status.State == "failed" || o.status.State == "finalized" {
		return
	}
	o.status.State = "failed"
	o.status.Failure = reason
	o.status.Evidence = nil
	if o.timer != nil {
		o.timer.Stop()
	}
}
func (o *ConsumerObservation) snapshot() cc.Status {
	s := *o.status
	if s.Evidence != nil {
		e := *s.Evidence
		s.Evidence = &e
		if e.Hello != nil {
			h := *e.Hello
			s.Evidence.Hello = &h
		}
		if e.Admission != nil {
			a := *e.Admission
			s.Evidence.Admission = &a
		}
	}
	return s
}
func (o *ConsumerObservation) Arm(q cc.Arm) (cc.Status, error) {
	if pc.CurrentProfile() != pc.FullProfile || cc.ValidateArm(q) != nil {
		return cc.Status{}, cc.ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.status != nil {
		o.fail("duplicate")
		return cc.Status{}, cc.ErrInvalid
	}
	o.status = &cc.Status{Query: q, State: "armed"}
	o.armedAt = time.Now()
	o.timer = time.AfterFunc(10*time.Second, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.status.State != "observed" {
			o.fail("timeout")
		}
	})
	return o.snapshot(), nil
}
func (o *ConsumerObservation) Query(q cc.Query) (cc.Status, error) {
	if pc.CurrentProfile() != pc.FullProfile || cc.ValidateArm(q) != nil {
		return cc.Status{}, cc.ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.status == nil {
		return cc.Status{}, cc.ErrInvalid
	}
	if o.status.State != "observed" && o.status.State != "finalized" && time.Since(o.armedAt) >= 10*time.Second {
		o.fail("timeout")
	}
	if q != o.status.Query {
		o.fail("mismatch")
		return cc.Status{}, cc.ErrInvalid
	}
	return o.snapshot(), nil
}

// Finalize seals only the exact observed arm, atomically with all DATA hooks.
// The retained terminal snapshot and every returned snapshot are detached. Later
// traffic still follows normal authentication/admission but cannot change it.
func (o *ConsumerObservation) Finalize(q cc.Query) (cc.Status, error) {
	if pc.CurrentProfile() != pc.FullProfile || cc.ValidateArm(q) != nil {
		return cc.Status{}, cc.ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.status == nil {
		return cc.Status{}, cc.ErrInvalid
	}
	if q != o.status.Query {
		o.fail("mismatch")
		return cc.Status{}, cc.ErrInvalid
	}
	switch o.status.State {
	case "observed":
		if cc.ValidateStatus(*o.status) != nil {
			return cc.Status{}, cc.ErrInvalid
		}
		terminal := o.snapshot()
		terminal.State = "finalized"
		o.status = &terminal
		o.timer.Stop()
	case "finalized": // Exact retries are idempotent, never a second seal.
	default:
		return cc.Status{}, cc.ErrInvalid
	}
	return o.snapshot(), nil
}
func (o *ConsumerObservation) Close() { o.mu.Lock(); defer o.mu.Unlock(); o.fail("closed") }

// Context always attaches the fixed recorder for pre-arm live connections, but
// enables ciphertext hashing only for cross-E/wrong-Hello, never same-E auth.
func (o *ConsumerObservation) Context(ctx context.Context) context.Context {
	if ctx == nil || pc.CurrentProfile() != pc.FullProfile {
		return ctx
	}
	c := &consumerConnection{owner: o}
	o.mu.Lock()
	if o.status != nil && o.status.State != "observed" && o.status.State != "finalized" && time.Since(o.armedAt) >= 10*time.Second {
		o.fail("timeout")
	}
	if o.status != nil && (o.status.Query.CaseName == cc.CrossE || o.status.Query.CaseName == cc.SameEReconnect || cc.WrongHelloCase(o.status.Query.CaseName)) && o.status.State != "failed" && o.status.State != "finalized" {
		if o.selected != nil {
			o.fail("duplicate")
		} else {
			o.selected = c
			c.reconnectSelected = o.status.Query.CaseName == cc.SameEReconnect
			c.tlsSelected = !c.reconnectSelected
			o.status.SelectedCount = 1
			o.status.State = "claimed"
		}
	}
	o.mu.Unlock()
	ctx = context.WithValue(ctx, consumerKey{}, c)
	if c.tlsSelected {
		ctx = WithTLSFailureObservation(ctx)
	}
	return ctx
}
func consumerFrom(ctx context.Context) *consumerConnection {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(consumerKey{}).(*consumerConnection)
	return c
}

// Finish is called INSIDE the real Service.ServeData, before its listener can
// discard the return value. Arbitrary/transport errors never become evidence.
func (o *ConsumerObservation) Finish(ctx context.Context, err error) {
	c := consumerFrom(ctx)
	if c == nil || c.owner != o || (!c.tlsSelected && !c.reconnectSelected) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.status == nil || o.status.State == "failed" || o.status.State == "finalized" {
		return
	}
	if c.reconnectSelected {
		// Only authentication's actual result can populate this evidence. TLS,
		// wrong Hello, EOF and cancellation must never stand in for that call.
		if o.status.State != "observed" {
			o.fail("transport-or-unattributed")
		}
		return
	}
	q := o.status.Query
	var hello *a.DataHello
	e, ok := TLSFailureEvidence(err)
	if cc.WrongHelloCase(q.CaseName) {
		failure, attributed := err.(*helloFailureError)
		ok = attributed && failure != nil
		if ok {
			e = failure.snapshot
			h := failure.hello
			hello = &h
			ok = cc.WrongHelloMatches(q.CaseName, q.Original, h)
		}
	}
	if !ok {
		o.fail("transport-or-unattributed")
		return
	}
	leaf := hex.EncodeToString(e.RejectedCertificateSHA256[:])
	if string(e.Store) != q.WorkerScope.StoreUUID || string(e.ServiceEpoch) != q.WorkerScope.ServiceEpoch || leaf != q.OriginalLeafSHA256 {
		o.fail("mismatch")
		return
	}
	if time.Since(o.armedAt) >= 10*time.Second {
		o.fail("timeout")
		return
	}
	o.status.State = "observed"
	o.timer.Stop()
	o.status.Evidence = &cc.Evidence{Stage: "tls-client-certificate", ErrorClass: "unknown-authority", StoreUUID: string(e.Store), ServiceEpoch: string(e.ServiceEpoch), RejectedLeafSHA256: leaf, ByteCount: e.ByteCount, PrefixSHA256: hex.EncodeToString(e.PrefixSHA256[:])}
	if hello != nil {
		o.status.Evidence.Stage = "pki-verify-peer"
		o.status.Evidence.ErrorClass = "unauthorized"
		o.status.Evidence.Hello = hello
	}
}

// admission receives only values from the real authenticated peer and the exact
// per-request Authority.Admit invocation. It cannot affect that invocation.
func (c *consumerConnection) admission(h a.DataHello, leaf [32]byte, request w.Request, err error) {
	if c == nil {
		return
	}
	o := c.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.status == nil || (o.status.Query.CaseName != cc.SameE && o.status.Query.CaseName != cc.SameEFile) || o.status.State == "failed" || o.status.State == "finalized" {
		return
	}
	q := o.status.Query
	if string(h.Binding.Attachment) != q.Original.Binding.Attachment {
		return
	}
	if o.selected != nil {
		o.fail("duplicate")
		return
	}
	o.selected = c
	o.status.SelectedCount = 1
	o.status.State = "claimed"
	if c.established.IsZero() || !c.established.Before(o.armedAt) {
		o.fail("not-existing")
		return
	}
	actual := cc.OriginalFor(h)
	hash := hex.EncodeToString(leaf[:])
	if actual != q.Original || hash != q.OriginalLeafSHA256 || ((q.Version == cc.SameERootVersion || q.Version == cc.SameEFileVersion || q.Version == cc.SameEFileXattrVersion) && !cc.ExactOriginalHello(q.Original, h)) {
		o.fail("mismatch")
		return
	}
	if time.Since(o.armedAt) >= 10*time.Second {
		o.fail("timeout")
		return
	}
	if err != a.ErrBlocked || request.Sequence == 0 {
		o.fail("not-blocked")
		return
	}
	proof := &cc.Admission{Original: actual, RequestSequence: request.Sequence}
	if q.Version == cc.SameEFileVersion {
		// Observe only the real retained-handle WRITE operands. In particular,
		// caller-auth writes stay caller-auth; no open-grant provenance is invented.
		write, ok := request.Body.(w.WriteRequest)
		if !ok || request.Validate() != nil || write.Node == 0 || write.Handle == 0 || write.Offset != 0 || len(write.Data) != 1 || write.Data[0] != 0x5a {
			o.fail("mismatch")
			return
		}
		proof.Operation, proof.Node, proof.Handle = write.Operation(), write.Node, write.Handle
		proof.AuthKind, proof.WriteOneAtZero = request.Auth.Kind, true
	}
	if q.Version == cc.SameEFileXattrVersion {
		// Linux's real killpriv prelude can be denied before pwrite serializes
		// a WRITE. Record that exact request, never an invented WRITE operand.
		get, ok := request.Body.(w.GetXAttrRequest)
		if !ok || request.Validate() != nil || get.Node == 0 || string(get.Name) != cc.SameEFileCapability || request.Auth.Kind != w.CallerAuth {
			o.fail("mismatch")
			return
		}
		proof.Operation, proof.Node = get.Operation(), get.Node
		proof.AuthKind, proof.NoHandle, proof.CapabilityName = request.Auth.Kind, true, cc.SameEFileCapability
	}
	if q.Version == cc.SameERootVersion {
		// Bind the real decoded request to this connection's actual root grant,
		// not an arm-supplied opcode/node or a locally generated error.
		getattr, ok := request.Body.(w.GetAttrRequest)
		if !ok || c.rootNode == 0 || getattr.Node != c.rootNode || getattr.Handle != nil || request.Auth.Kind != w.NodeMetadataAuth || request.Auth.Caller != nil {
			o.fail("mismatch")
			return
		}
		proof.Operation, proof.Node = getattr.Operation(), getattr.Node
		proof.AuthKind, proof.NoHandle = request.Auth.Kind, true
	}
	o.status.State = "observed"
	o.timer.Stop()
	o.status.Evidence = &cc.Evidence{Stage: "request-admit", ErrorClass: "blocked", StoreUUID: string(h.Binding.Store), ServiceEpoch: string(h.Epoch), RejectedLeafSHA256: hash, Admission: proof}
}
