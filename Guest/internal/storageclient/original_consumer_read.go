package storageclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// OriginalConsumerReadGrant is an opaque, owner-local reference to a successful
// real READ on an already-open mounted file. It exports neither credentials nor
// a constructor. Holding it does not keep a kernel FD alive: the sealed Session
// must retain that FD and its mount until observation and cleanup have joined.
// A retired source may retain this reference; it confers no authority on B.
type OriginalConsumerReadGrant struct {
	mu          sync.Mutex
	used        bool
	owner       *Client
	authority   a.DataHello
	root        w.NodeID
	node        w.NodeID
	handle      w.HandleID
	sequence    uint64
	size        uint32
	ioFlags     uint32
	digest      [32]byte
	nodeOwner   *nodeState
	handleOwner *handleState
}

// Preserve actual read-only flags (Linux adds O_LARGEFILE); never substitute
// flags0 for the authentic request or allow writable/create/direct semantics.
func originalReadFlags(flags uint32) bool {
	const mask = w.OpenNonblock | w.OpenLargeFile | w.OpenNoFollow | w.OpenNoATime | w.OpenCloseOnExec
	return flags & ^uint32(mask) == 0
}

type OriginalConsumerReadWitness struct {
	Authority       a.DataHello `json:"authority"`
	RootNode        uint64      `json:"rootNode"`
	Node            uint64      `json:"node"`
	Handle          uint64      `json:"handle"`
	RequestSequence uint64      `json:"requestSequence"`
	Size            uint32      `json:"size"`
	IOFlags         uint32      `json:"ioFlags"`
	ContentSHA256   string      `json:"contentSHA256"`
}

// Witness is an immutable projection, not a reference constructor or authority.
func (g *OriginalConsumerReadGrant) Witness(expected a.DataHello) (OriginalConsumerReadWitness, error) {
	if g == nil || g.owner == nil || g.authority != expected || !g.owner.originalReadAuthority(expected) || g.sequence == 0 {
		return OriginalConsumerReadWitness{}, ErrProtocol
	}
	return OriginalConsumerReadWitness{g.authority, uint64(g.root), uint64(g.node), uint64(g.handle), g.sequence, g.size, g.ioFlags, hex.EncodeToString(g.digest[:])}, nil
}

// OriginalReadFailure is finite diagnostic metadata, never a READ witness.
// Unwrap preserves the existing protocol-refusal classification.
type OriginalReadFailure uint8

const (
	OriginalReadUnjoined OriginalReadFailure = iota + 1
	OriginalReadClosed
	OriginalReadCacheOnly
	OriginalReadTraffic
	OriginalReadShape
	OriginalReadReply
	OriginalReadMissingGrant
	OriginalReadRepeated
	OriginalReadGetAttr
	OriginalReadReleaseDir
)

func (e OriginalReadFailure) Error() string { return "original READ observation rejected" }
func (e OriginalReadFailure) Unwrap() error { return ErrProtocol }

type originalConsumerRead struct {
	calls              int
	attempted, invalid bool
	grant              *OriginalConsumerReadGrant
	failure            OriginalReadFailure
	metadataCalled     bool
	metadata           *originalReadMetadata
}

type originalReadMetadata struct {
	node      w.NodeID
	handle    w.HandleID
	sequence  uint64
	nodeOwner *nodeState
}

func (p *originalConsumerRead) reject(reason OriginalReadFailure) {
	p.invalid = true
	if p.failure == 0 {
		p.failure = reason
	}
}

func (c *Client) originalReadAuthority(expected a.DataHello) bool {
	return preparecompat.CurrentProfile() == preparecompat.FullProfile && c.authority == expected && expected.Binding.Role == a.RuntimeRole
}

// Begin/End passively bracket ONE kernel-originated read after the original FD
// has been opened, including Linux's optional single same-file GETATTR prelude.
// Cache-only success, unrelated traffic, failed local admission, mutation, a
// second read, or a missing/failed reply cannot create a reference.
func (c *Client) BeginOriginalConsumerRead(expected a.DataHello) error {
	if c == nil {
		return ErrProtocol
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.originalReadAuthority(expected) || c.err != nil || c.stopping || c.sealed || c.originalRead != nil || c.originalFile != nil || c.requests != 0 || c.outstanding != nil || len(c.queue) != 0 {
		return ErrProtocol
	}
	c.originalRead = &originalConsumerRead{}
	return nil
}

func (c *Client) EndOriginalConsumerRead(expected a.DataHello) (*OriginalConsumerReadGrant, error) {
	if c == nil {
		return nil, ErrProtocol
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.originalRead
	if !c.originalReadAuthority(expected) || p == nil {
		return nil, ErrProtocol
	}
	if p.calls != 0 {
		return nil, OriginalReadUnjoined
	}
	c.originalRead = nil
	if c.err != nil || c.stopping || c.sealed {
		return nil, OriginalReadClosed
	}
	if p.invalid {
		if p.failure != 0 {
			return nil, p.failure
		}
		return nil, OriginalReadTraffic
	}
	if !p.attempted {
		return nil, OriginalReadCacheOnly
	}
	if p.grant == nil {
		return nil, OriginalReadMissingGrant
	}
	return p.grant, nil
}

// Called under Client.mu at actual FIFO completion, before publishing done.
func (c *Client) observeOriginalReadCompletion(req w.Request, reply w.Reply, err error) {
	p := c.originalRead
	if p == nil {
		return
	}
	if b, ok := req.Body.(w.GetAttrRequest); ok {
		r, attrOK := reply.Body.(w.GetAttrReply)
		n := c.wireNodes[b.Node]
		if !attrOK || err != nil || p.attempted || p.metadata != nil || reply.Errno != 0 || reply.Sequence != req.Sequence || reply.Op != w.OpGetAttr || n == nil || r.Attr.Ino != n.entry.Attr.Ino || r.Attr.Mode&0170000 != 0100000 || r.Attr.Size != 32 {
			p.reject(OriginalReadGetAttr)
			return
		}
		var handle w.HandleID
		if b.Handle != nil {
			handle = *b.Handle
		}
		p.metadata = &originalReadMetadata{b.Node, handle, req.Sequence, n}
		return
	}
	b, ok := req.Body.(w.ReadRequest)
	r, readOK := reply.Body.(w.ReadReply)
	if !ok || !readOK || err != nil || p.grant != nil || b.Offset != 0 || b.Size == 0 || b.Size > 4096 || !originalReadFlags(b.IOFlags) || len(r.Data) != 32 || reply.Errno != 0 || reply.Sequence != req.Sequence || reply.Op != w.OpRead {
		p.reject(OriginalReadReply)
		return
	}
	if m := p.metadata; m != nil && (m.node != b.Node || m.handle != 0 && m.handle != b.Handle || m.sequence+1 != req.Sequence || m.nodeOwner != c.wireNodes[b.Node]) {
		p.reject(OriginalReadGetAttr)
		return
	}
	p.grant = &OriginalConsumerReadGrant{owner: c, authority: c.authority, root: c.root.Node, node: b.Node, handle: b.Handle, sequence: req.Sequence, size: b.Size, ioFlags: b.IOFlags, digest: sha256.Sum256(r.Data), nodeOwner: c.wireNodes[b.Node], handleOwner: c.wireHandles[b.Handle]}
}

// OriginalConsumerRootReplay describes only successful, actual B RPCs. It is NOT
// retirement/admission evidence, an unchanged-disk proof or native acceptance.
type OriginalConsumerRootReplay struct {
	Source        a.DataHello `json:"source"`
	Target        a.DataHello `json:"target"`
	RootNode      uint64      `json:"rootNode"`
	RootSequence  uint64      `json:"rootSequence"`
	Node          uint64      `json:"node"`
	Handle        uint64      `json:"handle"`
	ReadSequence  uint64      `json:"readSequence"`
	ContentSHA256 string      `json:"contentSHA256"`
}

// ReplayOriginalConsumerRead reuses actual A root/object numbers via B's EXISTING
// client and B's own grant provenance. Equal integers are legitimate local B
// grants, not a denial: require B's independently captured content, distinct from
// A's. Ordinary Do retains all node/handle/authority checks. Noncoincident local
// grants fail closed here and are NOT relabeled remote denial or accepted proof.
// The owner must independently establish actual mounts, retirement (when needed),
// exclusive objects, backing stability and retained FD lifetime before selecting
// either root case. This primitive alone deliberately enables no selector.
func (c *Client) ReplayOriginalConsumerRead(ctx context.Context, expected a.DataHello, source, target *OriginalConsumerReadGrant) (evidence OriginalConsumerRootReplay, err error) {
	if c == nil || ctx == nil || source == nil || target == nil || source == target {
		return evidence, ErrProtocol
	}
	if !target.mu.TryLock() {
		return evidence, ErrProtocol
	}
	defer target.mu.Unlock()
	if target.used {
		return evidence, ErrProtocol
	}
	target.used = true // failures are one-shot too; no automatic retries
	if !c.originalReadAuthority(expected) || target.owner != c || target.authority != expected || source.owner == nil || source.owner == c || source.authority.Epoch != expected.Epoch || source.authority.Binding.Store != expected.Binding.Store || source.authority.Binding.Container != expected.Binding.Container || source.authority.Binding.Launch != expected.Binding.Launch || source.authority.Binding.Role != a.RuntimeRole || source.authority.Binding.Volume == expected.Binding.Volume || source.authority.Binding.Attachment == expected.Binding.Attachment || source.authority.Binding.Key == expected.Binding.Key || source.sequence == 0 || target.sequence == 0 || source.digest == target.digest || source.root == 0 || source.node == 0 || source.handle == 0 || target.size == 0 || target.size > 4096 || source.size != target.size || source.ioFlags != target.ioFlags {
		return evidence, ErrProtocol
	}
	c.mu.Lock()
	live := c.err == nil && !c.stopping && !c.sealed && c.originalRead == nil && c.originalFile == nil && c.requests == 0 && c.outstanding == nil && len(c.queue) == 0 && target.nodeOwner != nil && target.handleOwner != nil && c.wireNodes[target.node] == target.nodeOwner && c.wireHandles[target.handle] == target.handleOwner && !target.handleOwner.releasing
	c.mu.Unlock()
	if !live {
		return evidence, ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return evidence, err
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.fail(ctx.Err()); close(canceled) })
	defer func() {
		if !stop() {
			<-canceled
			<-c.joined
			evidence, err = OriginalConsumerRootReplay{}, ctx.Err()
		}
	}()
	var rootSequence, readSequence uint64
	root, err := c.do(Snapshot{owner: c, valid: true}, w.NodeMetadataAuth, w.GetAttrRequest{Node: source.root}, &rootSequence)
	if err != nil {
		return evidence, err
	}
	attr, ok := root.Reply.Body.(w.GetAttrReply)
	if !ok || root.Reply.Errno != 0 || rootSequence != target.sequence+1 || attr.Attr.Ino != c.root.Attr.Ino || attr.Attr.Mode&0170000 != 0040000 || source.root != target.root {
		return evidence, ErrProtocol
	}
	read, err := c.do(Snapshot{owner: c, valid: true}, w.OpenGrantAuth, w.ReadRequest{Node: source.node, Handle: source.handle, Offset: 0, Size: target.size, IOFlags: target.ioFlags}, &readSequence)
	if err != nil {
		return evidence, err
	}
	body, ok := read.Reply.Body.(w.ReadReply)
	if !ok || read.Reply.Errno != 0 || readSequence != rootSequence+1 || len(body.Data) != 32 || sha256.Sum256(body.Data) != target.digest || source.node != target.node || source.handle != target.handle || c.Err() != nil {
		return evidence, ErrProtocol
	}
	c.mu.Lock()
	unchanged := c.err == nil && c.wireNodes[target.node] == target.nodeOwner && c.wireHandles[target.handle] == target.handleOwner && !target.handleOwner.releasing && c.sequence == readSequence
	c.mu.Unlock()
	if !unchanged {
		return evidence, ErrProtocol
	}
	return OriginalConsumerRootReplay{Source: source.authority, Target: expected, RootNode: uint64(source.root), RootSequence: rootSequence, Node: uint64(source.node), Handle: uint64(source.handle), ReadSequence: readSequence, ContentSHA256: hex.EncodeToString(target.digest[:])}, nil
}
