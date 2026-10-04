package storageclient

import (
	"crypto/sha256"
	"encoding/json"
	"errors"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// This is completion evidence, never authority or permission to retry. Only an
// already-BOUND provision replay has an unchanged intent across its exact replay.
// Other replay phases and EBUSY replies retain the ordinary failure policy.
// One context per client; query digests are bounded by the existing Requests limit.
type prepareReadDirRetry struct {
	intent       a.CopyIntent
	node         w.NodeID
	handle       w.HandleID
	bound, ready bool
	queries      map[[sha256.Size]byte]struct{}
}

var errPrepareReadDirRetry = errors.New("unresolved PREPARE directory replay retry")

func (c *Client) prepareRootHandle(node w.NodeID, handle w.HandleID) bool {
	h := c.wireHandles[handle]
	// Do already validated admission. A later queued RELEASEDIR marks releasing
	// before this reply is applied, but cannot revoke this earlier accepted read.
	// The wire grant remains present until its ordered release reply is applied.
	return c.authority.Binding.Role == a.PrepareRole && c.authority.Binding.Mode == a.ReadWrite &&
		node == c.root.Node && h != nil && h.directory && h.node.entry.Node == node && h.node.local == 1
}

func (c *Client) failPrepareReadDirRetry(cause error) {
	if c.completionErr == nil {
		c.completionErr = errors.Join(ErrIncomplete, errPrepareReadDirRetry, cause)
	}
}

// Called only after wire/request and authenticated PREPARE scope validation.
// Every transition is correlated to the full immutable intent and root grant.
func (c *Client) observePrepareReadDirReplay(req w.PrepareRequest, reply w.PrepareReply) {
	p := c.prepareReadDir
	exact := p != nil && c.prepareRootHandle(req.Node, req.Handle) && req.Node == p.node && req.Handle == p.handle &&
		reply.Intent == p.intent && reply.Root == p.intent.Root
	pending := req.Action == w.BeginCopy && reply.Pending == w.BindCopyTransaction &&
		reply.Intent.Phase == a.CopyBound && reply.Intent.InitialCaptured && c.prepareRootHandle(req.Node, req.Handle)
	if p == nil || len(p.queries) == 0 {
		// No rejected read is being discharged. Start tracking only this precisely
		// known pending replay; an observation alone does not obligate a retry.
		if pending {
			c.prepareReadDir = &prepareReadDirRetry{intent: reply.Intent, node: req.Node, handle: req.Handle}
		} else {
			c.prepareReadDir = nil
		}
		return
	}
	switch req.Action {
	case w.BeginCopy:
		if exact && pending {
			// Repeated pending observations must not discard outstanding queries or
			// reuse a prior successful Bind as evidence for this pending state.
			p.bound, p.ready = false, false
		} else if exact && reply.Pending == 0 && p.bound {
			p.ready = true
		} else {
			c.failPrepareReadDirRetry(nil)
		}
	case w.BindCopyTransaction:
		if exact && req.Intent == p.intent.ID && reply.Pending == 0 && reply.Identity == p.intent.Transaction {
			p.bound, p.ready = true, false
		} else {
			c.failPrepareReadDirRetry(nil)
		}
	}
}

// True means only that this exact completed rejection is accounted for by a
// bounded unresolved retry obligation. It does NOT change the errno, execute a
// retry, release a grant, clear another error, or claim remote drain/durability.
func (c *Client) recordPrepareReadDirRetry(req w.Request, reply w.Reply) bool {
	if control, ok := req.Body.(w.PrepareRequest); ok && reply.Errno == 0 {
		if result, ok := reply.Body.(w.PrepareReply); ok {
			c.observePrepareReadDirReplay(control, result)
		}
	}
	query, ok := req.Body.(w.ReadDirRequest)
	p := c.prepareReadDir
	if !ok || p == nil || query.Node != p.node || query.Handle != p.handle || !c.prepareRootHandle(query.Node, query.Handle) {
		return false
	}
	// Include every query field and the complete validated caller/provenance;
	// exclude only RPC sequence. Hashing bounds memory without retaining groups.
	encoded, err := json.Marshal(struct {
		Query w.ReadDirRequest
		Auth  w.Auth
	}{query, req.Auth})
	if err != nil {
		return false
	}
	key := sha256.Sum256(encoded)
	if reply.Errno == 16 && !p.bound && !p.ready { // Linux EBUSY, before ordinary DATA dispatch
		if _, exists := p.queries[key]; exists {
			return true
		}
		if len(p.queries) >= c.limits.Requests {
			c.failPrepareReadDirRetry(ErrCapacity)
			return true
		}
		if p.queries == nil {
			p.queries = make(map[[sha256.Size]byte]struct{})
		}
		p.queries[key] = struct{}{}
		return true
	}
	if reply.Errno == 0 && len(p.queries) == 0 {
		c.prepareReadDir = nil
	} else if reply.Errno == 0 {
		if !p.ready {
			c.failPrepareReadDirRetry(nil)
		} else if _, exists := p.queries[key]; exists {
			delete(p.queries, key)
			if len(p.queries) == 0 {
				c.prepareReadDir = nil
			}
		}
	}
	return false
}
