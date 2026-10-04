package storageclient

import (
	"context"
	"errors"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// OriginalConsumerFileRequest is an actual FIFO-assigned request, not proof of
// server admission. No credential, grant, or second connection is manufactured.
type OriginalConsumerFileRequest struct {
	Node            uint64 `json:"node"`
	Handle          uint64 `json:"handle"`
	RequestSequence uint64 `json:"requestSequence"`
}

type OriginalConsumerCapabilityRequest struct {
	Node            uint64 `json:"node"`
	RequestSequence uint64 `json:"requestSequence"`
}

type OriginalConsumerFileTrace struct {
	Capability *OriginalConsumerCapabilityRequest `json:"capability,omitempty"`
	Write      *OriginalConsumerFileRequest       `json:"write,omitempty"`
	Sync       *OriginalConsumerFileRequest       `json:"sync,omitempty"`
	WriteOK    bool                               `json:"writeOK"`
	SyncOK     bool                               `json:"syncOK"`
}

// One bounded record, retained even through terminal failure until End. All
// fields are guarded by Client.mu. Invalid observations never alter the RPC.
type originalConsumerFile struct {
	trace                                        OriginalConsumerFileTrace
	positive, invalid, writeDone, syncDone       bool
	capability, capabilityCalled, capabilityDone bool
	writeCalled, syncCalled                      bool
	calls                                        int
	// Exact remote terminal object retained only after the sequenced capability
	// request completed. Native mount propagation may join this failure, but
	// preclose or an independent abort must still invalidate the observation.
	terminal error
}

func (c *Client) originalConsumerFileAuthority(expected a.DataHello) bool {
	return preparecompat.CurrentProfile() == preparecompat.FullProfile && c.authority == expected &&
		expected.Binding.Role == a.RuntimeRole && expected.Binding.Mode == a.ReadWrite
}

// BeginOriginalConsumerFile passively brackets operations on the already-open
// original writable FD. The caller owns serialization of this observation scope.
// A terminal client cannot begin, including cross-epoch local-no-wire attempts.
func (c *Client) BeginOriginalConsumerFile(expected a.DataHello, positive bool) error {
	return c.beginOriginalConsumerFile(expected, positive, false)
}

// Separate versioned bracket: old WRITE-only witnesses cannot be reinterpreted.
func (c *Client) BeginOriginalConsumerCapabilityFile(expected a.DataHello) error {
	return c.beginOriginalConsumerFile(expected, false, true)
}

func (c *Client) beginOriginalConsumerFile(expected a.DataHello, positive, capability bool) error {
	if c == nil {
		return ErrProtocol
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.originalConsumerFileAuthority(expected) || c.err != nil || c.stopping || c.sealed || c.originalFile != nil || c.originalRead != nil || c.requests != 0 || c.outstanding != nil || len(c.queue) != 0 {
		return ErrProtocol
	}
	c.originalFile = &originalConsumerFile{positive: positive, capability: capability}
	return nil
}

// EndOriginalConsumerFile atomically detaches the observation after operation
// calls return. A failed attempt is only client evidence, NEVER authority denial.
// An early End fails without discarding the still-running record.
func (c *Client) EndOriginalConsumerFile(expected a.DataHello) (OriginalConsumerFileTrace, error) {
	if c == nil {
		return OriginalConsumerFileTrace{}, ErrProtocol
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.originalFile
	if !c.originalConsumerFileAuthority(expected) || p == nil || p.calls != 0 {
		return OriginalConsumerFileTrace{}, ErrProtocol
	}
	c.originalFile = nil
	if p.invalid || c.stopping || c.sealed {
		return OriginalConsumerFileTrace{}, ErrProtocol
	}
	if p.capability {
		if p.trace.Capability == nil || !p.capabilityDone || c.err == nil || p.trace.Write != nil || p.trace.Sync != nil || p.trace.WriteOK || p.trace.SyncOK {
			return OriginalConsumerFileTrace{}, ErrProtocol
		}
		return p.trace, nil
	}
	if p.trace.Capability != nil || p.trace.Write == nil || !p.writeDone || p.trace.Sync != nil && !p.syncDone {
		return OriginalConsumerFileTrace{}, ErrProtocol
	}
	if p.positive {
		if c.err != nil || !p.trace.WriteOK || p.trace.Sync == nil || !p.trace.SyncOK {
			return OriginalConsumerFileTrace{}, ErrProtocol
		}
	} else if p.trace.WriteOK || p.trace.SyncOK || p.trace.Sync == nil && c.err == nil {
		return OriginalConsumerFileTrace{}, ErrProtocol
	}
	return p.trace, nil
}

// Called with mu held. A terminal flag without the completed, actual wire
// request is insufficient. Close/Abort cannot manufacture this retained cause.
func (c *Client) completedCapabilityFailure() bool {
	p := c.originalFile
	return p != nil && p.capability && !p.invalid && p.capabilityDone &&
		p.trace.Capability != nil && p.terminal != nil && c.err == p.terminal
}

// Called with mu held only after actual sequence assignment in execute.
func (c *Client) observeOriginalFileRequest(req w.Request) {
	p := c.originalFile
	if p == nil {
		return
	}
	if p.capability {
		get, ok := req.Body.(w.GetXAttrRequest)
		if !ok || p.trace.Capability != nil || req.Validate() != nil || req.Auth.Kind != w.CallerAuth || get.Node == 0 || string(get.Name) != "security.capability" {
			p.invalid = true
			return
		}
		p.trace.Capability = &OriginalConsumerCapabilityRequest{uint64(get.Node), req.Sequence}
		return
	}
	switch b := req.Body.(type) {
	case w.WriteRequest:
		want := byte(0x5a)
		if p.positive {
			want = 0xa5
		}
		if p.trace.Write != nil || p.trace.Sync != nil || b.Offset != 0 || len(b.Data) != 1 || b.Data[0] != want {
			p.invalid = true
			return
		}
		p.trace.Write = &OriginalConsumerFileRequest{uint64(b.Node), uint64(b.Handle), req.Sequence}
	case w.FsyncRequest:
		v := p.trace.Write
		if v == nil || !p.writeDone || p.trace.Sync != nil || b.DataOnly || uint64(b.Node) != v.Node || uint64(b.Handle) != v.Handle || req.Sequence <= v.RequestSequence {
			p.invalid = true
			return
		}
		p.trace.Sync = &OriginalConsumerFileRequest{uint64(b.Node), uint64(b.Handle), req.Sequence}
	default:
		if req.Mutates() {
			p.invalid = true
		}
	}
}

// Called with mu held after apply and before publishing work.done.
func (c *Client) observeOriginalFileCompletion(req w.Request, reply w.Reply, err error) {
	p := c.originalFile
	if p == nil {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrProtocol) {
		p.invalid = true
	}
	if v := p.trace.Capability; v != nil && v.RequestSequence == req.Sequence {
		p.capabilityDone = true
		// Only actual transport loss is the local negative; an errno reply
		// or successful metadata response cannot stand in for blocked Admit.
		if err == nil {
			p.invalid = true
		} else if !p.invalid && c.err == err {
			p.terminal = err
		}
	}
	if v := p.trace.Write; v != nil && v.RequestSequence == req.Sequence {
		p.writeDone = true
		body, ok := reply.Body.(w.WriteReply)
		p.trace.WriteOK = err == nil && reply.Sequence == req.Sequence && reply.Op == w.OpWrite && reply.Errno == 0 && ok && body.Written == 1
		// A successful zero-byte write is not the required failed attempt.
		if err == nil && reply.Errno == 0 && !p.trace.WriteOK {
			p.invalid = true
		}
	}
	if v := p.trace.Sync; v != nil && v.RequestSequence == req.Sequence {
		p.syncDone = true
		_, ok := reply.Body.(w.FsyncReply)
		p.trace.SyncOK = err == nil && reply.Sequence == req.Sequence && reply.Op == w.OpFsync && reply.Errno == 0 && ok
	}
}
