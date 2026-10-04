package storageclient

import (
	"fmt"
	"math"
	"reflect"

	w "dev.cengine/guest/internal/storagewire"
)

// LocalNode/LocalHandle are monotonically allocated adapter IDs. LocalNode 1 is
// the lifetime-pinned mount root. Neither type is a server or Linux inode number.
type LocalNode uint64
type LocalHandle uint64

type nodeState struct {
	local       LocalNode
	entry       w.Entry
	refs, owned uint64 // kernel lookup refs; server refs awaiting FORGET ack
	pinned      bool
	handles     int
	pending     *work // latest queued cell; coalesce only at the FIFO tail
}
type handleState struct {
	local                LocalHandle
	wire                 w.HandleID
	node                 *nodeState
	flags                uint32
	directory, releasing bool
}

// HandleGrant never contains opener credentials. Its access/kind cannot upgrade.
type HandleGrant struct {
	Handle    w.HandleID
	Node      w.NodeID
	Flags     uint32
	Directory bool
}
type Notification struct {
	Event          w.Event
	Nodes, Parents []LocalNode
}

func (c *Client) Node(id LocalNode) (w.Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return w.Entry{}, c.err
	}
	n := c.nodes[id]
	if n == nil || !n.pinned && n.refs == 0 && n.handles == 0 {
		return w.Entry{}, ErrGrant
	}
	return n.entry, nil
}
func (c *Client) Handle(id LocalHandle) (HandleGrant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return HandleGrant{}, c.err
	}
	h := c.handles[id]
	if h == nil || h.releasing {
		return HandleGrant{}, ErrGrant
	}
	return HandleGrant{h.wire, h.node.entry.Node, h.flags, h.directory}, nil
}
func (c *Client) notification(e w.Event) Notification {
	out := Notification{Event: e, Nodes: []LocalNode{}, Parents: []LocalNode{}}
	for id, n := range c.nodes {
		if !n.pinned && n.refs == 0 && n.handles == 0 {
			continue
		}
		if n.entry.Object == e.Object {
			out.Nodes = append(out.Nodes, id)
		}
		if n.entry.Object == e.Parent {
			out.Parents = append(out.Parents, id)
		}
	}
	return out
}

// Forget is the no-reply FUSE callback path: bounded local bookkeeping only, no
// ioctl, socket I/O, waiting for queue capacity, or dropping counts. Capacity for
// its cells is reserved by each node grant, independent of the ordinary queue.
// The worker serializes and acknowledges cleanup outside this callback. Count
// underflow/overflow or an unknown ID terminates the exact session.
func (c *Client) Forget(id LocalNode, count uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.admissionLocked(); err != nil {
		return err
	}
	n := c.nodes[id]
	if n == nil || count == 0 || count > n.refs {
		c.failLocked(ErrProtocol)
		return c.err
	}
	n.refs -= count
	if n.pending != nil && len(c.queue) > 0 && c.queue[len(c.queue)-1] == n.pending {
		body := n.pending.req.Body.(w.ForgetRequest)
		if math.MaxUint64-body.Entries[0].Count < count {
			c.failLocked(ErrProtocol)
			return c.err
		}
		body.Entries[0].Count += count
	} else {
		j := &work{cleanup: true, forget: n, req: w.Request{Sequence: 1, Auth: w.Auth{Kind: w.LifecycleAuth}, Body: w.ForgetRequest{Entries: []w.ForgetEntry{{Node: n.entry.Node, Count: count}}}}}
		n.pending = j
		c.queue = append(c.queue, j)
		c.broadcastLocked()
		c.signal()
	}
	return nil
}

func grantCapacity(op w.Operation) (bool, bool) {
	switch op {
	case w.OpCreate:
		return true, true
	case w.OpLookup, w.OpMkdir, w.OpMknod, w.OpSymlink, w.OpLink:
		return true, false
	case w.OpOpen, w.OpOpenDir:
		return false, true
	}
	return false, false
}

// The wire validator has already enforced the closed concrete body whitelist.
func operands(body w.RequestBody) (w.NodeID, w.HandleID) {
	var node w.NodeID
	var handle w.HandleID
	v := reflect.ValueOf(body)
	for i := 0; i < v.NumField(); i++ {
		switch x := v.Field(i).Interface().(type) {
		case w.NodeID:
			if v.Type().Field(i).Name == "Node" {
				node = x
			}
		case w.HandleID:
			handle = x
		case *w.HandleID:
			if x != nil {
				handle = *x
			}
		}
	}
	return node, handle
}
func (c *Client) checkRequest(req w.Request) error {
	node, handle := operands(req.Body)
	if req.Body.Operation() == w.OpPrepare {
		root := c.nodes[1]
		if root == nil || !root.pinned || root.entry.Node != node || root.entry.Attr.Mode&0170000 != 0040000 {
			return ErrGrant
		}
	}
	if handle != 0 {
		h := c.wireHandles[handle]
		if h == nil || h.releasing || h.node.entry.Node != node {
			return ErrGrant
		}
		op := req.Body.Operation()
		directory := op == w.OpReadDir || op == w.OpFsyncDir || op == w.OpReleaseDir || op == w.OpPrepare
		file := op == w.OpRead || op == w.OpWrite || op == w.OpFlush || op == w.OpFsync || op == w.OpRelease || op == w.OpFallocate || op == w.OpLseek
		if directory && !h.directory || file && h.directory {
			return ErrGrant
		}
		access := h.flags & w.OpenAccessMask
		if op == w.OpRead && access == w.OpenWriteOnly || (op == w.OpWrite || op == w.OpFallocate) && access == w.OpenReadOnly {
			return ErrGrant
		}
	}
	v := reflect.ValueOf(req.Body)
	for i := 0; i < v.NumField(); i++ {
		if id, ok := v.Field(i).Interface().(w.NodeID); ok {
			n := c.wireNodes[id]
			if n == nil || !n.pinned && n.refs == 0 && (handle == 0 || n.handles == 0) {
				return ErrGrant
			}
			if req.Auth.Kind == w.NodeMetadataAuth && !n.pinned && n.refs == 0 {
				return ErrGrant
			}
		}
	}
	return nil
}
func (c *Client) collect(n *nodeState) {
	if !n.pinned && n.refs == 0 && n.owned == 0 && n.handles == 0 {
		delete(c.nodes, n.local)
		delete(c.wireNodes, n.entry.Node)
	}
}
func (c *Client) onEntry(e w.Entry) (LocalNode, error) {
	n := c.wireNodes[e.Node]
	if n != nil {
		if n.entry.Generation != e.Generation || n.entry.Object != e.Object || n.entry.Attr.Ino != e.Attr.Ino || n.entry.Attr.Mode&0170000 != e.Attr.Mode&0170000 || n.refs == math.MaxUint64 || n.owned == math.MaxUint64 {
			return 0, ErrProtocol
		}
	} else {
		if len(c.nodes) >= c.limits.Nodes || c.nextNode == math.MaxUint64 {
			return 0, ErrProtocol
		}
		c.nextNode++
		n = &nodeState{local: LocalNode(c.nextNode), entry: e}
		c.nodes[n.local], c.wireNodes[e.Node] = n, n
	}
	n.entry = e
	n.refs++
	n.owned++
	c.pins++
	return n.local, nil
}
func (c *Client) onOpen(node w.NodeID, opened w.Opened, flags uint32, directory bool) (LocalHandle, error) {
	n := c.wireNodes[node]
	if n == nil || c.wireHandles[opened.Handle] != nil || len(c.handles) >= c.limits.Handles || c.nextHandle == math.MaxUint64 {
		return 0, ErrProtocol
	}
	if directory != (n.entry.Attr.Mode&0170000 == 0040000) {
		return 0, ErrProtocol
	}
	c.nextHandle++
	h := &handleState{local: LocalHandle(c.nextHandle), wire: opened.Handle, node: n, flags: flags, directory: directory}
	c.handles[h.local], c.wireHandles[h.wire] = h, h
	n.handles++
	return h.local, nil
}
func (c *Client) apply(j *work, out *Result) error {
	if v, ok := out.Reply.Body.(w.PrepareReply); ok {
		if err := c.checkPrepareReply(v); err != nil {
			return err
		}
	}
	c.recordCompletedOutcome(j.req, out.Reply)
	if out.Reply.Errno != 0 {
		if j.cleanup {
			return fmt.Errorf("%w: cleanup errno %d", ErrProtocol, out.Reply.Errno)
		}
		return nil
	}
	var entry *w.Entry
	switch v := out.Reply.Body.(type) {
	case w.LookupReply:
		entry = &v.Entry
	case w.CreateReply:
		entry = &v.Entry
	case w.MkdirReply:
		entry = &v.Entry
	case w.MknodReply:
		entry = &v.Entry
	case w.SymlinkReply:
		entry = &v.Entry
	case w.LinkReply:
		entry = &v.Entry
	}
	var err error
	if entry != nil {
		out.Node, err = c.onEntry(*entry)
		if err != nil {
			return err
		}
	}
	switch v := j.req.Body.(type) {
	case w.CreateRequest:
		out.Handle, err = c.onOpen(entry.Node, out.Reply.Body.(w.CreateReply).Opened, v.Flags, false)
	case w.OpenRequest:
		out.Handle, err = c.onOpen(v.Node, out.Reply.Body.(w.OpenReply).Opened, v.Flags, false)
	case w.OpenDirRequest:
		out.Handle, err = c.onOpen(v.Node, out.Reply.Body.(w.OpenDirReply).Opened, v.Flags, true)
	case w.ReleaseRequest:
		err = c.release(v.Handle)
	case w.ReleaseDirRequest:
		err = c.release(v.Handle)
	case w.ForgetRequest:
		for _, e := range v.Entries {
			n := c.wireNodes[e.Node]
			if n == nil || n.owned < e.Count {
				return ErrProtocol
			}
			n.owned -= e.Count
			if c.pins <= e.Count {
				return ErrProtocol
			}
			c.pins -= e.Count
			c.collect(n)
		}
	}
	return err
}
func (c *Client) release(id w.HandleID) error {
	h := c.wireHandles[id]
	if h == nil || !h.releasing {
		return ErrProtocol
	}
	delete(c.handles, h.local)
	delete(c.wireHandles, id)
	h.node.handles--
	c.collect(h.node)
	return nil
}
