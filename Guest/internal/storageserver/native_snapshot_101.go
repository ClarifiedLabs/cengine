//go:build cengine_native_faulttest

package storageserver

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"sync"
)

// NativeSnapshot101Wait is observation only: never exposes or releases a guard.
// Built solely into the existing signed native-fixture profile.
type NativeSnapshot101Wait struct {
	Binding    a.Binding
	Sequence   uint64
	Operation  w.Operation
	WriteFlags uint32
	Node       w.NodeID
	Handle     w.HandleID
	// Closed prerequisite label: never retain arbitrary names or xattr values.
	XattrName string
}

type NativeSnapshot101Observer struct {
	mu         sync.Mutex
	targets    [2]a.Binding
	operations [2]w.Operation
	armed      bool
	seen       [2]bool
	guards     [2][4]*a.Guard
	evidence   [2][4]NativeSnapshot101Wait
	next       [2]int
	waits      chan NativeSnapshot101Wait
	writes     chan NativeSnapshot101Wait
	wrote      [2]bool
	fenced     [2]NativeSnapshot101Wait
	positive   [2]NativeSnapshot101Wait
	reads      chan NativeSnapshot101Wait
	read       [2]bool
}

// InstallNativeSnapshot101 must run before the first Serve. Only two immutable
// runtime bindings on one volume; no executor, authority, error or scheduling hook.
func (s *Server) InstallNativeSnapshot101(targets [2]a.Binding) (*NativeSnapshot101Observer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// PKI construction binds the owned authority before Serve. A generic server
	// with a bound authority is not an eligible construction-time owner.
	if s.serveStarted || (s.authority != nil && s.pki == nil) || s.copyHooks != nil || len(s.connections) != 0 || targets[0].Attachment == targets[1].Attachment {
		return nil, ErrConfiguration
	}
	if s.pki != nil && targets[0].Store != s.pki.Store {
		return nil, ErrConfiguration
	}
	for _, b := range targets {
		if b.Role != a.RuntimeRole || b.Mode != a.ReadWrite || b.Store == "" || b.Volume == "" || b.Attachment == "" || b.Store != targets[0].Store || b.Volume != targets[0].Volume {
			return nil, ErrConfiguration
		}
	}
	o := &NativeSnapshot101Observer{targets: targets, waits: make(chan NativeSnapshot101Wait, 2), writes: make(chan NativeSnapshot101Wait, 2), reads: make(chan NativeSnapshot101Wait, 2)}
	s.copyHooks = &copyFenceHooks{admitted: o.admitted, waiting: o.waiting}
	return o, nil
}
func (o *NativeSnapshot101Observer) Arm(operations [2]w.Operation) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed {
		return ErrConfiguration
	}
	for _, op := range operations {
		if op != w.OpWrite && op != w.OpRead && op != w.OpReadDir {
			return ErrConfiguration
		}
	}
	o.operations = operations
	o.armed = true
	return nil
}
func (o *NativeSnapshot101Observer) Waits() <-chan NativeSnapshot101Wait { return o.waits }

func (o *NativeSnapshot101Observer) Writes() <-chan NativeSnapshot101Wait { return o.writes }

// PositiveReads snapshots the last pre-arm actual READ/READDIR on each binding.
// The isolated consumers complete those operations before the fixture arms.
func (o *NativeSnapshot101Observer) PositiveReads() [2]NativeSnapshot101Wait {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.positive
}
func (o *NativeSnapshot101Observer) Reads() <-chan NativeSnapshot101Wait { return o.reads }

func snapshot101ReadView(b a.Binding, r w.Request) NativeSnapshot101Wait {
	e := NativeSnapshot101Wait{Binding: b, Sequence: r.Sequence, Operation: r.Body.Operation()}
	switch v := r.Body.(type) {
	case w.GetAttrRequest:
		e.Node = v.Node
		if v.Handle != nil {
			e.Handle = *v.Handle
		}
	case w.ReadRequest:
		e.Node, e.Handle = v.Node, v.Handle
	case w.ReadDirRequest:
		e.Node, e.Handle = v.Node, v.Handle
	}
	return e
}

// At most three requests per peer can be outstanding here: executing, jobs[1],
// and readLoop's blocked sender. Four recent slots retain every possibly waiting
// guard without retaining unbounded completed pre-Begin requests.
// Include all mismatches. Later READ/WRITE observations are admission evidence,
// not held-fence evidence; no guard or dispatch behavior changes.
func (o *NativeSnapshot101Observer) admitted(b a.Binding, g *a.Guard, r w.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	event := snapshot101ReadView(b, r)
	if !o.armed {
		for i := range o.targets {
			if b == o.targets[i] && (event.Operation == w.OpRead || event.Operation == w.OpReadDir) {
				o.positive[i] = event
			}
		}
		return
	}
	for i := range o.targets {
		first, positive := o.fenced[i], o.positive[i]
		if b == o.targets[i] && o.seen[i] && !o.read[i] && o.operations[i] == w.OpRead &&
			positive.Operation == w.OpRead && positive.Node != 0 && positive.Handle != 0 &&
			first.Operation == w.OpGetAttr && first.Node == positive.Node && first.Handle == positive.Handle && first.Sequence > positive.Sequence &&
			event.Operation == w.OpRead && event.Node == first.Node && event.Handle == first.Handle && event.Sequence > first.Sequence {
			o.read[i] = true
			o.reads <- event
		}
		if b == o.targets[i] && o.seen[i] && !o.wrote[i] && o.fenced[i].Operation == w.OpGetXAttr && o.fenced[i].XattrName == "security.capability" && r.Sequence > o.fenced[i].Sequence {
			if write, ok := r.Body.(w.WriteRequest); ok {
				o.wrote[i] = true
				o.writes <- NativeSnapshot101Wait{Binding: b, Sequence: r.Sequence, Operation: w.OpWrite, WriteFlags: write.WriteFlags}
			}
		}
		if !o.seen[i] && b == o.targets[i] {
			j := o.next[i] % 4
			o.next[i]++
			o.guards[i][j] = g
			o.evidence[i][j] = event
			if write, ok := r.Body.(w.WriteRequest); ok {
				o.evidence[i][j].WriteFlags = write.WriteFlags
			}
			if get, ok := r.Body.(w.GetXAttrRequest); ok {
				o.evidence[i][j].XattrName = "other"
				if string(get.Name) == "security.capability" {
					o.evidence[i][j].XattrName = "security.capability"
				}
			}
		}
	}
}
func (o *NativeSnapshot101Observer) waiting(g *a.Guard) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.targets {
		for j := range o.guards[i] {
			if o.guards[i][j] == g && !o.seen[i] {
				o.seen[i] = true
				o.fenced[i] = o.evidence[i][j]
				o.guards[i] = [4]*a.Guard{}
				o.waits <- o.evidence[i][j]
			}
		}
	}
}
