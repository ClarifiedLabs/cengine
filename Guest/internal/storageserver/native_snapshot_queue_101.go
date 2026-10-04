//go:build cengine_native_faulttest

package storageserver

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"sync"
)

// NativeSnapshot101Queue is a finite scheduling cut in the existing native-only
// fixture. It parks only the exact admitted Rename(p0,moved) / Unlink(p1), before
// dispatch. It never creates/releases guards, substitutes execution, or changes
// authentication. Other operations (including prerequisite GetAttr) run normally.
type NativeSnapshot101Queue struct {
	mu       sync.Mutex
	server   *Server
	epoch    a.ID
	targets  [2]a.Binding
	armed    bool
	captured [2]bool
	held     [2]bool
	guards   [2]*a.Guard
	evidence [2]NativeSnapshot101Wait
	release  [2]chan struct{}
	once     [2]sync.Once
	admitted chan NativeSnapshot101Wait
	waiting  chan NativeSnapshot101Wait
	waited   [2]bool
}
type NativeSnapshot101QueueState struct {
	Epoch                        a.ID
	Targets                      [2]a.Binding
	Held                         [2]bool
	Sequences                    [2]uint64
	ReceiveUsed, ReceiveCapacity int
}

func (s *Server) InstallNativeSnapshot101Queue(epoch a.ID, targets [2]a.Binding) (*NativeSnapshot101Queue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch == "" || s.serveStarted || (s.authority != nil && s.pki == nil) || s.copyHooks != nil || len(s.connections) != 0 || targets[0].Attachment == targets[1].Attachment {
		return nil, ErrConfiguration
	}
	if s.pki != nil && (epoch != s.pki.ServiceEpoch || targets[0].Store != s.pki.Store) {
		return nil, ErrConfiguration
	}
	for _, b := range targets {
		if b.Role != a.RuntimeRole || b.Mode != a.ReadWrite || b.Store == "" || b.Volume == "" || b.Attachment == "" || b.Store != targets[0].Store || b.Volume != targets[0].Volume {
			return nil, ErrConfiguration
		}
	}
	q := &NativeSnapshot101Queue{server: s, epoch: epoch, targets: targets, admitted: make(chan NativeSnapshot101Wait, 2), waiting: make(chan NativeSnapshot101Wait, 2)}
	for i := range q.release {
		q.release[i] = make(chan struct{})
	}
	s.copyHooks = &copyFenceHooks{admitted: q.admit, waiting: q.wait}
	return q, nil
}
func (q *NativeSnapshot101Queue) Arm() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.armed {
		return ErrConfiguration
	}
	q.armed = true
	return nil
}
func (q *NativeSnapshot101Queue) Admissions() <-chan NativeSnapshot101Wait { return q.admitted }
func (q *NativeSnapshot101Queue) Waits() <-chan NativeSnapshot101Wait      { return q.waiting }
func (q *NativeSnapshot101Queue) Release(index int) error {
	if index < 0 || index > 1 {
		return ErrConfiguration
	}
	q.once[index].Do(func() { close(q.release[index]) })
	return nil
}
func (q *NativeSnapshot101Queue) State() NativeSnapshot101QueueState {
	q.mu.Lock()
	defer q.mu.Unlock()
	state := NativeSnapshot101QueueState{Epoch: q.epoch, Targets: q.targets, Held: q.held, ReceiveUsed: len(q.server.receive), ReceiveCapacity: cap(q.server.receive)}
	for i := range q.evidence {
		state.Sequences[i] = q.evidence[i].Sequence
	}
	return state
}
func (q *NativeSnapshot101Queue) admit(b a.Binding, g *a.Guard, r w.Request) {
	q.mu.Lock()
	index := -1
	if q.armed {
		for i := range q.targets {
			if b != q.targets[i] || q.captured[i] {
				continue
			}
			match := false
			switch v := r.Body.(type) {
			case w.RenameRequest:
				match = i == 0 && string(v.OldName) == "p0" && string(v.NewName) == "moved" && v.Flags == 0
			case w.UnlinkRequest:
				match = i == 1 && string(v.Name) == "p1"
			}
			if match {
				index = i
				q.captured[i] = true
				q.held[i] = true
				q.guards[i] = g
				q.evidence[i] = NativeSnapshot101Wait{Binding: b, Sequence: r.Sequence, Operation: r.Body.Operation()}
				q.admitted <- q.evidence[i]
				break
			}
		}
	}
	q.mu.Unlock()
	if index < 0 {
		return
	}
	// No server dispatch/authority/observer lock is held while parked. Cancellation
	// is deliberately not a release: retirement must remain unable to claim drain.
	<-q.release[index]
	q.mu.Lock()
	q.held[index] = false
	q.mu.Unlock()
}
func (q *NativeSnapshot101Queue) wait(g *a.Guard) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.guards {
		if q.guards[i] == g && !q.waited[i] {
			q.waited[i] = true
			q.guards[i] = nil
			q.waiting <- q.evidence[i]
		}
	}
}
