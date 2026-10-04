package storageserver

import (
	"os"
	"sync"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageidentity"
	m "dev.cengine/guest/internal/storagemanaged"
)

// Resources owns the namespace, identity worker, and attachment registry before
// authority creates E. It must not be copied. Exactly one Server may consume it.
// No network or TLS policy exists at this construction stage.
type Resources struct {
	mu       sync.Mutex
	claimed  bool
	gate     sync.Mutex
	worker   storageidentity.Worker
	registry *m.Registry
	live     map[a.ID]bool
}

// Idle is resource accounting only, never a durable drain receipt.
func (r *Resources) Idle() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registry != nil && len(r.live) == 0
}

func NewResources() (*Resources, error) {
	r := &Resources{live: make(map[a.ID]bool)}
	var err error
	r.registry, err = m.NewRegistry(&r.gate)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// PreflightCopyRecovery is startup-only read-only validation, not DATA admission.
func (r *Resources) PreflightCopyRecovery(root *os.File, deviceID, action string, intent a.CopyIntent) error {
	if r == nil || r.registry == nil {
		return ErrConfiguration
	}
	return m.PreflightCopyRecovery(root, deviceID, action, intent)
}

// PrepareRetirementProof publishes only a root-bootstrap-only live resource census.
// The authority has already fenced and joined the selected owner; the registry
// keeps its namespace gate through the synchronous authority publication.
func (r *Resources) PrepareRetirementProof(b a.Binding, root *os.File, publish func() (bool, error)) (bool, error) {
	if r == nil || r.registry == nil {
		return false, ErrConfiguration
	}
	return r.registry.PrepareRetirementProof(b, root, publish)
}

// Barrier is solely for Authority.Config.Barrier, after authority fences and joins
// admitted work. Transport loss and notification delivery never invoke it.
func (r *Resources) Barrier(b a.Binding, root *os.File) error {
	if r == nil || r.registry == nil {
		return ErrConfiguration
	}
	if err := r.registry.Barrier(b, root); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.live, b.Attachment)
	r.mu.Unlock()
	return nil
}
