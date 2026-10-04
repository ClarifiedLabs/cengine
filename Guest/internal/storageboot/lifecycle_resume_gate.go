package storageboot

import (
	"errors"
	"sync"
)

// lifecycleResumeGate freezes PID1's actual boot purpose. Only a read-only
// probe boot may resume, and its first worker MUST be the admitted resume.
// A failed attempt is terminal. Later ROOT-authorized replacements may reopen
// the promoted mount but may never reuse its resume or initialize permission.
type lifecycleResumeGate struct {
	mu        sync.Mutex
	probe     bool
	attempted bool
	promoted  bool
	promote   func(LifecycleConfiguration) error
}

func (g *lifecycleResumeGate) take(c LifecycleConfiguration) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	reject := func() (bool, error) { return false, errors.New("configuration") }
	if !g.probe {
		if c.Action == "resume-open-takeover" {
			return reject()
		}
		return false, nil
	}
	if g.attempted {
		if !g.promoted || c.Action != "open" {
			return reject()
		}
		return false, nil
	}
	g.attempted = true
	if c.Action != "resume-open-takeover" || c.validate() != nil || g.promote == nil {
		return reject()
	}
	if err := g.promote(copyLifecycleConfiguration(c)); err != nil {
		return false, err
	}
	g.promoted = true
	return true, nil
}
