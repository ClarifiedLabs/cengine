package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	p "dev.cengine/guest/internal/storagepki"
)

// A host-fabricated service change with valid shape but no ROOT signature must
// be rejected before pending installation: no kill, no start.
func TestLifecycleSupervisorRejectsUnsignedServiceChange(t *testing.T) {
	s, starter, cfg := newTestLifecycleSupervisor(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	for name, forge := range map[string]func(*p.SignedLifecycleServiceChange){
		"absent":  func(c *p.SignedLifecycleServiceChange) { c.Signature = nil },
		"zero":    func(c *p.SignedLifecycleServiceChange) { c.Signature = make([]byte, 64) },
		"flipped": func(c *p.SignedLifecycleServiceChange) { c.Signature[0] ^= 1 },
		"other-root": func(c *p.SignedLifecycleServiceChange) {
			msg, _ := p.LifecycleServiceChangeSigningBytes(c.Request)
			c.Signature = ed25519.Sign(other, msg)
		},
	} {
		request := lifecycleTestReplacement(t, s, cfg)
		if request.Configuration.Reopen.Request.Validate() != nil {
			t.Fatal("request shape must be valid")
		}
		forge(request.Configuration.Reopen)
		starter.mu.Lock()
		calls, worker := starter.calls, starter.current
		starter.mu.Unlock()
		kills, _ := worker.counts()
		status, code := s.replaceService(request)
		if status != nil || code == "" {
			t.Fatalf("%s: unsigned change admitted", name)
		}
		starter.mu.Lock()
		after := starter.calls
		starter.mu.Unlock()
		killsAfter, _ := worker.counts()
		s.mu.Lock()
		pending, terminal := s.pending, s.terminal
		s.mu.Unlock()
		if after != calls || killsAfter != kills || pending != nil || terminal != nil {
			t.Fatalf("%s: unsigned change killed/started a worker", name)
		}
	}
	// The same request, ROOT-signed, is admitted.
	if _, code := s.replaceService(lifecycleTestReplacement(t, s, cfg)); code != "" {
		t.Fatal("signed change rejected", code)
	}
}

// The configure frame and the PID1->worker start packet both re-verify.
func TestLifecycleOpenConfigurationRequiresSignedChange(t *testing.T) {
	s, _, cfg := newTestLifecycleSupervisor(t)
	open := lifecycleTestReplacement(t, s, cfg).Configuration
	if open.validate() != nil {
		t.Fatal("signed open rejected")
	}
	start := lifecycleTestStart(t)
	start.Configuration, start.VerifiedFresh = open, false
	if _, err := encodeLifecycleWorkerStart(start); err != nil {
		t.Fatal("signed open start rejected", err)
	}
	for name, forge := range map[string]func(*LifecycleConfiguration){
		"absent":    func(c *LifecycleConfiguration) { c.Reopen.Signature = nil },
		"flipped":   func(c *LifecycleConfiguration) { c.Reopen.Signature[0] ^= 1 },
		"no-reopen": func(c *LifecycleConfiguration) { c.Reopen = nil },
		"root-swap": func(c *LifecycleConfiguration) {
			c.RootPublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
		},
	} {
		bad := copyLifecycleConfiguration(open)
		forge(&bad)
		if bad.validate() == nil {
			t.Fatalf("%s: configure accepted", name)
		}
		frame := lifecycleFrame("configure", lifecycleTestBinding())
		frame.Configuration = &bad
		if _, err := EncodeLifecycleFrame(&frame); err == nil {
			t.Fatalf("%s: configure frame encoded", name)
		}
		h := start
		h.Configuration = bad
		if _, err := encodeLifecycleWorkerStart(h); err == nil {
			t.Fatalf("%s: worker start encoded", name)
		}
		if raw, err := lifecycleCanonical(&h); err != nil {
			t.Fatal(err)
		} else if _, err = decodeLifecycleWorkerStart(raw); err == nil {
			t.Fatalf("%s: worker start decoded", name)
		}
	}
}
