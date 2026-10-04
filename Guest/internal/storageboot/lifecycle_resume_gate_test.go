package storageboot

import (
	"errors"
	"testing"
)

func TestResumeBootGatePurposeAndSingleUse(t *testing.T) {
	_, cfg := resumeTestConfiguration(t)
	for _, probe := range []bool{false, true} {
		calls := 0
		gate := &lifecycleResumeGate{probe: probe, promote: func(LifecycleConfiguration) error { calls++; return nil }}
		ok, err := gate.take(cfg)
		if probe {
			if !ok || err != nil || calls != 1 {
				t.Fatal("probe not promoted", ok, err, calls)
			}
			if ok, err := gate.take(cfg); ok || err == nil || calls != 1 {
				t.Fatal("resume reused")
			}
			open := cfg
			open.Action = "open"
			if ok, err := gate.take(open); ok || err != nil {
				t.Fatal("replacement refused after promotion")
			}
		} else if ok || err == nil || calls != 0 {
			t.Fatal("ordinary RW boot admitted resume")
		}
	}
	for _, fault := range []string{"wrong-action", "bad-signature", "promotion"} {
		t.Run(fault, func(t *testing.T) {
			calls := 0
			gate := &lifecycleResumeGate{probe: true, promote: func(LifecycleConfiguration) error { calls++; return errors.New("denied") }}
			bad := copyLifecycleConfiguration(cfg)
			if fault == "wrong-action" {
				bad.Action = "initialize"
			}
			if fault == "bad-signature" {
				bad.Resume.Signature[0] ^= 1
			}
			if ok, err := gate.take(bad); ok || err == nil {
				t.Fatal("failure admitted")
			}
			if ok, err := gate.take(cfg); ok || err == nil {
				t.Fatal("failure retried")
			}
			want := 0
			if fault == "promotion" {
				want = 1
			}
			if calls != want {
				t.Fatal("unexpected promotion calls", calls)
			}
		})
	}
}

func TestResumeWorkerPacketRequiresPID1PromotionEvidence(t *testing.T) {
	_, cfg := resumeTestConfiguration(t)
	h := lifecycleTestStart(t)
	h.Configuration, h.VerifiedFresh = cfg, false
	if _, err := encodeLifecycleWorkerStart(h); err == nil {
		t.Fatal("resume without PID1 promotion encoded")
	}
	h.VerifiedResume = true
	raw, err := encodeLifecycleWorkerStart(h)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeLifecycleWorkerStart(raw)
	if err != nil || !decoded.VerifiedResume {
		t.Fatal("promotion evidence lost", err)
	}
	h.Configuration, _ = lifecycleTestConfig(t)
	h.VerifiedFresh = true
	if _, err := encodeLifecycleWorkerStart(h); err == nil {
		t.Fatal("initialize accepted resume evidence")
	}
}
