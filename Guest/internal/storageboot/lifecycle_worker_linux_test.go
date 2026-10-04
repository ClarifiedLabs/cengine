//go:build linux

package storageboot

import (
	"errors"
	"os"
	"testing"
)

func TestProcessLifecycleStarterRequiresHeldRootAndPID1Inputs(t *testing.T) {
	fresh := func() error { return nil }
	if _, err := processLifecycleStarter(nil, lifecycleTestBinding(), "10.0.0.2", fresh); err == nil {
		t.Fatal("nil root accepted")
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, tc := range map[string]struct {
		address string
		fresh   func() error
	}{"address": {"0.0.0.0", fresh}, "fresh": {"10.0.0.2", nil}} {
		if _, err := processLifecycleStarter(root, lifecycleTestBinding(), tc.address, tc.fresh); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestResumeLauncherDefersRootUntilPromotionAndRefusesFailedRepin(t *testing.T) {
	_, cfg := resumeTestConfiguration(t)
	promotionCalls, rootCalls, freshCalls := 0, 0, 0
	gate := &lifecycleResumeGate{probe: true, promote: func(LifecycleConfiguration) error { promotionCalls++; return nil }}
	fresh := func() error { freshCalls++; return nil }
	rootSource := func() (*os.File, error) {
		rootCalls++
		if promotionCalls != 1 {
			t.Fatal("root requested before signed promotion")
		}
		return nil, errors.New("repin failed")
	}
	start, err := processLifecycleStarterWithResume(nil, lifecycleTestBinding(), "10.0.0.2", fresh, gate, rootSource)
	if err != nil || promotionCalls != 0 || rootCalls != 0 {
		t.Fatal("launcher escaped root before configure", err)
	}
	worker, ready, err := start(cfg, lifecycleTestID(t), func(send func() error) error { return send() })
	if err == nil || worker != nil || ready != nil || promotionCalls != 1 || rootCalls != 1 || freshCalls != 0 {
		t.Fatal("failed new-root proof launched a worker", err)
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := processLifecycleStarterWithResume(root, lifecycleTestBinding(), "10.0.0.2", fresh, &lifecycleResumeGate{probe: true}, rootSource); err == nil {
		t.Fatal("probe accepted escaped old root descriptor")
	}
	if _, err := processLifecycleStarterWithResume(nil, lifecycleTestBinding(), "10.0.0.2", fresh, &lifecycleResumeGate{probe: true}, nil); err == nil {
		t.Fatal("probe accepted absent new-root source")
	}
}

func TestRunLifecycleWorkerRefusesWithoutInheritedChannel(t *testing.T) {
	if RunLifecycleWorker() == nil {
		t.Fatal("worker ran without an authenticated PID1 channel")
	}
}
