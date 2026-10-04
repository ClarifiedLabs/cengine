package storageboot

import (
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
)

func TestLifecycleChallengeCloseDuringOriginalObservation(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile")
	}
	supervisor, starter, _ := newTestLifecycleSupervisor(t)
	_, original := starter.snapshot()
	child := newFakeLifecycleWorker(nil)
	child.finish(true)
	supervisor.worker = &lifecycleTestChallenger{original, func(lifecycleWorkerChallenge, workerStartGate) (lifecycleWorker, error) {
		return child, nil
	}}
	entered, release := make(chan struct{}), make(chan struct{})
	original.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		close(entered)
		<-release
		return lifecycleIsolationProof(t, f, original.ready), nil
	}
	request := lifecycleIsolationRequest(t, supervisor.ready, "second-service-exclusivity")
	commandDone := make(chan struct{})
	go func() {
		defer close(commandDone)
		if reply, code := supervisor.dispatch(request); reply != nil || code == "" {
			t.Error("shutdown admitted proof")
		}
	}()
	<-entered // authenticated refusal + reap have already completed
	closed := make(chan error, 1)
	go func() { closed <- supervisor.close() }()
	<-original.done()
	select {
	case <-closed:
		t.Fatal("close escaped admitted original exchange")
	default:
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close failed to join original observation")
	}
	<-commandDone
	if _, closes := child.counts(); closes != 1 {
		t.Fatal("child closed twice")
	}
	if _, closes := original.counts(); closes != 1 {
		t.Fatal("original not closed once")
	}
}
