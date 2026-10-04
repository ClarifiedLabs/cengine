package storageboot

import (
	"errors"
	"reflect"
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
)

type lifecycleTestChallenger struct {
	*fakeLifecycleWorker
	launch func(lifecycleWorkerChallenge, workerStartGate) (lifecycleWorker, error)
}

func (w *lifecycleTestChallenger) challenge(h lifecycleWorkerChallenge, g workerStartGate) (lifecycleWorker, error) {
	return w.launch(h, g)
}

func TestLifecycleChallengeSupervisorAdmissionAndReap(t *testing.T) {
	sup, starter, cfg := newTestLifecycleSupervisor(t)
	_, original := starter.snapshot()
	request := lifecycleIsolationRequest(t, sup.ready, "second-service-exclusivity")
	child := newFakeLifecycleWorker(nil)
	child.autoDone = false
	entered := make(chan lifecycleWorkerChallenge, 1)
	sup.worker = &lifecycleTestChallenger{original, func(h lifecycleWorkerChallenge, g workerStartGate) (lifecycleWorker, error) {
		entered <- h
		return child, g(func() error { return nil })
	}}
	original.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		if !child.reaped() {
			t.Error("original queried before sole reap")
		}
		return lifecycleIsolationProof(t, f, sup.ready), nil
	}
	if pc.CurrentProfile() != pc.FullProfile {
		if r, code := sup.dispatch(request); r != nil || code != "command" {
			t.Fatal("ordinary admitted")
		}
		select {
		case <-entered:
			t.Fatal("ordinary launched")
		default:
		}
		return
	}
	old := copyLifecycleReady(sup.ready)
	done := make(chan *LifecycleFrame, 1)
	go func() {
		r, code := sup.dispatch(request)
		if code != "" {
			t.Error(code)
		}
		done <- r
	}()
	h := <-entered
	if h.WorkerUUID == old.WorkerUUID || !id(h.WorkerUUID) || !lifecycleSignedEqual(h.Current, cfg.Signed) || h.Predecessor != lifecycleServiceState(old, cfg.Signed.Grant) || h.IsolationRequest != *request.IsolationRequest {
		t.Fatal("wrong snapshot")
	}
	if r, code := sup.dispatch(request); r != nil || code != "worker-busy" {
		t.Fatal("concurrent admission")
	}
	select {
	case <-done:
		t.Fatal("proof before reap")
	default:
	}
	child.finish(true)
	reply := <-done
	if !validLifecycleIsolationReply(request, reply) || reply.IsolationProof.Result != "second-owner-locked" {
		t.Fatal("proof", reply)
	}
	if kills, closes := original.counts(); kills != 0 || closes != 0 {
		t.Fatal("original disturbed")
	}
	if _, closes := child.counts(); closes != 1 {
		t.Fatal("child not released once")
	}
	if !reflect.DeepEqual(old, sup.ready) || !lifecycleSignedEqual(sup.signed, cfg.Signed) || sup.challenger != nil {
		t.Fatal("promoted original or retained reaped challenger")
	}
}

func TestLifecycleChallengeSupervisorCurrentGrantAfterReconcile(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile")
	}
	sup, starter, cfg := newTestLifecycleSupervisor(t)
	_, original := starter.snapshot()
	signed, controller := lifecycleTakeover(t, cfg, 1)
	original.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		r := lifecycleSupervisorReply(f)
		r.Certificate = []byte("certificate")
		return r, nil
	}
	authorize := lifecycleSupervisorCommand(sup.ready, "authorize-successor")
	authorize.Signed = &signed
	authorize.CSR = []byte("csr")
	if _, code := sup.command(authorize); code != "" {
		t.Fatal(code)
	}
	adopted := copyLifecycleReady(sup.ready)
	adopted.ControllerEpoch = controller.Epoch
	adopted.ControllerKey = string(controller.Key)
	adopted.Revision++
	original.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		r := lifecycleSupervisorReply(f)
		r.Ready = copyLifecycleReady(adopted)
		return r, nil
	}
	reconcile := lifecycleSupervisorCommand(sup.ready, "reconcile-controller")
	reconcile.Signed = &signed
	reconcile.Controller = &controller
	if _, code := sup.command(reconcile); code != "" {
		t.Fatal(code)
	}
	child := newFakeLifecycleWorker(nil)
	child.finish(true)
	sup.worker = &lifecycleTestChallenger{original, func(h lifecycleWorkerChallenge, g workerStartGate) (lifecycleWorker, error) {
		if !lifecycleSignedEqual(h.Current, signed) || h.Predecessor != lifecycleServiceState(adopted, signed.Grant) {
			t.Error("stale startup grant snapshot")
		}
		return child, nil
	}}
	original.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) { return lifecycleIsolationProof(t, f, adopted), nil }
	request := lifecycleIsolationRequest(t, sup.ready, "second-service-exclusivity")
	if r, code := sup.dispatch(request); code != "" || !validLifecycleIsolationReply(request, r) {
		t.Fatal("post-takeover challenge", code)
	}
}

func TestLifecycleChallengeSupervisorFailureContainment(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile")
	}
	for _, kind := range []string{"no-owner", "launch-error", "EOF", "wrong-refusal", "unreaped", "timeout", "wrong-state"} {
		t.Run(kind, func(t *testing.T) {
			sup, starter, _ := newTestLifecycleSupervisor(t)
			_, original := starter.snapshot()
			child := newFakeLifecycleWorker(nil)
			if kind == "unreaped" {
				child.finish(false)
			} else if kind != "timeout" {
				child.finish(true)
			} else {
				child.autoDone = false
			}
			sup.worker = &lifecycleTestChallenger{original, func(h lifecycleWorkerChallenge, g workerStartGate) (lifecycleWorker, error) {
				if kind == "no-owner" {
					return nil, errors.New(kind)
				}
				if kind == "launch-error" || kind == "EOF" || kind == "wrong-refusal" {
					return child, errors.New(kind)
				}
				return child, nil
			}}
			queries := 0
			original.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
				queries++
				r := lifecycleIsolationProof(t, f, sup.ready)
				r.IsolationProof.Request.Challenge = lifecycleTestID(t)
				return r, nil
			}
			if r, code := sup.dispatch(lifecycleIsolationRequest(t, sup.ready, "second-service-exclusivity")); r != nil || code == "" {
				t.Fatal("failure became proof")
			}
			want := 0
			if kind == "wrong-state" {
				want = 1
			}
			if queries != want {
				t.Fatal("queried original without refusal/reap", queries)
			}
			if !sup.failed {
				t.Fatal("failure did not fence")
			}
			if kills, _ := original.counts(); kills != 0 {
				t.Fatal("challenge killed original")
			}
			if kind == "unreaped" || kind == "timeout" {
				if sup.challenger != child {
					t.Fatal("lost partial owner")
				}
				if _, closes := child.counts(); closes != 0 {
					t.Fatal("closed unreaped birth pin")
				}
			}
			if kind == "timeout" {
				child.finish(true)
			}
			err := sup.close()
			if kind == "unreaped" && err == nil {
				t.Fatal("unreaped close succeeded")
			}
			if kills, closes := original.counts(); kills == 0 || closes != 1 {
				t.Fatal("close did not join original")
			}
		})
	}
}

func TestLifecycleChallengeCloseJoinsRacingLaunch(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile")
	}
	sup, starter, _ := newTestLifecycleSupervisor(t)
	_, original := starter.snapshot()
	entered, release := make(chan struct{}), make(chan struct{})
	child := newFakeLifecycleWorker(nil)
	sup.worker = &lifecycleTestChallenger{original, func(h lifecycleWorkerChallenge, g workerStartGate) (lifecycleWorker, error) {
		close(entered)
		<-release
		return child, g(func() error { t.Error("handoff after close"); return nil })
	}}
	request := lifecycleIsolationRequest(t, sup.ready, "second-service-exclusivity")
	commandDone := make(chan struct{})
	go func() {
		defer close(commandDone)
		if r, code := sup.dispatch(request); r != nil || code == "" {
			t.Error("close race produced proof")
		}
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- sup.close() }()
	<-original.done() // close has fenced admission and started shutdown
	select {
	case <-closed:
		t.Fatal("close escaped racing launch")
	default:
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not join launcher/child")
	}
	<-commandDone
	if _, closes := child.counts(); closes != 1 {
		t.Fatal("racing child not released once")
	}
}
