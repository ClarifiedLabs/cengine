package storageboot

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"testing/synctest"

	pc "dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/storageworker"
)

func TestLifecycleCompatibilityWireClosed(t *testing.T) {
	arm := storageArmVector(t)
	query, err := pc.StorageQueryForArm(arm)
	must(t, err)
	seq := uint64(1)
	base := lifecycleFrame("command", bindingFixture())
	base.Sequence, base.ServiceEpoch, base.WorkerUUID = &seq, arm.Arm.Scope.ServiceEpoch, arm.WorkerUUID
	for _, command := range []string{"prepare-compatibility-arm", "prepare-compatibility-observe", "prepare-compatibility-release", "prepare-compatibility-worker-exit"} {
		f := base
		f.Command = command
		switch command {
		case "prepare-compatibility-arm":
			f.PrepareCompatibilityArm = &arm
		case "prepare-compatibility-observe":
			f.PrepareCompatibilityQuery = &query
		case "prepare-compatibility-release":
			f.PrepareCompatibilityRelease = &pc.StorageRelease{Query: query, Stage: arm.Arm.CaseName, Token: strings.Repeat("a", 64)}
		default:
			f.PrepareCompatibilityWorkerExit = &pc.StorageRelease{Query: query, Stage: arm.Arm.CaseName, Token: strings.Repeat("a", 64)}
		}
		encoded, err := EncodeLifecycleFrame(&f)
		must(t, err)
		_, err = DecodeLifecycleFrame(encoded[4:])
		must(t, err)
		for _, bad := range [][]byte{
			bytes.Replace(encoded[4:], []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1),
			bytes.Replace(encoded[4:], []byte(`"version":`), []byte(`"arbitrary":true,"version":`), 1),
			bytes.Replace(encoded[4:], []byte(`"workerUUID":`), []byte(`"workerPID":42,"workerUUID":`), 1),
			append(encoded[4:], ' '),
		} {
			if _, err := DecodeLifecycleFrame(bad); err == nil {
				t.Fatalf("accepted %s", bad)
			}
		}
		f.PrepareCompatibilityStatus = &pc.StorageStatus{Query: query, State: "armed"}
		if _, err := EncodeLifecycleFrame(&f); err == nil {
			t.Fatal("mixed request/result")
		}
	}
}

type lifecycleExitWaitWorker struct {
	*fakeLifecycleWorker
	pid      int
	result   storageworker.WaitResult
	observed bool
}

func (w *lifecycleExitWaitWorker) workerPID() int { return w.pid }
func (w *lifecycleExitWaitWorker) workerWaitResult() (storageworker.WaitResult, bool) {
	return w.result, w.observed
}

func TestLifecycleCompatibilityExitWaitOwnership(t *testing.T) {
	pid, result := realWorkerExitResult(t, "74")
	stages := append([]string{"admitted-queued", "full-frame-before-admit"}, checkpointExitStages...)
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			var oldRequest, oldReply *LifecycleFrame
			if stage == "admitted-queued" || stage == "full-frame-before-admit" {
				oldRequest, oldReply = workerExitFramesForStage(t, stage)
			} else {
				oldRequest, oldReply = checkpointExitFramesForStage(t, stage)
			}
			request, reply := oldRequest, oldReply
			synctest.Test(t, func(t *testing.T) {
				worker := &lifecycleExitWaitWorker{fakeLifecycleWorker: newFakeLifecycleWorker(nil), pid: pid, result: result, observed: true}
				exchanges := 0
				worker.respond = func(*LifecycleFrame) (*LifecycleFrame, error) { exchanges++; return reply, nil }
				supervisor := &lifecycleSupervisor{worker: worker, ready: &LifecycleReady{ServiceEpoch: request.ServiceEpoch, WorkerUUID: request.WorkerUUID}}
				type outcome struct {
					reply *LifecycleFrame
					code  string
				}
				done := make(chan outcome, 1)
				go func() { r, c := supervisor.command(request); done <- outcome{r, c} }()
				synctest.Wait()
				if pc.CurrentProfile() != pc.FullProfile {
					got := <-done
					if got.code != "command" || exchanges != 0 {
						t.Fatal("production activated", got)
					}
					return
				}
				select {
				case <-done:
					t.Fatal("ACK proved death")
				default:
				}
				if _, code := supervisor.command(request); code != "worker-busy" {
					t.Fatal(code)
				}
				if _, code := supervisor.status(request.ServiceEpoch, request.WorkerUUID); code != "" {
					t.Fatal("status blocked", code)
				}
				worker.finish(true)
				synctest.Wait()
				got := <-done
				if got.code != "" || got.reply == nil {
					t.Fatal(got)
				}
				must(t, got.reply.validate())
				if got.reply.PrepareCompatibilityCheckpointAck != nil || got.reply.PrepareCompatibilityStatus != nil {
					t.Fatal("ACK projected as Wait")
				}
				if supervisor.worker != worker || !supervisor.lost || supervisor.active {
					t.Fatal("owner lost")
				}
				kills, closes := worker.counts()
				if kills != 0 || closes != 0 {
					t.Fatal("implicit kill/close")
				}
			})
		})
	}
}

func TestLifecycleCompatibilityCheckpointACKStrict(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile only")
	}
	for _, stage := range checkpointExitStages {
		t.Run(stage, func(t *testing.T) {
			oldRequest, oldReply := checkpointExitFramesForStage(t, stage)
			request, reply := oldRequest, oldReply
			must(t, request.validate())
			must(t, reply.validate())
			_, err := lifecycleExitACK(request, reply)
			must(t, err)
			encoded, err := EncodeLifecycleFrame(request)
			must(t, err)
			_, err = DecodeLifecycleFrame(encoded[4:])
			must(t, err)
			raw, err := lifecycleCanonical(reply)
			must(t, err)
			for _, mutate := range []func(*LifecycleFrame){
				func(f *LifecycleFrame) { f.ServiceEpoch = f.WorkerUUID },
				func(f *LifecycleFrame) { f.Binding.Ext4UUID = f.WorkerUUID },
				func(f *LifecycleFrame) { f.OK = new(bool); *f.OK = true },
				func(f *LifecycleFrame) { f.PrepareCompatibilityCheckpointAck.WorkerUUID = f.ServiceEpoch },
				func(f *LifecycleFrame) { f.PrepareCompatibilityCheckpointAck.Arm.RequestID = f.ServiceEpoch },
			} {
				var bad LifecycleFrame
				must(t, json.Unmarshal(raw, &bad))
				mutate(&bad)
				if _, err := lifecycleExitACK(request, &bad); err == nil {
					t.Fatal("accepted wrong ACK")
				}
			}
		})
	}
}

func TestLifecycleCompatibilityDispatchProductionRefusal(t *testing.T) {
	arm := storageArmVector(t)
	q, err := pc.StorageQueryForArm(arm)
	must(t, err)
	seq := uint64(1)
	f := lifecycleFrame("command", bindingFixture())
	f.Sequence, f.ServiceEpoch, f.WorkerUUID = &seq, arm.Arm.Scope.ServiceEpoch, arm.WorkerUUID
	f.Command, f.PrepareCompatibilityQuery = "prepare-compatibility-observe", &q
	// A missing retained owner interface must fail closed, never construct a v1 service.
	reply := lifecycleFrame("reply", f.Binding)
	if lifecycleCompatibilityDispatch(struct{}{}, &f, &reply) == nil {
		t.Fatal("invented owner")
	}
	if got := lifecycleWorkerCommand(nil, &f); got.Code != "command" {
		t.Fatal("nil owner activated")
	}
}

// This exercises the actual worker dispatcher against its retained-owner API,
// not a Frame codec alone. The lifecycle service forwarding implementation is a
// separate integration prerequisite; no test constructs a second coordinator.
type lifecycleCompatibilityTestOwner struct {
	calls  int
	status pc.StorageStatus
}

func (o *lifecycleCompatibilityTestOwner) BindPrepareCompatibilityWorker(string) error { return nil }
func (o *lifecycleCompatibilityTestOwner) ArmPrepareCompatibility(pc.StorageArm) (pc.StorageStatus, error) {
	o.calls++
	return o.status, nil
}
func (o *lifecycleCompatibilityTestOwner) ObservePrepareCompatibility(pc.StorageQuery) (pc.StorageStatus, error) {
	o.calls++
	return o.status, nil
}
func (o *lifecycleCompatibilityTestOwner) ReleasePrepareCompatibility(pc.StorageRelease) (pc.StorageStatus, error) {
	o.calls++
	return o.status, nil
}
func (o *lifecycleCompatibilityTestOwner) ClaimPrepareCompatibilityWorkerExit(pc.StorageRelease) (pc.StorageStatus, error) {
	o.calls++
	return o.status, nil
}
func (o *lifecycleCompatibilityTestOwner) ClaimPrepareCompatibilityCheckpointExit(r pc.WorkerCheckpointExit) (pc.WorkerCheckpointExit, error) {
	o.calls++
	return r, nil
}

func TestLifecycleCompatibilityDispatchRetainedOwner(t *testing.T) {
	oldRequest, oldReply := workerExitFrames(t)
	request, reply := oldRequest, oldReply
	owner := &lifecycleCompatibilityTestOwner{status: *reply.PrepareCompatibilityStatus}
	result := lifecycleSupervisorReply(request)
	err := lifecycleCompatibilityDispatch(owner, request, result)
	if pc.CurrentProfile() != pc.FullProfile {
		if err == nil || owner.calls != 0 {
			t.Fatal("production reached compatibility owner")
		}
		return
	}
	must(t, err)
	if owner.calls != 1 || result.PrepareCompatibilityStatus == nil {
		t.Fatal("dispatch did not reach retained owner")
	}
	_, err = lifecycleExitACK(request, result)
	must(t, err)
	oldRequest, oldReply = checkpointExitFrames(t)
	request, reply = oldRequest, oldReply
	result = lifecycleSupervisorReply(request)
	must(t, lifecycleCompatibilityDispatch(owner, request, result))
	_, err = lifecycleExitACK(request, result)
	must(t, err)
	if owner.calls != 2 || result.PrepareCompatibilityCheckpointWait != nil {
		t.Fatal("worker emitted Wait")
	}
}
