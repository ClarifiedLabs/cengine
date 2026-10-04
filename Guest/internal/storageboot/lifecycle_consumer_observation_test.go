package storageboot

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"testing"

	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	s "dev.cengine/guest/internal/storageservice"
)

func lifecycleConsumerFrame(q cc.Arm, command string) *LifecycleFrame {
	f := lifecycleFrame("command", lifecycleTestBinding())
	seq := uint64(1)
	f.Sequence, f.ServiceEpoch, f.WorkerUUID, f.Command = &seq, q.WorkerScope.ServiceEpoch, q.WorkerScope.WorkerUUID, command
	if command == "consumer-observation-arm" {
		f.ConsumerObservationArm = &q
	} else {
		f.ConsumerObservationQuery = &q
	}
	return &f
}

func TestLifecycleConsumerWireClosed(t *testing.T) {
	q := consumerVector(t)
	for _, command := range []string{"consumer-observation-arm", "consumer-observation-query", "consumer-observation-finalize"} {
		f := lifecycleConsumerFrame(q, command)
		raw, err := EncodeLifecycleFrame(f)
		must(t, err)
		decoded, err := DecodeLifecycleFrame(raw[4:])
		must(t, err)
		if !reflect.DeepEqual(f, decoded) {
			t.Fatal("roundtrip")
		}
		for _, mutation := range [][2]string{
			{`"worker_uuid":"` + f.WorkerUUID + `"`, `"worker_uuid":"11111111-1111-4111-8111-111111111111"`},
			{`"service_epoch":"` + f.ServiceEpoch + `"`, `"service_epoch":"11111111-1111-4111-8111-111111111111"`},
			{`"role":"runtime"`, `"role":"runtime","unknown":null`},
			{`"sequence":1`, `"sequence":1,"consumerObservationStatus":null`},
			{`"sequence":1`, `"sequence":1,"sequence":1`},
			{`"armDigest":"` + q.ArmDigest + `"`, `"armDigest":null`},
		} {
			bad := bytes.Replace(raw[4:], []byte(mutation[0]), []byte(mutation[1]), 1)
			if bytes.Equal(bad, raw[4:]) {
				t.Fatal("mutation missed")
			}
			if _, err := DecodeLifecycleFrame(bad); err == nil {
				t.Fatalf("accepted %s", bad)
			}
		}
		f.ConsumerObservationStatus = &cc.Status{Query: q, State: "armed"}
		if _, err := EncodeLifecycleFrame(f); err == nil {
			t.Fatal("mixed union")
		}
	}
	for _, state := range []string{"armed", "claimed", "failed", "observed", "finalized"} {
		f := lifecycleSupervisorReply(lifecycleConsumerFrame(q, "consumer-observation-query"))
		status := cc.Status{Query: q, State: state}
		if state != "armed" {
			status.SelectedCount = 1
		}
		if state == "failed" {
			status.Failure = "duplicate"
		}
		if state == "observed" || state == "finalized" {
			status.Evidence = &cc.Evidence{Stage: "request-admit", ErrorClass: "blocked", StoreUUID: q.WorkerScope.StoreUUID, ServiceEpoch: q.WorkerScope.ServiceEpoch, RejectedLeafSHA256: q.OriginalLeafSHA256, Admission: &cc.Admission{Original: q.Original, RequestSequence: 19}}
		}
		f.ConsumerObservationStatus = &status
		raw, err := EncodeLifecycleFrame(f)
		must(t, err)
		_, err = DecodeLifecycleFrame(raw[4:])
		must(t, err)
		for _, insertion := range []string{`"failure":"",`, `"unknown":null,`, `"evidence":null,`} {
			bad := bytes.Replace(raw[4:], []byte(`"consumerObservationStatus":{`), []byte(`"consumerObservationStatus":{`+insertion), 1)
			if _, err := DecodeLifecycleFrame(bad); err == nil {
				t.Fatalf("accepted %s", bad)
			}
		}
		if status.Evidence != nil {
			bad := bytes.Replace(raw[4:], []byte(`"requestSequence":19`), []byte(`"requestSequence":19,"handle":0`), 1)
			if _, err := DecodeLifecycleFrame(bad); err == nil {
				t.Fatal("optional evidence shape widened")
			}
		}
		f.ServiceEpoch = "11111111-1111-4111-8111-111111111111"
		if _, err := EncodeLifecycleFrame(f); err == nil {
			t.Fatal("uncorrelated status")
		}
	}
}

// Exercise the signed worker admission, real worker codec/dispatcher, supervisor,
// and lifecycle owner's DATA endpoint. No fake service or second recorder.
func TestLifecycleConsumerActualWorkerOwner(t *testing.T) {
	cfg, _ := lifecycleTestConfig(t)
	ip := &inProcessLifecycle{}
	var service *s.LifecycleService
	sup, err := newLifecycleSupervisor(cfg, ip.starter(openRoot(t), lifecycleTestBinding(), func() error { return nil }, func(owner *s.LifecycleService) (func() error, error) { service = owner; return nil, nil }))
	must(t, err)
	defer func() { must(t, sup.close()); ip.wg.Wait() }()
	before := copyLifecycleReady(sup.ready)
	q := consumerVector(t)
	q.Original.Binding.Store, q.Original.Epoch = string(before.Identity.Store), before.ServiceEpoch
	q.WorkerScope = cc.WorkerScope{StoreUUID: string(before.Identity.Store), ServiceEpoch: before.ServiceEpoch, WorkerUUID: before.WorkerUUID}
	q.CaseName, q.Original.Epoch = cc.CrossE, lifecycleTestID(t)
	if got := lifecycleWorkerCommand(nil, lifecycleConsumerFrame(q, "consumer-observation-arm")); got.Code != "command" {
		t.Fatal("nil owner")
	}
	exchange := func(q cc.Arm, command string) (*LifecycleFrame, string) {
		t.Helper()
		return sup.command(lifecycleConsumerFrame(q, command))
	}
	if pc.CurrentProfile() != pc.FullProfile {
		for _, command := range []string{"consumer-observation-arm", "consumer-observation-query", "consumer-observation-finalize"} {
			if _, code := exchange(q, command); code != "command" {
				t.Fatal("ordinary supervisor activated", code)
			}
			if got := lifecycleWorkerCommand(service, lifecycleConsumerFrame(q, command)); got.Code != "command" {
				t.Fatal("ordinary worker activated")
			}
		}
		return
	}
	for _, mutate := range []func(*cc.Arm){
		func(q *cc.Arm) { q.WorkerScope.WorkerUUID = lifecycleTestID(t) },
		func(q *cc.Arm) { q.WorkerScope.ServiceEpoch = lifecycleTestID(t) },
		func(q *cc.Arm) {
			q.WorkerScope.StoreUUID = lifecycleTestID(t)
			q.Original.Binding.Store = q.WorkerScope.StoreUUID
		},
	} {
		bad := q
		mutate(&bad)
		if reply, code := exchange(bad, "consumer-observation-arm"); code == "" && reply.Code == "" {
			t.Fatal("stale scope armed")
		}
		if got := lifecycleWorkerCommand(service, lifecycleConsumerFrame(bad, "consumer-observation-arm")); got.Code != "command" {
			t.Fatal("worker scope bypass")
		}
	}
	reply, code := exchange(q, "consumer-observation-arm")
	if code != "" || reply.ConsumerObservationStatus == nil || reply.ConsumerObservationStatus.State != "armed" {
		t.Fatal("arm", reply, code)
	}
	reply, code = exchange(q, "consumer-observation-finalize")
	if code != "" || reply.Code != "command" {
		t.Fatal("unobserved finalize", reply, code)
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- service.ServeData(context.Background(), server) }()
	client.Close()
	if <-done == nil {
		t.Fatal("DATA unexpectedly admitted")
	}
	reply, code = exchange(q, "consumer-observation-query")
	if code != "" || reply.ConsumerObservationStatus == nil || reply.ConsumerObservationStatus.State != "failed" || reply.ConsumerObservationStatus.Failure != "transport-or-unattributed" || reply.ConsumerObservationStatus.SelectedCount != 1 {
		t.Fatal("not the DATA recorder", reply, code)
	}
	if !reflect.DeepEqual(before, sup.ready) {
		t.Fatal("observation changed Ready")
	}
}

func TestLifecycleConsumerSupervisorCorrelatesReplies(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full profile only")
	}
	q := consumerVector(t)
	request := lifecycleConsumerFrame(q, "consumer-observation-query")
	for _, mutate := range []func(*LifecycleFrame){
		func(f *LifecycleFrame) { f.Binding.GuestBootNonce = lifecycleTestID(t) },
		func(f *LifecycleFrame) { f.ConsumerObservationStatus.Query.RequestID = lifecycleTestID(t) },
		func(f *LifecycleFrame) { f.ConsumerObservationStatus.Query.WorkerScope.WorkerUUID = lifecycleTestID(t) },
		func(f *LifecycleFrame) { f.ConsumerObservationStatus.State = "finalized" },
		func(f *LifecycleFrame) { f.ConsumerObservationStatus = nil; yes := true; f.OK = &yes },
	} {
		worker := newFakeLifecycleWorker(nil)
		worker.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
			r := lifecycleSupervisorReply(f)
			r.ConsumerObservationStatus = &cc.Status{Query: q, State: "armed"}
			mutate(r)
			return r, nil
		}
		ready := &LifecycleReady{ServiceEpoch: q.WorkerScope.ServiceEpoch, WorkerUUID: q.WorkerScope.WorkerUUID}
		ready.Identity.Store = a.ID(q.WorkerScope.StoreUUID)
		sup := &lifecycleSupervisor{worker: worker, ready: ready}
		if _, code := sup.command(request); code != "command" {
			t.Fatal("accepted substituted status", code)
		}
	}
}
