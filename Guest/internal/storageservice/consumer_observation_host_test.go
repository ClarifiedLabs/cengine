//go:build cengine_storage_host_test && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageservice

import (
	"crypto/tls"
	cc "dev.cengine/guest/internal/consumercompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	w "dev.cengine/guest/internal/storagewire"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// The explicit host adapter replaces only Linux filesystem execution/barrier;
// issued TLS, actual control Retire, per-request Admit and its tuple remain real.
func TestConsumerSameELiveBeforeArmRealRetire(t *testing.T) {
	f := newFixture(t)
	_, err := f.s.InstallCompatibilityHostTestExecutor()
	must(t, err)
	h, identity := consumerIdentity(t, f)
	raw, wait := serve(t, f.s.ServeData)
	data := tls.Client(raw, consumerTLS(t, f, identity))
	must(t, data.SetDeadline(time.Now().Add(5*time.Second)))
	var greeting w.ServerHello
	must(t, w.ReadFrame(data, &greeting))
	must(t, w.WriteFrame(data, &w.ClientHello{Authority: h, Profile: w.RequiredProfile()}))
	var root w.RootReply
	must(t, w.ReadFrame(data, &root))
	request := w.Request{Sequence: 7, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.GetAttrRequest{Node: 1}}
	must(t, w.WriteFrame(data, &request))
	var reply w.Reply
	must(t, w.ReadFrame(data, &reply))
	if reply.Sequence != 7 || reply.Errno != 0 {
		t.Fatal(reply)
	}
	q := consumerArm(t, f, h, identity, cc.SameE)
	_, err = f.s.ArmConsumerObservation(q)
	must(t, err)
	control, join := f.connect(t)
	response := call(t, control, c.Request{Retire: &a.RetireRequest{Operation: a.ID(q.OperationUUID), Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch}})
	if response.Receipt == nil {
		t.Fatal("no real retirement receipt")
	}
	control.Close()
	join()
	request.Sequence = 19
	must(t, w.WriteFrame(data, &request))
	if w.ReadFrame(data, &reply) == nil {
		t.Fatal("retired request accepted")
	}
	if wait() != a.ErrBlocked {
		t.Fatal("not actual blocked admission")
	}
	s, err := f.s.QueryConsumerObservation(q)
	must(t, err)
	must(t, cc.ValidateStatus(s))
	if s.State != "observed" || s.SelectedCount != 1 || s.Evidence == nil || s.Evidence.Admission == nil || s.Evidence.Admission.Original != cc.OriginalFor(h) || s.Evidence.Admission.RequestSequence != 19 {
		t.Fatal(s)
	}
	bad := q
	bad.OperationUUID = string(id(t))
	if _, err = f.s.QueryConsumerObservation(bad); err == nil {
		t.Fatal("mismatched query")
	}
	s, err = f.s.QueryConsumerObservation(q)
	must(t, err)
	if s.State != "failed" || s.Evidence != nil {
		t.Fatal("mismatch retained positive", s)
	}
}

func TestConsumerSameEAdmittedRequestIsNotDenial(t *testing.T) {
	f := newFixture(t)
	_, err := f.s.InstallCompatibilityHostTestExecutor()
	must(t, err)
	h, identity := consumerIdentity(t, f)
	raw, wait := serve(t, f.s.ServeData)
	data := tls.Client(raw, consumerTLS(t, f, identity))
	must(t, data.SetDeadline(time.Now().Add(5*time.Second)))
	var greeting w.ServerHello
	must(t, w.ReadFrame(data, &greeting))
	must(t, w.WriteFrame(data, &w.ClientHello{Authority: h, Profile: w.RequiredProfile()}))
	var root w.RootReply
	must(t, w.ReadFrame(data, &root))
	q := consumerArm(t, f, h, identity, cc.SameE)
	_, err = f.s.ArmConsumerObservation(q)
	must(t, err)
	request := w.Request{Sequence: 11, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.GetAttrRequest{Node: 1}}
	must(t, w.WriteFrame(data, &request))
	var reply w.Reply
	must(t, w.ReadFrame(data, &reply))
	if reply.Sequence != 11 || reply.Errno != 0 {
		t.Fatal("observer changed admitted work", reply)
	}
	status, err := f.s.QueryConsumerObservation(q)
	must(t, err)
	if status.State != "failed" || status.Failure != "not-blocked" || status.SelectedCount != 1 || status.Evidence != nil {
		t.Fatal(status)
	}
	control, join := f.connect(t)
	response := call(t, control, c.Request{Retire: &a.RetireRequest{Operation: a.ID(q.OperationUUID), Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch}})
	if response.Receipt == nil {
		t.Fatal("admitted guard not released")
	}
	control.Close()
	join()
	raw.Close()
	_ = wait()
}

// Finalize races a real per-request Authority.Admit after actual control Retire.
// Authority permits only one live session per attachment; later reconnects must
// still reject at normal authentication, without changing a sealed observation.
func TestConsumerSameEFinalizeAgainstRealAdmission(t *testing.T) {
	for _, order := range []string{"before", "after", "concurrent"} {
		iterations := 1
		if order == "concurrent" {
			iterations = 16
		}
		for iteration := 0; iteration < iterations; iteration++ {
			t.Run(fmt.Sprintf("%s/%d", order, iteration), func(t *testing.T) {
				f := newFixture(t)
				_, err := f.s.InstallCompatibilityHostTestExecutor()
				must(t, err)
				h, identity := consumerIdentity(t, f)
				raw, wait := serve(t, f.s.ServeData)
				data := tls.Client(raw, consumerTLS(t, f, identity))
				must(t, data.SetDeadline(time.Now().Add(5*time.Second)))
				var greeting w.ServerHello
				must(t, w.ReadFrame(data, &greeting))
				must(t, w.WriteFrame(data, &w.ClientHello{Authority: h, Profile: w.RequiredProfile()}))
				var root w.RootReply
				must(t, w.ReadFrame(data, &root))
				request := w.Request{Sequence: 7, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.GetAttrRequest{Node: 1}}
				must(t, w.WriteFrame(data, &request))
				var reply w.Reply
				must(t, w.ReadFrame(data, &reply))
				if reply.Sequence != 7 || reply.Errno != 0 {
					t.Fatal(reply)
				}
				q := consumerArm(t, f, h, identity, cc.SameE)
				_, err = f.s.ArmConsumerObservation(q)
				must(t, err)
				control, join := f.connect(t)
				response := call(t, control, c.Request{Retire: &a.RetireRequest{Operation: a.ID(q.OperationUUID), Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch}})
				if response.Receipt == nil {
					t.Fatal("missing real retirement receipt")
				}
				control.Close()
				join()
				var terminal cc.Status
				var sealErr error
				var start, done chan struct{}
				if order == "before" {
					if _, err = f.s.FinalizeConsumerObservation(q); err == nil {
						t.Fatal("finalized before admission")
					}
				} else if order == "concurrent" {
					start, done = make(chan struct{}), make(chan struct{})
					go func() { <-start; terminal, sealErr = f.s.FinalizeConsumerObservation(q); close(done) }()
				}
				request.Sequence = 19
				must(t, w.WriteFrame(data, &request))
				if start != nil {
					close(start)
				}
				if w.ReadFrame(data, &reply) == nil {
					t.Fatal("retired request accepted")
				}
				if wait() != a.ErrBlocked {
					t.Fatal("not actual blocked admission")
				}
				if done != nil {
					<-done
				}
				observed, err := f.s.QueryConsumerObservation(q)
				must(t, err)
				if observed.Evidence == nil || observed.Evidence.Admission == nil || observed.Evidence.Admission.RequestSequence != 19 {
					t.Fatal(observed)
				}
				if order == "concurrent" && sealErr == nil {
					if observed.State != "finalized" || !reflect.DeepEqual(observed, terminal) {
						t.Fatal("race seal mismatch", observed)
					}
				} else if observed.State != "observed" {
					t.Fatal("query alone finalized", observed)
				}
				terminal, err = f.s.FinalizeConsumerObservation(q)
				must(t, err)
				observed.State = "finalized"
				if !reflect.DeepEqual(terminal, observed) {
					t.Fatal("admission seal changed", terminal)
				}
				must(t, cc.ValidateStatus(terminal))
				// A later old connection performs real TLS and DataHello. Retired
				// authority must reject it; the observer cannot authorize a root.
				raw2, wait2 := serve(t, f.s.ServeData)
				old := tls.Client(raw2, consumerTLS(t, f, identity))
				must(t, old.SetDeadline(time.Now().Add(5*time.Second)))
				must(t, w.ReadFrame(old, &greeting))
				must(t, w.WriteFrame(old, &w.ClientHello{Authority: h, Profile: w.RequiredProfile()}))
				if w.ReadFrame(old, &root) == nil {
					t.Fatal("retired reconnect admitted")
				}
				if wait2() != a.ErrBlocked {
					t.Fatal("reconnect bypassed normal blocked authority")
				}
				terminal.Evidence.Admission.RequestSequence++
				terminal.Evidence.Admission.Original.Binding.Key = "mutated"
				got, err := f.s.FinalizeConsumerObservation(q)
				must(t, err)
				if !reflect.DeepEqual(got, observed) {
					t.Fatal("aliased or changed admission", got)
				}
			})
		}
	}
}
