package storageboot

import (
	"bytes"
	"context"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
	s "dev.cengine/guest/internal/storageservice"
)

func lifecycleIsolationRequest(t *testing.T, ready *LifecycleReady, command string) *LifecycleFrame {
	f := lifecycleSupervisorCommand(ready, command)
	f.IsolationRequest = &s.IsolationRequest{RequestID: lifecycleTestID(t), OperationUUID: lifecycleTestID(t), ArmDigest: lifecycleTestHex(t), Challenge: lifecycleTestID(t)}
	return f
}

func lifecycleIsolationProof(t *testing.T, f *LifecycleFrame, ready *LifecycleReady) *LifecycleFrame {
	r := lifecycleSupervisorReply(f)
	result := map[string]string{"isolation-state": "registry-state", "legacy-connection": "legacy-tls-header-rejected", "second-service-exclusivity": "second-owner-locked"}[f.Command]
	r.IsolationProof = &s.IsolationProof{Request: *f.IsolationRequest, WorkerUUID: f.WorkerUUID, CaseName: f.Command, Store: string(ready.Identity.Store), ServiceEpoch: f.ServiceEpoch, Revision: ready.Revision, RegistrySHA256: lifecycleTestHex(t), Result: result}
	return r
}

func TestLifecycleIsolationWireClosed(t *testing.T) {
	supervisor, _, _ := newTestLifecycleSupervisor(t)
	for _, command := range []string{"isolation-state", "legacy-connection", "second-service-exclusivity"} {
		request := lifecycleIsolationRequest(t, supervisor.ready, command)
		sequence := ^uint64(0)
		request.Sequence = &sequence
		reply := lifecycleIsolationProof(t, request, supervisor.ready)
		reply.IsolationProof.Revision = ^uint64(0)
		for _, frame := range []*LifecycleFrame{request, reply} {
			raw, err := EncodeLifecycleFrame(frame)
			must(t, err)
			decoded, err := DecodeLifecycleFrame(raw[4:])
			must(t, err)
			if !reflect.DeepEqual(frame, decoded) {
				t.Fatal("full-width roundtrip")
			}
			for _, mutation := range [][2]string{
				{`"sequence":18446744073709551615`, `"sequence":0`},
				{`"sequence":18446744073709551615`, `"sequence":18446744073709551616`},
				{`"sequence":18446744073709551615`, `"sequence":1e2`},
				{`"sequence":18446744073709551615`, `"sequence":1,"sequence":1`},
				{`"challenge":"` + request.IsolationRequest.Challenge + `"`, `"challenge":null`},
				{`"armDigest":"`, `"extra":null,"armDigest":"`},
				{`"operationUUID":"` + request.IsolationRequest.OperationUUID + `"`, `"operationUUID":"INVALID"`},
				{`"version":`, `"extra":null,"version":`},
			} {
				bad := bytes.Replace(raw[4:], []byte(mutation[0]), []byte(mutation[1]), 1)
				if bytes.Equal(bad, raw[4:]) {
					t.Fatal("mutation missed", mutation)
				}
				if _, err := DecodeLifecycleFrame(bad); err == nil {
					t.Fatalf("accepted %s", bad)
				}
			}
			if _, err := DecodeLifecycleFrame(append(raw[4:], ' ')); err == nil {
				t.Fatal("noncanonical trailing space")
			}
		}
		for _, mutate := range []func(*s.IsolationProof){
			func(p *s.IsolationProof) { p.WorkerUUID = lifecycleTestID(t) },
			func(p *s.IsolationProof) { p.ServiceEpoch = lifecycleTestID(t) },
			func(p *s.IsolationProof) { p.Revision = 0 },
			func(p *s.IsolationProof) { p.Result = "success" },
			func(p *s.IsolationProof) { p.CaseName = "unknown" },
			func(p *s.IsolationProof) { p.RegistrySHA256 = strings.Repeat("G", 64) },
		} {
			bad := lifecycleIsolationProof(t, request, supervisor.ready)
			mutate(bad.IsolationProof)
			if _, err := EncodeLifecycleFrame(bad); err == nil {
				t.Fatal("invalid proof encoded")
			}
		}
		reply.Ready = copyLifecycleReady(supervisor.ready)
		if _, err := EncodeLifecycleFrame(reply); err == nil {
			t.Fatal("mixed reply bodies")
		}
		request.IsolationProof = reply.IsolationProof
		if _, err := EncodeLifecycleFrame(request); err == nil {
			t.Fatal("reply body in command")
		}
	}
}

func TestLifecycleIsolationSupervisorAdmission(t *testing.T) {
	supervisor, starter, _ := newTestLifecycleSupervisor(t)
	_, worker := starter.snapshot()
	calls := 0
	worker.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
		calls++
		return lifecycleIsolationProof(t, f, supervisor.ready), nil
	}
	for _, command := range []string{"isolation-state", "legacy-connection", "second-service-exclusivity"} {
		request := lifecycleIsolationRequest(t, supervisor.ready, command)
		reply, code := supervisor.dispatch(request)
		if pc.CurrentProfile() == pc.FullProfile && command != "second-service-exclusivity" {
			if code != "" || !validLifecycleIsolationReply(request, reply) {
				t.Fatal("valid reply refused", code)
			}
		} else if code != "command" || reply != nil {
			t.Fatal("unsupported execution admitted", command, code)
		}
	}
	want := 0
	if pc.CurrentProfile() == pc.FullProfile {
		want = 2
	}
	if calls != want {
		t.Fatal("forbidden worker IO", calls)
	}
	// Worker must also refuse before touching a service in ordinary builds;
	// second-service is always supervisor-only, including full profile.
	for _, command := range []string{"isolation-state", "legacy-connection", "second-service-exclusivity"} {
		if pc.CurrentProfile() == pc.FullProfile && command != "second-service-exclusivity" {
			continue
		}
		r := lifecycleWorkerCommand(nil, lifecycleIsolationRequest(t, supervisor.ready, command))
		if r.Code != "command" || r.IsolationProof != nil {
			t.Fatal("worker executed forbidden probe")
		}
	}
}

func TestLifecycleIsolationSupervisorRejectsUnboundProof(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full-profile proof validation")
	}
	for name, mutate := range map[string]func(*LifecycleFrame){
		"request":   func(r *LifecycleFrame) { r.IsolationProof.Request.RequestID = lifecycleTestID(t) },
		"operation": func(r *LifecycleFrame) { r.IsolationProof.Request.OperationUUID = lifecycleTestID(t) },
		"challenge": func(r *LifecycleFrame) { r.IsolationProof.Request.Challenge = lifecycleTestID(t) },
		"digest":    func(r *LifecycleFrame) { r.IsolationProof.Request.ArmDigest = lifecycleTestHex(t) },
		"store":     func(r *LifecycleFrame) { r.IsolationProof.Store = lifecycleTestID(t) },
		"case": func(r *LifecycleFrame) {
			r.IsolationProof.CaseName, r.IsolationProof.Result = "second-service-exclusivity", "second-owner-locked"
		},
		"mixed":   func(r *LifecycleFrame) { yes := true; r.OK = &yes },
		"binding": func(r *LifecycleFrame) { r.Binding.GuestBootNonce = lifecycleTestID(t) },
	} {
		t.Run(name, func(t *testing.T) {
			supervisor, starter, _ := newTestLifecycleSupervisor(t)
			_, worker := starter.snapshot()
			worker.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
				r := lifecycleIsolationProof(t, f, supervisor.ready)
				mutate(r)
				return r, nil
			}
			if r, code := supervisor.dispatch(lifecycleIsolationRequest(t, supervisor.ready, "isolation-state")); r != nil || code == "" {
				t.Fatal("unbound proof accepted")
			}
		})
	}
}

// Host component coverage: real v2 constructor + packet worker + actual joined
// TCP DATA handler. This is not Linux pidfd/native VM acceptance.
func TestLifecycleIsolationActualServiceVertical(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full-profile actual service observations")
	}
	for _, eofOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined-data", true: "EOF-is-not-proof"}[eofOnly], func(t *testing.T) {
			root, err := os.Open(t.TempDir())
			must(t, err)
			defer root.Close()
			cfg, _ := lifecycleTestConfig(t)
			ip := &inProcessLifecycle{}
			start := ip.starter(root, lifecycleTestBinding(), func() error { return nil }, func(service *s.LifecycleService) (func() error, error) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				if err = service.BindCompatibilityDataListener(listener.Addr()); err != nil {
					_ = listener.Close()
					return nil, err
				}
				joined := make(chan struct{})
				go func() {
					defer close(joined)
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						if eofOnly {
							_ = conn.Close()
						} else {
							_ = service.ServeDataConnection(context.Background(), conn)
						}
					}
				}()
				return func() error { err := listener.Close(); <-joined; return err }, nil
			})
			supervisor, err := newLifecycleSupervisor(cfg, start)
			must(t, err)
			defer func() { must(t, supervisor.close()); ip.wg.Wait() }()
			observe := func(command string) (*LifecycleFrame, string) {
				return supervisor.dispatch(lifecycleIsolationRequest(t, supervisor.ready, command))
			}
			before, code := observe("isolation-state")
			if code != "" || before == nil || before.Code != "" || before.IsolationProof == nil {
				t.Fatal("state", code, before)
			}
			legacy, code := observe("legacy-connection")
			if code != "" || legacy == nil {
				t.Fatal("legacy dispatch", code)
			}
			if eofOnly {
				if legacy.Code != "command" || legacy.IsolationProof != nil {
					t.Fatal("EOF manufactured proof")
				}
			} else if legacy.Code != "" || legacy.IsolationProof == nil || legacy.IsolationProof.Result != "legacy-tls-header-rejected" {
				t.Fatal("real DATA rejection missing", legacy)
			}
			after, code := observe("isolation-state")
			if code != "" || after == nil || after.IsolationProof == nil {
				t.Fatal("state after", code)
			}
			if before.IsolationProof.RegistrySHA256 != after.IsolationProof.RegistrySHA256 || before.IsolationProof.Revision != after.IsolationProof.Revision {
				t.Fatal("probe changed registry")
			}
			if r, code := observe("second-service-exclusivity"); r != nil || code != "command" {
				t.Fatal("missing challenger was accepted")
			}
			if lifecycleWorkerExited(supervisor.worker) {
				t.Fatal("original worker was terminated")
			}
		})
	}
}
