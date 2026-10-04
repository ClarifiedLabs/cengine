package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func handoffBootConfig(t *testing.T) LifecycleConfiguration {
	cfg, _ := lifecycleTestConfig(t)
	cfg.Signed.Grant.Serial = 1
	b, err := a.LifecycleGrantSigningBytes(cfg.Signed.Grant)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signed.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), b)
	return cfg
}

func handoffBootCommand(t *testing.T, ready *LifecycleReady, previous, pending a.LifecycleGrant) *LifecycleFrame {
	f := lifecycleSupervisorCommand(ready, "fence-handoff")
	r := a.LifecycleHandoffRequest{OperationID: a.ID(lifecycleTestID(t)), Predecessor: previous, Pending: pending, ServiceEpoch: a.ID(ready.ServiceEpoch), OpenRevision: ready.OpenRevision}
	b, err := a.LifecycleHandoffSigningBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	f.Handoff = &a.SignedLifecycleHandoff{Request: r, Signature: ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), b)}
	f.Nonce = bytes.Repeat([]byte{3}, 32)
	return f
}

func TestLifecycleHandoffWorkerWire(t *testing.T) {
	cfg := handoffBootConfig(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ip := &inProcessLifecycle{}
	supervisor, err := newLifecycleSupervisor(cfg, ip.starter(root, lifecycleTestBinding(), func() error { return nil }, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = supervisor.close(); ip.wg.Wait() }()
	pending, _ := lifecycleTakeover(t, cfg, 1)
	request := handoffBootCommand(t, supervisor.ready, cfg.Signed.Grant, pending.Grant)
	for i := 0; i < 2; i++ {
		request.Nonce = bytes.Repeat([]byte{byte(i)}, 32)
		packet, err := lifecycleFramePacket(request)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := readLifecycleFramePacket(packet)
		if err != nil {
			t.Fatal(err)
		}
		reply, code := supervisor.command(decoded)
		if code != "" || reply.Code != "" || reply.HandoffResult == nil {
			t.Fatalf("%+v %s", reply, code)
		}
		packet, err = lifecycleFramePacket(reply)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readLifecycleFramePacket(packet)
		if err != nil || got.HandoffResult.Result.AppliedGrant != cfg.Signed.Grant || !bytes.Equal(got.HandoffResult.Result.Nonce, request.Nonce) || got.HandoffResult.Result.FenceRevision != 2 {
			t.Fatal("wrong worker receipt", got, err)
		}
	}
	bad := *request
	bad.Command = "query"
	if _, err := lifecycleFramePacket(&bad); err == nil {
		t.Fatal("ordinary query accepted handoff fields")
	}
	bad = *request
	bad.Nonce = nil
	if _, err := lifecycleFramePacket(&bad); err == nil {
		t.Fatal("missing nonce")
	}
}

func TestLifecycleSupervisorHandoffRetainsOnlyExactSignedOutcome(t *testing.T) {
	for _, phase := range []string{"predecessor", "pending", "reconciled"} {
		t.Run(phase, func(t *testing.T) {
			cfg := handoffBootConfig(t)
			starter := &fakeLifecycleStarter{}
			s, err := newLifecycleSupervisor(cfg, starter.start(t))
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			_, w := starter.snapshot()
			pending, _ := lifecycleTakeover(t, cfg, 1)
			s.successor = &pending
			request := handoffBootCommand(t, s.ready, cfg.Signed.Grant, pending.Grant)
			actual := cfg.Signed
			appliedRevision := uint64(1)
			if phase != "predecessor" {
				actual, appliedRevision = pending, 2
			}
			next := copyLifecycleReady(s.ready)
			next.ControllerEpoch, next.ControllerKey, next.Revision = actual.Grant.ExpectedEpoch+1, string(actual.Grant.NewKey), 3
			if phase == "reconciled" {
				s.signed, s.successor, s.ready = pending, nil, copyLifecycleReady(next)
			}
			result := a.LifecycleHandoffResult{Request: request.Handoff.Request, Nonce: request.Nonce, AppliedGrant: actual.Grant, AppliedServiceEpoch: a.ID(next.ServiceEpoch), AppliedRevision: appliedRevision, FenceRevision: 3}
			w.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
				r := lifecycleSupervisorReply(f)
				if f.Command == "query" {
					r.Ready = next
				} else {
					r.HandoffResult = &LifecycleHandoffReply{Result: result, Ready: next}
				}
				return r, nil
			}
			if phase == "pending" {
				if _, code := s.command(lifecycleSupervisorCommand(s.ready, "query")); code != "command" {
					t.Fatal("query adopted unreconciled controller", code)
				}
			}
			for i := 0; i < 2; i++ {
				reply, code := s.command(request)
				if code != "" || reply.HandoffResult == nil || !lifecycleSignedEqual(s.signed, actual) || s.successor != nil || !reflect.DeepEqual(s.ready, next) {
					t.Fatal("handoff did not atomically retain exact signed outcome", code)
				}
			}
		})
	}
}

func TestLifecycleSupervisorHandoffRejectsUncorrelatedOrUnsignedOutcome(t *testing.T) {
	for _, kind := range []string{"signature", "nonce", "open", "tls", "unretained-signature", "wrong-operation"} {
		t.Run(kind, func(t *testing.T) {
			cfg := handoffBootConfig(t)
			starter := &fakeLifecycleStarter{}
			s, err := newLifecycleSupervisor(cfg, starter.start(t))
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			_, w := starter.snapshot()
			pending, _ := lifecycleTakeover(t, cfg, 1)
			s.successor = &pending
			request := handoffBootCommand(t, s.ready, cfg.Signed.Grant, pending.Grant)
			next := copyLifecycleReady(s.ready)
			next.ControllerEpoch, next.ControllerKey, next.Revision = 2, string(pending.Grant.NewKey), 3
			result := a.LifecycleHandoffResult{Request: request.Handoff.Request, Nonce: bytes.Clone(request.Nonce), AppliedGrant: pending.Grant, AppliedServiceEpoch: a.ID(next.ServiceEpoch), AppliedRevision: 2, FenceRevision: 3}
			switch kind {
			case "signature":
				request.Handoff.Signature = make([]byte, 64)
			case "nonce":
				result.Nonce[0] ^= 1
			case "open":
				next.OpenRevision++
			case "tls":
				next.ServerDER = []byte("other")
			case "unretained-signature":
				s.successor = nil
			case "wrong-operation":
				result.Request.OperationID = a.ID(lifecycleTestID(t))
			}
			before, signed := copyLifecycleReady(s.ready), copyLifecycleSigned(s.signed)
			w.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
				r := lifecycleSupervisorReply(f)
				r.HandoffResult = &LifecycleHandoffReply{Result: result, Ready: next}
				return r, nil
			}
			if _, code := s.command(request); code != "command" {
				t.Fatal("accepted", kind, code)
			}
			if !reflect.DeepEqual(before, s.ready) || !lifecycleSignedEqual(signed, s.signed) {
				t.Fatal("refusal changed cache")
			}
		})
	}
}
