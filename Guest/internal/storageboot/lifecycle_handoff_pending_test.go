package storageboot

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageworker"
)

func TestLifecycleHandoffPendingReplyRecovery(t *testing.T) {
	for _, mode := range []string{"delayed", "busy", "command", "busy-sequence", "busy-binding", "unknown-code", "mixed-busy", "dropped", "malformed", "nonce", "sequence", "tls", "eof", "unknown-send"} {
		t.Run(mode, func(t *testing.T) {
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
			worker := supervisor.worker.(*lifecyclePacketWorker)
			before := copyLifecycleReady(supervisor.ready)
			replacement := lifecycleTestReplacement(t, supervisor, cfg)
			pending, _ := lifecycleTakeover(t, cfg, 1)
			request := handoffBootCommand(t, supervisor.ready, cfg.Signed.Grant, pending.Grant)
			originalNonce := bytes.Clone(request.Nonce)
			originalSend := worker.send
			var outstanding []byte
			sends, drains := 0, 0
			worker.sendFence = func(raw []byte, deadline time.Time) ([]byte, error) {
				sends++
				if time.Until(deadline) > lifecycleFenceReplyBudget {
					t.Fatal("unbounded fence")
				}
				if mode == "unknown-send" {
					return nil, os.ErrDeadlineExceeded
				}
				result, err := originalSend(raw)
				if err != nil {
					return nil, err
				}
				if sends == 1 {
					outstanding = bytes.Clone(result)
					decoded, err := readLifecycleFramePacket(result)
					if err != nil || decoded.HandoffResult == nil || decoded.HandoffResult.Result.FenceRevision != 2 {
						t.Fatal("fence not committed before deadline", err)
					}
					if mode == "busy" || mode == "command" || mode == "busy-sequence" || mode == "busy-binding" || mode == "unknown-code" || mode == "mixed-busy" {
						decoded.HandoffResult = nil
						decoded.Code = "worker-busy"
						if mode == "command" {
							decoded.Code = "command"
						}
						if mode == "busy-sequence" {
							*decoded.Sequence++
						}
						if mode == "busy-binding" {
							decoded.Binding.GuestBootNonce = lifecycleTestID(t)
						}
						outstanding, err = lifecycleFramePacket(decoded)
						if err != nil {
							t.Fatal(err)
						}
						if mode == "unknown-code" {
							outstanding = bytes.Replace(outstanding, []byte("worker-busy"), []byte("unknown-err"), 1)
						}
						if mode == "mixed-busy" {
							outstanding = bytes.Replace(outstanding, []byte(`"worker-busy"`), []byte(`"worker-busy","ok":true`), 1)
						}
					}
					return nil, &storageworker.ReplyPendingError{}
				}
				if drains < 2 {
					t.Fatal("resent before draining")
				}
				return result, nil
			}
			worker.receivePending = func(time.Time) ([]byte, error) {
				drains++
				if mode == "dropped" || drains == 1 {
					return nil, &storageworker.ReplyPendingError{}
				}
				switch mode {
				case "eof":
					return nil, io.EOF
				case "malformed":
					return []byte("bad packet"), nil
				case "nonce", "sequence", "tls":
					reply, err := readLifecycleFramePacket(outstanding)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "nonce" {
						reply.HandoffResult.Result.Nonce = bytes.Clone(request.Nonce)
					}
					if mode == "sequence" {
						*reply.Sequence++
					}
					if mode == "tls" {
						reply.HandoffResult.Ready.TLSRootDER = []byte("wrong TLS root")
					}
					return lifecycleFramePacket(reply)
				}
				return outstanding, nil
			}
			_, code := supervisor.command(request)
			if mode == "unknown-send" {
				if code != "worker-lost" || !supervisor.lost || worker.pendingFence != nil {
					t.Fatal("unknown send was recoverable", code)
				}
				return
			}
			if code != "worker-busy" || supervisor.lost || !supervisor.fencePending || worker.pendingFence == nil {
				t.Fatal("deadline became death", code)
			}
			// Retention owns the original bytes even when the host mutates its request.
			request.Nonce[0] ^= 1
			seq := uint64(99)
			request.Sequence = &seq
			if !bytes.Equal(worker.pendingFence.Nonce, originalNonce) || *worker.pendingFence.Sequence != 1 {
				t.Fatal("pending frame aliases caller")
			}
			if _, code := supervisor.command(lifecycleSupervisorCommand(before, "query")); code != "worker-busy" {
				t.Fatal("unrelated command admitted", code)
			}
			changed := handoffBootCommand(t, before, cfg.Signed.Grant, pending.Grant)
			if _, code := supervisor.command(changed); code != "worker-busy" || drains != 0 || sends != 1 {
				t.Fatal("changed signed tuple drained or sent", code)
			}
			if _, code := supervisor.replaceService(replacement); code != "worker-busy" {
				t.Fatal("replacement admitted", code)
			}
			if _, code := supervisor.command(request); code != "worker-busy" || sends != 1 {
				t.Fatal("receive deadline resent", code)
			}
			reply, code := supervisor.command(request)
			switch mode {
			case "delayed", "busy":
				if code != "" || reply == nil || reply.Code != "" || *reply.Sequence != seq || !bytes.Equal(reply.HandoffResult.Result.Nonce, request.Nonce) || reply.HandoffResult.Result.FenceRevision != 2 || sends != 2 || worker.sequence != 2 || worker.pendingFence != nil || supervisor.fencePending || supervisor.logicalHandoff != nil {
					t.Fatal("fresh replay failed", code, reply)
				}
				if supervisor.ready.WorkerUUID != before.WorkerUUID || supervisor.ready.ServiceEpoch != before.ServiceEpoch || !reflect.DeepEqual(supervisor.ready.ServerDER, before.ServerDER) || supervisor.worker != worker {
					t.Fatal("replaced worker/service")
				}
			case "dropped":
				if code != "worker-busy" || sends != 1 || supervisor.lost {
					t.Fatal("dropped receive triggered resend/death", code)
				}
			default:
				if code != "worker-lost" || !supervisor.lost || sends != 1 || !supervisor.fencePending || supervisor.logicalHandoff == nil {
					t.Fatal("invalid old reply recovered", mode, code)
				}
				if _, code := supervisor.replaceService(replacement); code != "worker-busy" {
					t.Fatal("unresolved fence allowed replacement", code)
				}
				if _, code := supervisor.command(lifecycleSupervisorCommand(before, "query")); code != "worker-lost" {
					t.Fatal("terminal fence allowed unrelated command", code)
				}
			}
			if mode == "delayed" || mode == "busy" || mode == "dropped" {
				if lifecycleWorkerExited(worker) || supervisor.closed {
					t.Fatal("deadline closed session or worker")
				}
			}
		})
	}
}

func TestLifecycleHandoffDirectErrorContract(t *testing.T) {
	for _, mode := range []string{"worker-busy", "command", "unknown", "mixed-busy", "binding", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			cfg := handoffBootConfig(t)
			starter := &fakeLifecycleStarter{}
			supervisor, err := newLifecycleSupervisor(cfg, starter.start(t))
			if err != nil {
				t.Fatal(err)
			}
			defer supervisor.close()
			_, worker := starter.snapshot()
			before := copyLifecycleReady(supervisor.ready)
			replacement := lifecycleTestReplacement(t, supervisor, cfg)
			pending, _ := lifecycleTakeover(t, cfg, 1)
			request := handoffBootCommand(t, before, cfg.Signed.Grant, pending.Grant)
			worker.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
				r := lifecycleSupervisorReply(f)
				r.Code = mode
				switch mode {
				case "mixed-busy":
					r.Code = "worker-busy"
					yes := true
					r.OK = &yes
				case "binding":
					r.Code = "worker-busy"
					r.Binding.GuestBootNonce = lifecycleTestID(t)
				case "sequence":
					r.Code = "worker-busy"
					sequence := *r.Sequence + 1
					r.Sequence = &sequence
				}
				return r, nil
			}
			reply, code := supervisor.command(request)
			if mode == "worker-busy" || mode == "command" {
				if code != "" || reply == nil || reply.Code != mode || reply.HandoffResult != nil {
					t.Fatal("closed code not preserved", code, reply)
				}
			} else if code == "" || reply != nil {
				t.Fatal("malformed error passed through", code, reply)
			}
			if !reflect.DeepEqual(supervisor.ready, before) {
				t.Fatal("error minted state")
			}
			if mode == "worker-busy" {
				if supervisor.lost || supervisor.fencePending || supervisor.logicalHandoff == nil {
					t.Fatal("typed busy lost logical fence or became terminal")
				}
				for attempt := 0; attempt < 8; attempt++ {
					request.Nonce = bytes.Repeat([]byte{byte(attempt + 4)}, 32)
					if reply, code := supervisor.command(request); code != "" || reply.Code != "worker-busy" {
						t.Fatal("typed busy could not retry", code)
					}
					if _, code := supervisor.command(lifecycleSupervisorCommand(before, "query")); code != "worker-busy" {
						t.Fatal("logical fence allowed unrelated command", code)
					}
					if _, code := supervisor.replaceService(replacement); code != "worker-busy" {
						t.Fatal("logical fence allowed replacement", code)
					}
				}
				changed := handoffBootCommand(t, before, cfg.Signed.Grant, pending.Grant)
				if _, code := supervisor.command(changed); code != "worker-busy" {
					t.Fatal("logical fence allowed different signed request", code)
				}
				// The retained signature must not alias the caller's slice.
				request.Handoff.Signature[0] ^= 1
				if _, code := supervisor.command(request); code != "worker-busy" {
					t.Fatal("logical fence allowed changed signature", code)
				}
				request.Handoff.Signature[0] ^= 1
				next := copyLifecycleReady(before)
				next.Revision = 2
				worker.respond = func(f *LifecycleFrame) (*LifecycleFrame, error) {
					r := lifecycleSupervisorReply(f)
					if f.Command == "query" {
						r.Ready = next
					} else {
						r.HandoffResult = &LifecycleHandoffReply{Ready: next, Result: a.LifecycleHandoffResult{
							Request: f.Handoff.Request, Nonce: bytes.Clone(f.Nonce), AppliedGrant: cfg.Signed.Grant,
							AppliedServiceEpoch: a.ID(before.ServiceEpoch), AppliedRevision: 1, FenceRevision: 2}}
					}
					return r, nil
				}
				request.Nonce = bytes.Repeat([]byte{99}, 32)
				if reply, code := supervisor.command(request); code != "" || reply.HandoffResult == nil || supervisor.logicalHandoff != nil || supervisor.fencePending {
					t.Fatal("fresh proof did not clear logical fence", code)
				}
				if _, code := supervisor.command(lifecycleSupervisorCommand(before, "query")); code != "" {
					t.Fatal("validated proof did not reopen unrelated admission", code)
				}
				if _, code := supervisor.replaceService(replacement); code != "" {
					t.Fatal("validated proof did not reopen replacement admission", code)
				}
			} else {
				if !supervisor.lost || !supervisor.fencePending || supervisor.logicalHandoff == nil {
					t.Fatal("error resolved fence")
				}
				if _, code := supervisor.command(request); code != "worker-lost" {
					t.Fatal("terminal error retried", code)
				}
				if _, code := supervisor.replaceService(replacement); code != "worker-busy" {
					t.Fatal("terminal fence allowed replacement", code)
				}
			}
		})
	}
}

func TestLifecycleNonFenceReceiveTimeoutStillFailsClosed(t *testing.T) {
	cfg := handoffBootConfig(t)
	starter := &fakeLifecycleStarter{}
	supervisor, err := newLifecycleSupervisor(cfg, starter.start(t))
	if err != nil {
		t.Fatal(err)
	}
	defer supervisor.close()
	_, worker := starter.snapshot()
	worker.respond = func(*LifecycleFrame) (*LifecycleFrame, error) { return nil, &storageworker.ReplyPendingError{} }
	if _, code := supervisor.command(lifecycleSupervisorCommand(supervisor.ready, "query")); code != "worker-lost" {
		t.Fatal(code)
	}
}
