package storageboot

import (
	"bytes"
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"dev.cengine/guest/internal/storageworker"
)

type handoffControlReadSignal struct {
	net.Conn
	once    sync.Once
	reading chan struct{}
}

func (c *handoffControlReadSignal) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(b)
}

func TestLifecycleHandoffWorkerReportsTypedBusy(t *testing.T) {
	cfg := handoffBootConfig(t)
	root := openRoot(t)
	service, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	ready, err := lifecyclePublicReady(service, lifecycleTestID(t))
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := lifecycleTakeover(t, cfg, 1)
	request := handoffBootCommand(t, ready, cfg.Signed.Grant, pending.Grant)
	host, guest := net.Pipe()
	conn := &handoffControlReadSignal{Conn: guest, reading: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = service.ServeControl(context.Background(), conn)
	}()
	defer func() { _ = host.Close(); _ = guest.Close(); <-done }()
	select {
	case <-conn.reading:
	case <-time.After(5 * time.Second):
		t.Fatal("CONTROL did not start")
	}
	// Real service contention must not collapse into generic command failure.
	reply := lifecycleWorkerCommand(service, request)
	if reply.Code != "worker-busy" || reply.HandoffResult != nil || reply.validate() != nil {
		t.Fatal("busy lost its typed contract", reply)
	}
	bad := *request
	// Copy the signed tuple before corrupting its signature.
	signed := *request.Handoff
	signed.Signature = make([]byte, len(signed.Signature))
	bad.Handoff = &signed
	if reply := lifecycleWorkerCommand(service, &bad); reply.Code != "command" || reply.HandoffResult != nil {
		t.Fatal("unknown failure became busy", reply)
	}
	_ = host.Close()
	_ = guest.Close()
	<-done
	reply = lifecycleWorkerCommand(service, request)
	if reply.Code != "" || reply.HandoffResult == nil || !bytes.Equal(reply.HandoffResult.Result.Nonce, request.Nonce) {
		t.Fatal("drained CONTROL could not produce exact proof", reply)
	}
}

func TestLifecycleHandoffPendingKeeps4106Session(t *testing.T) {
	for _, mode := range []string{"success", "late-busy", "late-command", "direct-busy", "direct-command"} {
		t.Run(mode, func(t *testing.T) { testLifecycleHandoff4106Session(t, mode) })
	}
}

func testLifecycleHandoff4106Session(t *testing.T, mode string) {
	cfg := handoffBootConfig(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ip := &inProcessLifecycle{}
	start := ip.starter(root, lifecycleTestBinding(), func() error { return nil }, nil)
	delayed := func(c LifecycleConfiguration, id string, gate workerStartGate) (lifecycleWorker, *LifecycleReady, error) {
		w, ready, err := start(c, id, gate)
		if err != nil {
			return w, ready, err
		}
		packet := w.(*lifecyclePacketWorker)
		send := packet.send
		var outstanding []byte
		first := true
		packet.sendFence = func(raw []byte, deadline time.Time) ([]byte, error) {
			reply, err := send(raw)
			if err != nil {
				return nil, err
			}
			if first {
				first = false
				if mode != "success" {
					frame, err := readLifecycleFramePacket(reply)
					if err != nil {
						return nil, err
					}
					frame.HandoffResult = nil
					frame.Code = "worker-busy"
					if mode == "late-command" || mode == "direct-command" {
						frame.Code = "command"
					}
					reply, err = lifecycleFramePacket(frame)
					if err != nil {
						return nil, err
					}
				}
				if mode == "direct-busy" || mode == "direct-command" {
					return reply, nil
				}
				outstanding = reply
				return nil, &storageworker.ReplyPendingError{}
			}
			return reply, nil
		}
		packet.receivePending = func(time.Time) ([]byte, error) { return outstanding, nil }
		return packet, ready, nil
	}
	host, guest := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- lifecycleSession(ctx, guest, lifecycleTestBinding(), delayed, 5*time.Second) }()
	defer func() { cancel(); _ = host.Close(); <-done; ip.wg.Wait() }()
	_ = host.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	configure := lifecycleFrame("configure", lifecycleTestBinding())
	configure.Configuration = &cfg
	if err := WriteLifecycleFrame(host, &configure); err != nil {
		t.Fatal(err)
	}
	ready, err := ReadLifecycleFrame(host)
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := lifecycleTakeover(t, cfg, 1)
	request := handoffBootCommand(t, ready.Ready, cfg.Signed.Grant, pending.Grant)
	seq := uint64(1)
	request.Sequence = &seq
	if err := WriteLifecycleFrame(host, request); err != nil {
		t.Fatal(err)
	}
	busy, err := ReadLifecycleFrame(host)
	expectedCode := "worker-busy"
	if mode == "direct-command" {
		expectedCode = "command"
	}
	if err != nil || busy.Code != expectedCode || busy.HandoffResult != nil {
		t.Fatal("4106 did not preserve closed error", err, busy)
	}
	seq = 2
	request.Nonce = bytes.Repeat([]byte{8}, 32)
	if err := WriteLifecycleFrame(host, request); err != nil {
		t.Fatal(err)
	}
	replay, err := ReadLifecycleFrame(host)
	if mode == "late-command" || mode == "direct-command" {
		if err != nil || replay.Code != "worker-lost" || replay.HandoffResult != nil {
			t.Fatal("4106 retried generic error", err, replay)
		}
		return
	}
	if err != nil || replay.Code != "" || replay.HandoffResult == nil || !bytes.Equal(replay.HandoffResult.Result.Nonce, request.Nonce) || replay.HandoffResult.Ready.WorkerUUID != ready.Ready.WorkerUUID {
		t.Fatal("4106 could not replay same worker", err, replay)
	}
	seq = 3
	query := lifecycleSupervisorCommand(ready.Ready, "query")
	query.Sequence = &seq
	if err := WriteLifecycleFrame(host, query); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadLifecycleFrame(host)
	if err != nil || reply.Code != "" || reply.Ready == nil || reply.Ready.ServiceEpoch != ready.Ready.ServiceEpoch {
		t.Fatal("4106 lost after replay", err, reply)
	}
}
