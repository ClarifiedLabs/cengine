package storageboot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
)

const lifecycleFixturePath = "../../../Tests/Fixtures/storage-bootstrap/lifecycle-service-boot-v2.json"

func lifecycleTestBinding() diskbootstrap.StorageBinding {
	return diskbootstrap.StorageBinding{ShimLaunchUUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", GuestBootNonce: "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb", Ext4UUID: "cccccccc-cccc-1ccc-accc-cccccccccccc", Bytes: 104857600}
}
func lifecycleTestConfig(t *testing.T) (LifecycleConfiguration, p.Key) {
	t.Helper()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	key, err := p.NewControllerKey()
	if err != nil {
		t.Fatal(err)
	}
	finger, err := p.PublicKeyFingerprint(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	g := a.LifecycleGrant{Operation: a.LifecycleInitialize, ID: a.ID("dddddddd-dddd-4ddd-bddd-dddddddddddd"), Identity: a.LifecycleIdentity{Store: a.ID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), Generation: 9007199254740993, Binding: a.Fingerprint(strings.Repeat("a", 64))}, Serial: ^uint64(0), NewKey: a.Fingerprint(finger.String())}
	b, err := a.LifecycleGrantSigningBytes(g)
	if err != nil {
		t.Fatal(err)
	}
	return LifecycleConfiguration{"initialize", root.Public().(ed25519.PublicKey), a.SignedLifecycleGrant{Grant: g, Signature: ed25519.Sign(root, b)}, 1800000000, 3600, nil, nil, nil}, key
}
func TestLifecycleBootSharedFixture(t *testing.T) {
	if os.Getenv("UPDATE_LIFECYCLE_BOOT_FIXTURE") == "1" {
		root, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		cfg, _ := lifecycleTestConfig(t)
		b := lifecycleTestBinding()
		service, err := lifecycleConstruct(root, b, cfg, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		ready, err := lifecyclePublicReady(service, "ffffffff-ffff-4fff-9fff-ffffffffffff")
		if err != nil {
			t.Fatal(err)
		}
		h := lifecycleFrame("hello", b)
		c := lifecycleFrame("configure", b)
		c.Configuration = &cfg
		r := lifecycleFrame("ready", b)
		r.Ready = ready
		seq := ^uint64(0)
		q := lifecycleFrame("command", b)
		q.Sequence = &seq
		q.ServiceEpoch = ready.ServiceEpoch
		q.WorkerUUID = ready.WorkerUUID
		q.Command = "query"
		reply := lifecycleFrame("reply", b)
		reply.Sequence = &seq
		reply.ServiceEpoch = ready.ServiceEpoch
		reply.WorkerUUID = ready.WorkerUUID
		reply.Ready = ready
		open := lifecycleFrame("configure", b)
		openCfg := cfg
		openCfg.Action = "open"
		openCfg.Reopen = lifecycleTestReopen(t, cfg, ready)
		open.Configuration = &openCfg
		if err = service.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := lifecycleConstruct(root, b, openCfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		next := lifecycleFrame("ready", b)
		next.Ready, err = lifecyclePublicReady(reopened, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
		if err != nil {
			t.Fatal(err)
		}
		// Indices 7..15 freeze the same-worker replacement wire.
		one := uint64(1)
		scoped := func(op, command string) LifecycleFrame {
			f := lifecycleFrame(op, b)
			f.Sequence, f.ServiceEpoch, f.WorkerUUID, f.Command = &one, ready.ServiceEpoch, ready.WorkerUUID, command
			return f
		}
		request := LifecycleReplacementRequest{PredecessorWorkerUUID: ready.WorkerUUID, Configuration: openCfg}
		statusCommand := scoped("command", "service-status")
		statusReply := scoped("reply", "")
		statusReply.Status = &LifecycleServiceStatus{Phase: "worker-lost"}
		replace := scoped("command", "replace-service")
		replace.ReplacementRequest = &request
		replacementCommand := scoped("command", "replacement-status")
		pending, succeeded, failed := scoped("reply", ""), scoped("reply", ""), scoped("reply", "")
		pending.Replacement = &LifecycleReplacementStatus{Request: request, Phase: "pending"}
		succeeded.Replacement = &LifecycleReplacementStatus{Request: request, Phase: "succeeded", Ready: next.Ready}
		failed.Replacement = &LifecycleReplacementStatus{Request: request, Phase: "failed", Code: "worker-unreaped"}
		notifications := scoped("command", "notifications")
		reconcile := scoped("command", "reconcile-controller")
		reconcile.Controller = &a.Controller{Epoch: 1, Key: cfg.Signed.Grant.NewKey}
		reconcile.Signed = &cfg.Signed
		// Indices 16..17: notifications payload reply and a supervisor-internal code.
		notifyReply := scoped("reply", "")
		list := []a.DataHello{lifecycleTestNotification(ready)}
		notifyReply.Notifications = &list
		busy := scoped("reply", "")
		busy.Code = "worker-busy"
		var vectors []string
		for _, f := range []LifecycleFrame{h, c, r, q, reply, open, next, statusCommand, statusReply, replace, replacementCommand, pending, succeeded, failed, notifications, reconcile, notifyReply, busy} {
			raw, e := EncodeLifecycleFrame(&f)
			if e != nil {
				t.Fatal(e)
			}
			vectors = append(vectors, string(raw[4:]))
		}
		raw, _ := json.MarshalIndent(vectors, "", "  ")
		if err = os.WriteFile(lifecycleFixturePath, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(lifecycleFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []string
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 18 {
		t.Fatal("missing paired reopen vectors")
	}
	open, err := DecodeLifecycleFrame([]byte(vectors[5]))
	if err != nil {
		t.Fatal(err)
	}
	if open.Configuration.Reopen.Request.OperationID != "99999999-9999-4999-8999-999999999999" || open.Configuration.Reopen.Request.OperationID == string(open.Configuration.Signed.Grant.ID) {
		t.Fatal("reopen operation ID replaced by grant ID")
	}
	for _, v := range vectors {
		f, e := DecodeLifecycleFrame([]byte(v))
		if e != nil {
			t.Fatal(e)
		}
		out, e := EncodeLifecycleFrame(f)
		if e != nil || string(out[4:]) != v {
			t.Fatal("roundtrip", e)
		}
		for _, bad := range []string{" " + v, strings.Replace(v, `"version":`, `"unknown":true,"version":`, 1), strings.Replace(v, `"version":`, `"csr":null,"version":`, 1), strings.Replace(v, LifecycleBootVersion, "storage-boot.v2", 1)} {
			if _, e = DecodeLifecycleFrame([]byte(bad)); e == nil {
				t.Fatal("accepted malformed")
			}
		}
	}
}
func TestLifecycleReplacementWireClosed(t *testing.T) {
	raw, err := os.ReadFile(lifecycleFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []string
	if err = json.Unmarshal(raw, &vectors); err != nil || len(vectors) != 18 {
		t.Fatal("fixture", err)
	}
	frame := func(i int) *LifecycleFrame {
		f, e := DecodeLifecycleFrame([]byte(vectors[i]))
		if e != nil {
			t.Fatal(i, e)
		}
		return f
	}
	if f := frame(9); f.WorkerUUID != f.ReplacementRequest.PredecessorWorkerUUID || f.ServiceEpoch != f.ReplacementRequest.Configuration.Reopen.Request.Predecessor.Context.ServiceEpoch || f.WorkerUUID != frame(2).Ready.WorkerUUID {
		t.Fatal("replace-service not predecessor-bound")
	}
	if frame(12).Replacement.Ready.ServiceEpoch != frame(6).Ready.ServiceEpoch || frame(8).Status.Phase != "worker-lost" || frame(13).Replacement.Code != "worker-unreaped" {
		t.Fatal("replacement vectors")
	}
	initialize := frame(1).Configuration
	faults := map[string]func() *LifecycleFrame{
		"command missing worker":  func() *LifecycleFrame { f := frame(7); f.WorkerUUID = ""; return f },
		"reply missing worker":    func() *LifecycleFrame { f := frame(8); f.WorkerUUID = ""; return f },
		"invalid worker":          func() *LifecycleFrame { f := frame(3); f.WorkerUUID = "bad"; return f },
		"unknown status phase":    func() *LifecycleFrame { f := frame(8); f.Status.Phase = "lost"; return f },
		"status plus ok":          func() *LifecycleFrame { f := frame(8); yes := true; f.OK = &yes; return f },
		"status plus replacement": func() *LifecycleFrame { f := frame(8); f.Replacement = frame(11).Replacement; return f },
		"pending with ready":      func() *LifecycleFrame { f := frame(11); f.Replacement.Ready = frame(6).Ready; return f },
		"pending with code":       func() *LifecycleFrame { f := frame(11); f.Replacement.Code = "replacement-failed"; return f },
		"succeeded without ready": func() *LifecycleFrame { f := frame(12); f.Replacement.Ready = nil; return f },
		"succeeded with code":     func() *LifecycleFrame { f := frame(12); f.Replacement.Code = "worker-unreaped"; return f },
		"failed without code":     func() *LifecycleFrame { f := frame(13); f.Replacement.Code = ""; return f },
		"failed with ready":       func() *LifecycleFrame { f := frame(13); f.Replacement.Ready = frame(6).Ready; return f },
		"unknown replacement code": func() *LifecycleFrame {
			f := frame(13)
			f.Replacement.Code = "service"
			return f
		},
		"unknown replacement phase": func() *LifecycleFrame { f := frame(11); f.Replacement.Phase = "running"; return f },
		"replace worker mismatch":   func() *LifecycleFrame { f := frame(9); f.WorkerUUID = frame(6).Ready.WorkerUUID; return f },
		"replace epoch mismatch":    func() *LifecycleFrame { f := frame(9); f.ServiceEpoch = frame(6).Ready.ServiceEpoch; return f },
		"replace missing request":   func() *LifecycleFrame { f := frame(9); f.ReplacementRequest = nil; return f },
		"replace request on query": func() *LifecycleFrame {
			f := frame(9)
			f.Command = "query"
			return f
		},
		"request initialize": func() *LifecycleFrame {
			f := frame(9)
			f.ReplacementRequest.Configuration = *initialize
			return f
		},
		"request action initialize with reopen": func() *LifecycleFrame {
			f := frame(9)
			f.ReplacementRequest.Configuration.Action = "initialize"
			return f
		},
		"request invalid predecessor": func() *LifecycleFrame { f := frame(9); f.ReplacementRequest.PredecessorWorkerUUID = "bad"; return f },
		"status request initialize": func() *LifecycleFrame {
			f := frame(11)
			f.Replacement.Request.Configuration = *initialize
			return f
		},
		"reconcile without signed":     func() *LifecycleFrame { f := frame(15); f.Signed = nil; return f },
		"reconcile without controller": func() *LifecycleFrame { f := frame(15); f.Controller = nil; return f },
		"notifications with status":    func() *LifecycleFrame { f := frame(14); f.Status = frame(8).Status; return f },
		"notifications on command":     func() *LifecycleFrame { f := frame(14); f.Notifications = frame(16).Notifications; return f },
		"notifications plus ok":        func() *LifecycleFrame { f := frame(16); yes := true; f.OK = &yes; return f },
		"notifications plus code":      func() *LifecycleFrame { f := frame(16); f.Code = "worker-lost"; return f },
		"notifications oversize": func() *LifecycleFrame {
			f := frame(16)
			list := make([]a.DataHello, lifecycleMaxNotifications+1)
			for i := range list {
				list[i] = (*f.Notifications)[0]
			}
			f.Notifications = &list
			return f
		},
		"notification bad epoch": func() *LifecycleFrame { f := frame(16); (*f.Notifications)[0].Epoch = "bad"; return f },
		"notification bad role":  func() *LifecycleFrame { f := frame(16); (*f.Notifications)[0].Binding.Role = "owner"; return f },
		"notification runtime prepare": func() *LifecycleFrame {
			f := frame(16)
			(*f.Notifications)[0].Binding.Prepare = a.ID(lifecycleTestID(t))
			return f
		},
		"unknown code": func() *LifecycleFrame { f := frame(17); f.Code = "worker-gone"; return f },
	}
	if frame(17).Code != "worker-busy" || len(*frame(16).Notifications) != 1 {
		t.Fatal("notification/code vectors")
	}
	for _, code := range []string{"stale-worker", "worker-busy", "worker-lost", "replacement-conflict", "configuration", "binding-mismatch", "sequence", "command", "service", "invalid-frame"} {
		f := frame(17)
		f.Code = code
		if _, e := EncodeLifecycleFrame(f); e != nil {
			t.Fatal("rejected code", code)
		}
	}
	for _, bad := range []string{
		strings.Replace(vectors[16], `"notifications":[`, `"notifications":[null,`, 1),
		strings.Replace(vectors[16], `"notifications":[{`, `"notifications":[{"extra":1,`, 1),
		strings.Replace(vectors[16], `"mode":"read-write"`, `"mode":"read-write","unknown":true`, 1),
		strings.Replace(vectors[16], `"notifications":[`, `"notifications":null,"x":[`, 1),
		strings.Replace(vectors[17], `"code":"worker-busy"`, `"code":"worker-gone"`, 1),
		strings.Replace(vectors[17], `"code":"worker-busy"`, `"code":null`, 1),
	} {
		if _, e := DecodeLifecycleFrame([]byte(bad)); e == nil {
			t.Fatal("accepted malformed notification/code", bad)
		}
	}
	missing := frame(16)
	missing.Notifications = nil
	if _, e := EncodeLifecycleFrame(missing); e == nil {
		t.Fatal("accepted reply without result")
	}
	for name, fault := range faults {
		if _, e := EncodeLifecycleFrame(fault()); e == nil {
			t.Fatal("accepted", name)
		}
	}
	for i, bad := range map[int]string{
		8:  strings.Replace(vectors[8], `"phase":"worker-lost"`, `"phase":"worker-lost","scope":1`, 1),
		9:  strings.Replace(vectors[9], `"predecessor_worker_uuid":`, `"extra":true,"predecessor_worker_uuid":`, 1),
		11: strings.Replace(vectors[11], `"phase":"pending"`, `"phase":"pending","ready":null`, 1),
		13: strings.Replace(vectors[13], `"code":"worker-unreaped"`, `"code":null`, 1),
	} {
		if bad == vectors[i] {
			t.Fatal("fault not applied", i)
		}
		if _, e := DecodeLifecycleFrame([]byte(bad)); e == nil {
			t.Fatal("accepted nested malformed", i)
		}
	}
}
func TestLifecycleBootPrivateExchange(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	b := lifecycleTestBinding()
	cfg, key := lifecycleTestConfig(t)
	cfg.NowUnixSeconds = uint64(time.Now().Add(-time.Minute).Unix())
	owner := make(chan *s.LifecycleService, 1)
	host, guest := net.Pipe()
	defer host.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- lifecycleSessionInProcess(ctx, guest, root, b, func() error { return nil }, func(service *s.LifecycleService) (func() error, error) { owner <- service; return nil, nil }, time.Second)
	}()
	if _, err = ReadLifecycleFrame(host); err != nil {
		t.Fatal(err)
	}
	f := lifecycleFrame("configure", b)
	f.Configuration = &cfg
	if err = WriteLifecycleFrame(host, &f); err != nil {
		t.Fatal(err)
	}
	r, err := ReadLifecycleFrame(host)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ready.Identity != cfg.Signed.Grant.Identity || r.Ready.ControllerKey != string(cfg.Signed.Grant.NewKey) {
		t.Fatal("wrong ready")
	}
	cb, err := p.NewControllerBinding(p.StoreID(cfg.Signed.Grant.Identity.Store), 1)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := key.CSR(cb)
	if err != nil {
		t.Fatal(err)
	}
	seq := uint64(1)
	command := lifecycleFrame("command", b)
	command.Sequence = &seq
	command.ServiceEpoch = r.Ready.ServiceEpoch
	command.WorkerUUID = r.Ready.WorkerUUID
	command.Command = "issue-controller"
	command.CSR = csr
	if err = WriteLifecycleFrame(host, &command); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadLifecycleFrame(host)
	if err != nil || !lifecycleDER(reply.Certificate) || reply.WorkerUUID != r.Ready.WorkerUUID {
		t.Fatal("CSR", err)
	}

	service := <-owner
	cert, err := p.ParseCertificateDER(reply.Certificate, cb)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := cert.WithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := p.ParseRootDER(r.Ready.TLSRootDER)
	if err != nil {
		t.Fatal(err)
	}
	pinBytes, err := hex.DecodeString(r.Ready.ServerSPKI)
	if err != nil {
		t.Fatal(err)
	}
	var serverPin p.Fingerprint
	copy(serverPin[:], pinBytes)
	clientRaw, serverRaw := net.Pipe()
	tlsDone := make(chan error, 1)
	go func() { tlsDone <- service.ServeLifecycle(ctx, serverRaw) }()
	client, err := c.NewLifecycleClient(ctx, clientRaw, c.LifecycleClientConfig{Identity: credential, ServerRoot: ca, ServerKey: serverPin, Hello: c.LifecycleHello{Version: c.LifecycleControlVersion, Identity: r.Ready.Identity, ServiceEpoch: a.ID(r.Ready.ServiceEpoch), ControllerEpoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	workRaw, workServer := net.Pipe()
	workDone := make(chan error, 1)
	go func() { workDone <- service.ServeControl(ctx, workServer) }()
	workload, err := c.NewPKILifecycleWorkloadClient(ctx, workRaw, c.PKILifecycleWorkloadClientConfig{Identity: credential, ServerRoot: ca, ServerKey: serverPin, LifecycleIdentity: r.Ready.Identity, ServiceEpoch: a.ID(r.Ready.ServiceEpoch), CurrentController: a.Controller{Epoch: 1, Key: cfg.Signed.Grant.NewKey}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = workload.Call(ctx, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: a.ID(b.ShimLaunchUUID), Store: cfg.Signed.Grant.Identity.Store, Volume: a.ID(b.GuestBootNonce), Name: "anchor"}})
	if err != nil {
		t.Fatal(err)
	}
	seq++
	command.CSR = nil
	command.Command = "query"
	if err = WriteLifecycleFrame(host, &command); err != nil {
		t.Fatal(err)
	}
	queried, err := ReadLifecycleFrame(host)
	if err != nil || queried.Ready == nil || queried.Ready.OpenRevision != 1 || queried.Ready.Revision <= queried.Ready.OpenRevision {
		t.Fatal("query inferred anchor from mutable revision", err)
	}
	// service-status is answered by the PID1 supervisor, not the worker.
	seq++
	command.Command = "service-status"
	if err = WriteLifecycleFrame(host, &command); err != nil {
		t.Fatal(err)
	}
	if status, e := ReadLifecycleFrame(host); e != nil || status.Status == nil || status.Status.Phase != "ready" || status.WorkerUUID != r.Ready.WorkerUUID {
		t.Fatal("service-status not answered by supervisor", e)
	}
	_ = workload.Close()
	select {
	case <-workDone:
	case <-time.After(time.Second):
		t.Fatal("workload did not join")
	}
	receipt, err := client.Result(ctx, cfg.Signed.Grant, bytes.Repeat([]byte{9}, 32))
	if err != nil || receipt.Grant != cfg.Signed.Grant {
		t.Fatal("private CSR to actual lifecycle TLS", err)
	}
	_ = client.Close()
	select {
	case <-tlsDone:
	case <-time.After(time.Second):
		t.Fatal("TLS did not join")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle cancellation did not join")
	}
	// The boot session persists registry schema 4.
	state, err := os.ReadFile(filepath.Join(root.Name(), authorityName, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(state, []byte(`"schema":4`)) && !bytes.Contains(state, []byte(`"schema_version":4`)) {
		t.Fatalf("not schema4: %s", state)
	}
}
func TestLifecycleBootRefusesMountedAndPartialDeadline(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cfg, _ := lifecycleTestConfig(t)
	if _, err = lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { return errors.New("mounted") }); err == nil {
		t.Fatal("mounted initialized")
	}
	entries, _ := root.ReadDir(-1)
	if len(entries) != 0 {
		t.Fatal("mutated mounted disk")
	}
	h, g := net.Pipe()
	defer h.Close()
	defer g.Close()
	done := make(chan error, 1)
	go func() { _, e := readLifecycleCommand(g, 30*time.Millisecond); done <- e }()
	if _, err = h.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("partial frame accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("unbounded partial frame")
	}
}

func TestLifecycleBootRejectsSequenceAndBinding(t *testing.T) {
	for _, fault := range []string{"binding", "sequence", "epoch", "worker"} {
		t.Run(fault, func(t *testing.T) {
			root, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			cfg, _ := lifecycleTestConfig(t)
			b := lifecycleTestBinding()
			host, guest := net.Pipe()
			defer host.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- lifecycleSessionInProcess(ctx, guest, root, b, func() error { return nil }, nil, time.Second)
			}()
			if _, err = ReadLifecycleFrame(host); err != nil {
				t.Fatal(err)
			}
			config := lifecycleFrame("configure", b)
			config.Configuration = &cfg
			if err = WriteLifecycleFrame(host, &config); err != nil {
				t.Fatal(err)
			}
			ready, err := ReadLifecycleFrame(host)
			if err != nil {
				t.Fatal(err)
			}
			sequence := uint64(1)
			request := lifecycleFrame("command", b)
			request.Sequence = &sequence
			request.ServiceEpoch = ready.Ready.ServiceEpoch
			request.WorkerUUID = ready.Ready.WorkerUUID
			request.Command = "query"
			switch fault {
			case "binding":
				request.Binding.GuestBootNonce = b.ShimLaunchUUID
			case "sequence":
				sequence = 2
			case "epoch":
				request.ServiceEpoch = b.ShimLaunchUUID
			case "worker":
				request.WorkerUUID = b.ShimLaunchUUID
			}
			if err = WriteLifecycleFrame(host, &request); err != nil {
				t.Fatal(err)
			}
			if fault == "binding" || fault == "sequence" {
				// A local post-Ready frame fault refuses further commands,
				// but may not retire the service before actual owner EOF.
				_ = host.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			}
			reply, err := ReadLifecycleFrame(host)
			if fault == "epoch" || fault == "worker" {
				// Checked against the current worker by the supervisor.
				if err != nil || reply.Code != "stale-worker" {
					t.Fatal("stale pair accepted", err)
				}
				cancel()
			} else {
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatal("mismatched command accepted or retired without EOF", err)
				}
				_ = host.Close()
			}
			select {
			case err = <-done:
				if err == nil {
					t.Fatal("failure succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("failure did not close")
			}
		})
	}
	if lifecycleSessionInProcess(context.Background(), nil, nil, diskbootstrap.StorageBinding{}, nil, nil, time.Second) == nil {
		t.Fatal("nil connection accepted")
	}
}
