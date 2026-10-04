package storagebootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
)

// Actual authority, own-key certificates and TLS, not a supplied client/result.
func lifecycleWorkloadFixture(t *testing.T, takeover bool, barrier ...func(a.Binding, *os.File) error) (*lifecycleSessionFixture, c.PKILifecycleWorkloadServerConfig) {
	t.Helper()
	f := newLifecycleSessionFixture(t, takeover, barrier...)
	key, err := p.NewServerKey()
	check(t, err)
	binding, err := p.NewServerBinding(p.StoreID(f.cfg.store), p.ServiceEpoch(f.authority.Epoch()))
	check(t, err)
	csr, err := key.CSR(binding)
	check(t, err)
	cert, err := f.issuer.IssueServer(csr, binding, f.now, time.Hour)
	check(t, err)
	identity, err := cert.WithKey(key)
	check(t, err)
	f.boot.serverPin, err = key.Fingerprint()
	check(t, err)
	sc := c.LifecycleServerConfig{Identity: identity, ClientRoot: f.issuer.Root(), ServiceEpoch: f.authority.Epoch(), CurrentGrant: f.initial.Grant, ControllerKey: f.initialPin}
	if takeover {
		sc.SuccessorGrant, sc.SuccessorKey = f.owner.Grant, lifecycleSessionPin(t, f.s)
	}
	f.server, err = c.NewLifecycleServer(f.authority, sc)
	check(t, err)
	f.connect(t)
	return f, c.PKILifecycleWorkloadServerConfig{Identity: identity, ClientRoot: f.issuer.Root(), LifecycleIdentity: f.owner.Grant.Identity, ServiceEpoch: f.authority.Epoch(), CurrentController: a.Controller{Epoch: f.cfg.expectedEpoch + 1, Key: f.owner.Grant.NewKey}}
}

func connectLifecycleWorkload(t *testing.T, f *lifecycleSessionFixture, cfg c.PKILifecycleWorkloadServerConfig) net.Conn {
	t.Helper()
	server, err := c.NewPKILifecycleWorkloadServer(f.authority, cfg)
	check(t, err)
	left, right := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), left) }()
	t.Cleanup(func() {
		right.Close()
		left.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("workload server hung")
		}
	})
	_, err = f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("connect-workload", nil), right)
	check(t, err)
	return left
}

func TestLifecycleWorkloadPrivateCurrentOwnerAndOrdinaryCommands(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		t.Run(map[bool]string{false: "initialize", true: "takeover"}[takeover], func(t *testing.T) {
			f, cfg := lifecycleWorkloadFixture(t, takeover)
			left, right := net.Pipe()
			if err := f.s.connectWorkload(t.Context(), right); err == nil {
				t.Fatal("connected without ROOT boot result")
			}
			if _, err := left.Write([]byte{1}); err == nil {
				t.Fatal("rejected stream leaked")
			}
			left.Close()
			if takeover {
				if _, err := f.s.proof(t.Context(), f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant)); err == nil {
					t.Fatal("unapplied takeover result")
				}
				check(t, f.s.takeover(t.Context()))
			}
			lifecycleSessionProof(t, f, f.challenge(t, 4, p.LifecycleChildResult, f.owner.Grant))
			old := connectLifecycleWorkload(t, f, cfg)
			connectLifecycleWorkload(t, f, cfg)
			old.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := old.Read(make([]byte, 1)); err == nil {
				t.Fatal("old connection retained")
			}
			call := func(request c.Request) c.Response {
				raw, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("workload-command", lifecyclePrivateBody(t, request)), nil)
				check(t, err)
				var response c.Response
				check(t, json.Unmarshal(raw, &response))
				return response
			}
			created := call(c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: lifecycleSessionID(t), Store: f.cfg.store, Volume: lifecycleSessionID(t), Name: "child-workload"}})
			if created.VolumeReceipt == nil || created.VolumeReceipt.Schema != a.SchemaVersion {
				t.Fatal("no schema3 volume receipt", string(lifecyclePrivateBody(t, created)))
			}
			response := call(c.Request{Query: &c.Empty{}})
			if response.Snapshot == nil || response.Snapshot.Schema != a.LifecycleSchemaVersion || response.LifecycleIdentity == nil || *response.LifecycleIdentity != cfg.LifecycleIdentity || response.Snapshot.Controller != cfg.CurrentController {
				t.Fatal("not actual v3 snapshot")
			}
			deleted := call(c.Request{DeleteVolume: &a.DeleteVolumeRequest{Operation: lifecycleSessionID(t), Store: f.cfg.store, Volume: created.VolumeReceipt.Volume.ID}})
			if deleted.VolumeReceipt == nil {
				t.Fatal("no deletion receipt")
			}
			f.s.close()
			if _, err := f.s.workloadCommand(t.Context(), c.Request{Query: &c.Empty{}}); err == nil {
				t.Fatal("closed owner allowed query")
			}
		})
	}
}

func TestLifecycleWorkloadFreshResultNotCachedAfterSealOrLoss(t *testing.T) {
	for _, seal := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport-loss", true: "sealed"}[seal], func(t *testing.T) {
			f, _ := lifecycleWorkloadFixture(t, false)
			lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
			if seal {
				check(t, f.server.ArmRetirement(f.retirement.Grant))
				check(t, f.s.bindRetire(f.retirement))
				check(t, f.s.retire(t.Context()))
			} else {
				f.peer.Close()
			}
			left, right := net.Pipe()
			defer left.Close()
			if err := f.s.connectWorkload(t.Context(), right); err == nil {
				t.Fatal("cached current result admitted workload")
			}
			if _, err := left.Write([]byte{1}); err == nil {
				t.Fatal("rejected stream retained")
			}
		})
	}
}

func TestLifecycleWorkloadClosedPrivateCommandsAndBounds(t *testing.T) {
	f := newLifecycleSessionIntent(t, false)
	for _, raw := range []string{`{"id":0,"takeover":{}}`, `{"id":1,"query":{}}`, `{"id":0,"query":{},"retire":{}}`, `{"id":0,"method":"query"}`, `{"id":0,"query":{"receipt":{}}}`} {
		if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("workload-command", []byte(raw)), nil); err == nil {
			t.Fatal("bad request admitted", raw)
		}
	}
	for _, op := range []string{"connect-boot", "connect-workload"} {
		if !lifecycleStreamOperation(op) {
			t.Fatal("missing stream marker")
		}
		if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand(op, nil), nil); err == nil {
			t.Fatal("missing descriptor accepted")
		}
	}
	request := lifecyclePrivateCommand("workload-command", json.RawMessage(`{"id":0,"query":{}}`))
	var decoded lifecyclePrivateRequest
	check(t, decodeLifecyclePrivateRequest(lifecyclePrivateBody(t, request), &decoded))
	request.Body = json.RawMessage(`{"id":0,"create_volume":{"name":"` + strings.Repeat("x", 70<<10) + `"}}`)
	check(t, decodeLifecyclePrivateRequest(lifecyclePrivateBody(t, request), &decoded))
	request.Operation = "connect-boot"
	if decodeLifecyclePrivateRequest(lifecyclePrivateBody(t, request), &decoded) == nil {
		t.Fatal("large nonworkload bypass")
	}
	if decodeLifecyclePrivateRequest(bytes.Repeat([]byte{'x'}, lifecycleWorkloadRequestLimit+1), &decoded) == nil {
		t.Fatal("oversize request")
	}
	if err := writeLifecyclePrivateReply(&bytes.Buffer{}, struct {
		Data []byte `json:"data"`
	}{make([]byte, lifecycleWorkloadResponseLimit+1024)}, true); err == nil {
		t.Fatal("oversize reply")
	}
}

func TestLifecycleWorkloadCanonicalRequestBoundary(t *testing.T) {
	request := lifecyclePrivateCommand("workload-command", json.RawMessage(`{"id":0,"create_volume":{"name":""}}`))
	base := len(lifecyclePrivateBody(t, request))
	for _, extra := range []int{0, 1} {
		request.Body = json.RawMessage(`{"id":0,"create_volume":{"name":"` + strings.Repeat("x", lifecycleWorkloadRequestLimit-base+extra) + `"}}`)
		raw := lifecyclePrivateBody(t, request)
		if len(raw) != lifecycleWorkloadRequestLimit+extra {
			t.Fatal("boundary fixture")
		}
		var decoded lifecyclePrivateRequest
		err := decodeLifecyclePrivateRequest(raw, &decoded)
		if (err == nil) != (extra == 0) {
			t.Fatal("wrong canonical frame boundary", extra, err)
		}
	}
}

func TestLifecycleWorkloadCloseInterruptsHandshake(t *testing.T) {
	f, _ := lifecycleWorkloadFixture(t, false)
	lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
	left, right := net.Pipe()
	defer left.Close()
	done := make(chan error, 1)
	go func() { done <- f.s.connectWorkload(t.Context(), right) }()
	// Reading the TLS header proves fresh Result completed and the new client
	// entered its actual handshake. The peer intentionally supplies no server.
	left.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := left.Read(make([]byte, 1)); err != nil {
		t.Fatal("no TLS handshake", err)
	}
	f.s.close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked handshake published client")
		}
	case <-time.After(time.Second):
		t.Fatal("session close failed to interrupt handshake")
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.workload != nil {
		t.Fatal("client published after revocation")
	}
}
