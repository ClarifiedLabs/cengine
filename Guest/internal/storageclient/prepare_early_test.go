//go:build cengine_prepare_early_compat

package storageclient

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func earlyClientWitness(t *testing.T, cfg *Config) *pc.Witness {
	t.Helper()
	cfg.Authority.Binding.Role = a.PrepareRole
	cfg.Authority.Binding.Prepare = testID('6')
	b := cfg.Authority.Binding
	sum := sha256.Sum256(cfg.TLSConfig.Certificates[0].Certificate[0])
	arm := pc.Arm{Version: 2, Profile: pc.EarlyProfile, RequestID: string(testID('7')), CaseName: "data-partial-frame", TargetAttachment: string(b.Attachment), Binding: pc.BootBinding{ShimLaunchUUID: string(b.Launch), GuestBootNonce: string(testID('8'))}, Scope: pc.Scope{Intent: string(testID('9')), Store: string(b.Store), ServiceEpoch: string(cfg.Authority.Epoch), ControllerEpoch: 1, ControllerKey: strings.Repeat("b", 64), Container: string(b.Container), ContainerInstance: string(testID('8')), Launch: string(b.Launch), Prepare: string(b.Prepare), SpecificationDigest: strings.Repeat("c", 64)}, Mounts: []pc.MountBinding{{Index: 0, Volume: string(b.Volume), Destination: "/data", Mode: "read-write"}}, Slots: []pc.Slot{{Volume: string(b.Volume), Attachment: string(b.Attachment), Role: "prepare", Mode: "read-write"}, {Volume: string(b.Volume), Attachment: string(testID('0')), Role: "runtime", Mode: "read-write"}}, Credentials: []pc.Credential{{Attachment: string(b.Attachment), Key: string(b.Key), CertificateSHA256: hex.EncodeToString(sum[:])}}}
	witness, err := pc.NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	if err = witness.AcceptPrepare(77); err != nil {
		t.Fatal(err)
	}
	cfg.PrepareCompatibility = witness
	return witness
}
func TestEarlyActualTLSFirstBeginPartialFiveJoinsObserver(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "written", true: "observer-error"}[fail], func(t *testing.T) { testEarlyActualTLSPartialFive(t, fail) })
	}
}
func testEarlyActualTLSPartialFive(t *testing.T, failObserver bool) {
	var witness *pc.Witness
	received := make(chan []byte, 1)
	closed := make(chan struct{})
	c := fixture(t, func(cfg *Config) { witness = earlyClientWitness(t, cfg) }, func(s *tls.Conn) {
		var req w.Request
		if err := w.ReadFrame(s, &req); err != nil {
			t.Error(err)
			return
		}
		if req.Sequence != 1 || req.Body.Operation() != w.OpOpenDir {
			t.Error("prior mounted DATA")
		}
		if err := w.WriteFrame(s, &w.Reply{Sequence: req.Sequence, Op: w.OpOpenDir, Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}}); err != nil {
			t.Error(err)
			return
		}
		prefix := make([]byte, 5)
		if _, err := io.ReadFull(s, prefix); err != nil {
			t.Error(err)
			return
		}
		received <- prefix
		rest, _ := io.ReadAll(s)
		if len(rest) != 0 {
			t.Error("full request or synthesized completion")
		}
		close(closed)
	})
	opened, err := c.Do(caller(c), 0, w.OpenDirRequest{Node: 99})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.Handle(opened.Handle)
	if err != nil {
		t.Fatal(err)
	}
	body := w.PrepareRequest{Node: 99, Handle: grant.Handle, Action: w.BeginCopy}
	returned := make(chan error, 1)
	go func() { _, err := c.Do(caller(c), 0, body); returned <- err }()
	prefix := <-received
	var expected bytes.Buffer
	authCaller := caller(c).caller
	request := w.Request{Sequence: 2, Auth: w.Auth{Kind: w.CallerAuth, Caller: &authCaller}, Body: body}
	if err := w.WriteFrame(&expected, &request); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prefix, expected.Bytes()[:5]) {
		t.Fatal("not actual codec prefix")
	}
	var o pc.EarlyObservation
	select {
	case o = <-witness.EarlyObservations():
	case <-time.After(3 * time.Second):
		t.Fatal("missing evidence")
	}
	if o.RequestSequence != 2 || o.DataBytesWritten != 5 || pc.ValidateEarlyObservation(o) != nil {
		t.Fatal("wrong evidence")
	}
	select {
	case <-closed:
		t.Fatal("closed before observer write joined")
	case <-returned:
		t.Fatal("returned before write joined")
	default:
	}
	var observerErr error
	if failObserver {
		observerErr = errors.New("observer write failed")
	}
	if !witness.ObservationWritten(observerErr) {
		t.Fatal("observer ack")
	}
	if err := <-returned; err == nil {
		t.Fatal("early succeeded")
	}
	<-closed
	waitTerminal(t, c)
	if witness.NormalObservationWritten() {
		t.Fatal("early normal success")
	}
}

type earlyFailConn struct {
	net.Conn
	fail atomic.Bool
}

func (c *earlyFailConn) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("transport write failed")
	}
	return c.Conn.Write(b)
}
func TestEarlyTLSFailedWriteHasNoEvidence(t *testing.T) {
	var transport *earlyFailConn
	var witness *pc.Witness
	c := fixtureWithClientConn(t, func(c net.Conn) net.Conn { transport = &earlyFailConn{Conn: c}; return transport }, func(cfg *Config) { witness = earlyClientWitness(t, cfg) }, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply { return w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}} })
	})
	opened, err := c.Do(caller(c), 0, w.OpenDirRequest{Node: 99})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.Handle(opened.Handle)
	if err != nil {
		t.Fatal(err)
	}
	transport.fail.Store(true)
	if _, err := c.Do(caller(c), 0, w.PrepareRequest{Node: 99, Handle: grant.Handle, Action: w.BeginCopy}); err == nil {
		t.Fatal("write succeeded")
	}
	select {
	case <-witness.EarlyObservations():
		t.Fatal("failed write evidence")
	default:
	}
	waitTerminal(t, c)
}
func TestEarlyDataFullAuthorityAndLeafComparison(t *testing.T) {
	cfg, _ := tlsPair(t)
	witness := earlyClientWitness(t, &cfg)
	der := cfg.TLSConfig.Certificates[0].Certificate[0]
	if witness.ValidateDataAuthority(cfg.Authority, der) != nil {
		t.Fatal("actual credentials")
	}
	for _, mutate := range []func(*a.DataHello){func(h *a.DataHello) { h.Epoch = testID('9') }, func(h *a.DataHello) { h.Binding.Store = testID('9') }, func(h *a.DataHello) { h.Binding.Volume = testID('9') }, func(h *a.DataHello) { h.Binding.Attachment = testID('9') }, func(h *a.DataHello) { h.Binding.Prepare = testID('9') }, func(h *a.DataHello) { h.Binding.Launch = testID('9') }, func(h *a.DataHello) { h.Binding.Container = a.ContainerID(strings.Repeat("d", 64)) }, func(h *a.DataHello) { h.Binding.Key = a.Fingerprint(strings.Repeat("d", 64)) }, func(h *a.DataHello) { h.Binding.Role = a.RuntimeRole }, func(h *a.DataHello) { h.Binding.Mode = a.ReadOnly }} {
		bad := cfg.Authority
		mutate(&bad)
		if witness.ValidateDataAuthority(bad, der) == nil || witness.ClaimPartialData(bad, der) == nil {
			t.Fatal("mismatch accepted")
		}
	}
	if witness.ValidateDataAuthority(cfg.Authority, append([]byte{0}, der...)) == nil {
		t.Fatal("wrong leaf")
	}
	if witness.ClaimPartialData(cfg.Authority, der) != nil || witness.ClaimPartialData(cfg.Authority, der) == nil {
		t.Fatal("one shot")
	}
}

func TestEarlyOtherPrepareActionDoesNotFire(t *testing.T) {
	var witness *pc.Witness
	c := fixture(t, func(cfg *Config) { witness = earlyClientWitness(t, cfg) }, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply {
			if req.Body.Operation() == w.OpOpenDir {
				return w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}}
			}
			return w.Reply{Body: w.PrepareReply{}}
		})
	})
	opened, err := c.Do(caller(c), 0, w.OpenDirRequest{Node: 99})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.Handle(opened.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Do(caller(c), 0, w.PrepareRequest{Node: 99, Handle: grant.Handle, Action: w.FinishCopy, Intent: testID('7')}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-witness.EarlyObservations():
		t.Fatal("wrong action fired")
	default:
	}
}
