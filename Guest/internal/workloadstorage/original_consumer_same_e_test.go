package workloadstorage

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"reflect"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	p "dev.cengine/guest/internal/storagepki"
	w "dev.cengine/guest/internal/storagewire"
)

// Only mount attestation is the existing private fixture. The retained Client,
// TLS identity, serializer, GETATTR request and transport closure are real.
// This peer is a wire fixture, NOT authority Admit/Retire or native evidence.
type originalClientAttachment struct {
	sessionAttachmentFake
	client *c.Client
}

func (m *originalClientAttachment) OriginalConsumerRootAttempt(ctx context.Context, h a.DataHello) (c.OriginalConsumerRootRequest, error) {
	return m.client.OriginalConsumerRootAttempt(ctx, h)
}

func sameEClientSession(t *testing.T, name string, blockNegative ...bool) (*Session, OriginalConsumerArm, *originalFactoryFake, *c.Client, <-chan w.Request, *tls.Config) {
	t.Helper()
	s, arm, f := originalInstalledSession(t)
	arm.Version, arm.CaseName = 4, name
	issuer := originalIssuer(t)
	e := s.entries[arm.TargetAttachment]
	csr, err := e.key.CSR(e.binding)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := issuer.IssueAttachment(csr, e.binding, time.Now().Add(-time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e.identity, err = cert.WithKey(e.key)
	if err != nil {
		t.Fatal(err)
	}
	s.root = issuer.Root()
	arm.LeafSHA256 = SpecificationDigest(cert.DER())
	sb, err := p.NewServerBinding(p.StoreID(arm.Scope.Store), p.ServiceEpoch(arm.Scope.ServiceEpoch))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := p.NewServerKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err = sk.CSR(sb)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := issuer.IssueServer(csr, sb, time.Now().Add(-time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	si, err := sc.WithKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := sk.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	s.peer = Peer{TLSRootDER: issuer.Root().DER(), ServerDER: sc.DER(), ServerKey: pin.String(), DataAddress: "127.0.0.1"}
	cfg, err := p.ClientTLSConfig(e.identity, issuer.Root(), sb, pin)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := p.ServerTLSConfig(si, issuer.Root())
	if err != nil {
		t.Fatal(err)
	}
	key, err := e.key.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	hello := a.DataHello{Epoch: a.ID(arm.Scope.ServiceEpoch), Binding: a.Binding{Store: a.ID(arm.Scope.Store), Volume: a.ID(e.slot.Volume), Attachment: a.ID(e.slot.Attachment), Container: a.ContainerID(arm.Scope.Container), Launch: a.ID(arm.Scope.Launch), Key: a.Fingerprint(key.String()), Role: a.RuntimeRole, Mode: a.Mode(e.slot.Mode)}}
	left, right := net.Pipe()
	transport, server := tls.Client(left, cfg), tls.Server(right, serverConfig)
	requests := make(chan w.Request, 2)
	joined := make(chan struct{})
	root := w.Entry{Node: 99, Generation: 1, Object: w.ObjectID{99}, Attr: w.Attr{Ino: 199, Mode: 0040755, Nlink: 1, BlockSize: 4096}}
	go func() {
		defer close(joined)
		defer right.Close()
		_ = right.SetDeadline(time.Now().Add(5 * time.Second))
		if err := w.WriteFrame(server, &w.ServerHello{Epoch: hello.Epoch, Version: w.Version, Profile: w.RequiredProfile()}); err != nil {
			return
		}
		var h w.ClientHello
		if w.ReadFrame(server, &h) != nil || h.Authority != hello {
			return
		}
		if w.WriteFrame(server, &w.RootReply{Root: root}) != nil {
			return
		}
		for i := 0; i < 2; i++ {
			var req w.Request
			if w.ReadFrame(server, &req) != nil {
				return
			}
			requests <- req
			if i == 1 && !(len(blockNegative) > 1 && blockNegative[1]) {
				if len(blockNegative) != 0 && blockNegative[0] {
					var next w.Request
					_ = w.ReadFrame(server, &next)
				}
				return
			} // remote closure only AFTER receiving the actual request
			if w.WriteFrame(server, &w.Reply{Sequence: req.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: root.Attr}}) != nil {
				return
			}
		}
		if len(blockNegative) > 1 && blockNegative[1] {
			var next w.Request
			_ = w.ReadFrame(server, &next) // retain the genuine original channel until cleanup
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := transport.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	client, err := c.New(c.Config{Conn: transport, TLSConfig: cfg, ServerPin: a.Fingerprint(pin.String()), Authority: hello, Version: w.Version, Profile: w.RequiredProfile(), SupportedCaps: 0x1ffffffffff, Limits: c.DefaultLimits(), Timeout: time.Second, Invalidate: func(context.Context, c.Notification) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); left.Close(); right.Close(); <-joined })
	e.attachment = &originalClientAttachment{sessionAttachmentFake: sessionAttachmentFake{done: make(chan struct{})}, client: client}
	return s, arm, f, client, requests, serverConfig
}

func armSameE(t *testing.T, s *Session, arm OriginalConsumerArm) OriginalConsumerEvidence {
	t.Helper()
	raw, _ := json.Marshal(arm)
	response, err := s.originalConsumerControl("original-consumer-arm", raw)
	if err != nil {
		t.Fatal(err)
	}
	var positive OriginalConsumerEvidence
	if originalDecode(response, &positive) != nil || positive.RootRequest == nil || positive.RootRequest.Node != 99 || positive.RootRequest.RequestSequence == 0 || positive.OriginalOperation != (OriginalOperation{Kind: "data-getattr-root", Sequence: 1, ErrorClass: "ok"}) {
		t.Fatal("not actual positive", string(response))
	}
	response, err = s.originalConsumerControl("original-consumer-begin", raw)
	if err != nil {
		t.Fatal(err)
	}
	var begun OriginalConsumerEvidence
	if originalDecode(response, &begun) != nil {
		t.Fatal("begin shape")
	}
	begun.Stage = positive.Stage
	if !reflect.DeepEqual(begun, positive) {
		t.Fatal("begin changed positive")
	}
	return positive
}

func TestOriginalConsumerSameEActualRetainedClient(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile")
	}
	for _, name := range []string{cc.SameE, "attachment-key-reuse", "delayed-registration"} {
		for _, preclose := range []bool{false, true} {
			t.Run(name+"/"+map[bool]string{false: "remote-close", true: "local-preclose"}[preclose], func(t *testing.T) {
				s, arm, f, client, requests, _ := sameEClientSession(t, name)
				positive := armSameE(t, s, arm)
				first := <-requests
				if first.Sequence != positive.RootRequest.RequestSequence {
					t.Fatal("positive sequence invented")
				}
				if preclose {
					client.Close()
				}
				raw, _ := json.Marshal(OriginalConsumerProbe{Arm: arm, Scope: arm.Scope, Peer: s.peer})
				response, err := s.originalConsumerControl("original-consumer-probe", raw)
				if preclose {
					if err == nil || !f.observer.stopped {
						t.Fatal("local preclose accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var result OriginalConsumerEvidence
				if originalDecode(response, &result) != nil {
					t.Fatal("bad evidence")
				}
				req := <-requests
				body, ok := req.Body.(w.GetAttrRequest)
				if !ok || uint64(body.Node) != result.RootRequest.Node || body.Handle != nil || req.Auth.Kind != w.NodeMetadataAuth || req.Sequence != result.RootRequest.RequestSequence || req.Sequence <= first.Sequence {
					t.Fatal("not actual retained operation")
				}
				if result.Stage != "original-data-attempt" || result.OriginalOperation != (OriginalOperation{Kind: "data-getattr-root", Sequence: 2, ErrorClass: "transport-failed"}) || result.FDSequence != 1 || result.FDOperation != "fsync-directory" || result.SignCount != 0 || result.ClientWrittenBytes != 0 || result.ClientPrefixBytes != 0 || result.LocalError != "" || result.ServerDER_SHA256 != SpecificationDigest(s.peer.ServerDER) || result.Scope != arm.Scope || f.observer.capture != nil {
					t.Fatal("false TLS/FD/admission evidence", result)
				}
				select {
				case <-s.entries[arm.TargetAttachment].attachment.Done():
					t.Fatal("waited for mount Done")
				default:
				}
				raw, _ = json.Marshal(OriginalConsumerPrefix{Arm: arm, ServerPrefixBytes: 1, ServerPrefixSHA256: arm.LeafSHA256})
				if _, err = s.originalConsumerControl("original-consumer-result", raw); err == nil {
					t.Fatal("sameE prefix accepted")
				}
			})
		}
	}
}

func TestOriginalConsumerSameEExactReconnect(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:2049")
	if err != nil {
		t.Skip("fixed production DATA port unavailable: ", err)
	}
	defer listener.Close()
	s, arm, f, _, requests, serverConfig := sameEClientSession(t, cc.SameEReconnect)
	positive := armSameE(t, s, arm)
	<-requests
	observed := make(chan w.ClientHello, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(raw, serverConfig)
		if w.WriteFrame(conn, &w.ServerHello{Epoch: f.observer.authority.Epoch, Version: w.Version, Profile: w.RequiredProfile()}) != nil {
			return
		}
		var hello w.ClientHello
		if w.ReadFrame(conn, &hello) == nil {
			observed <- hello
		}
	}()
	defer func() { listener.Close(); <-joined }()
	raw, _ := json.Marshal(OriginalConsumerProbe{Arm: arm, Scope: arm.Scope, Peer: s.peer})
	response, err := s.originalConsumerControl("original-consumer-probe", raw)
	if err != nil {
		t.Fatal(err)
	}
	var result OriginalConsumerEvidence
	if originalDecode(response, &result) != nil {
		t.Fatal("bad evidence")
	}
	select {
	case hello := <-observed:
		if hello.Authority != f.observer.authority || hello.Profile != w.RequiredProfile() {
			t.Fatal("mutated original Hello")
		}
	default:
		t.Fatal("no Hello")
	}
	if result.Hello == nil || *result.Hello != f.observer.authority || !reflect.DeepEqual(result.RootRequest, positive.RootRequest) || result.OriginalOperation != (OriginalOperation{Kind: "data-original-hello", Sequence: 2, ErrorClass: "peer-closed-before-root"}) || result.Stage != "original-owner-signed-flight" || result.SignCount != 1 || !pin(result.SignInputSHA256) || result.BytesWrittenAfterSign == 0 || result.ClientPrefixBytes != 0 || result.ClientPrefixSHA256 != "" || result.FDSequence != 1 {
		t.Fatal("wrong reconnect evidence", result)
	}
}

func TestOriginalConsumerSameEContractAndTrust(t *testing.T) {
	for _, name := range []string{cc.SameE, cc.SameEReconnect, "same-e-retained-fd", "cross-e-existing-data"} {
		arm := originalTestArm()
		arm.Version = 4
		arm.CaseName = name
		if arm.valid() != sameEOriginalCase(name) {
			t.Fatal("version4 widened", name)
		}
	}
	_, _, _, _, peer := originalIdentities(t)
	arm := originalTestArm()
	arm.Version = 4
	arm.CaseName = cc.SameE
	o := &originalConsumer{arm: arm, peer: peer}
	q := OriginalConsumerProbe{Arm: arm, Scope: arm.Scope, Peer: peer}
	if !o.validTrust(q) {
		t.Fatal("exact trust rejected")
	}
	q.Scope.ControllerEpoch++
	if o.validTrust(q) {
		t.Fatal("controller changed")
	}
	q.Scope = arm.Scope
	q.Peer.ServerDER = []byte("different")
	if o.validTrust(q) {
		t.Fatal("server changed")
	}
	raw, _ := json.Marshal(OriginalConsumerEvidence{Arm: arm, RootRequest: &OriginalRootRequest{Node: 99, RequestSequence: 1}})
	var evidence OriginalConsumerEvidence
	if originalDecode(raw, &evidence) != nil {
		t.Fatal("root request schema")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"rootRequest":{"node":99,"requestSequence":1}`), []byte(`"rootRequest":null`), 1),
		bytes.Replace(raw, []byte(`"node":99`), []byte(`"node":99,"node":99`), 1),
		bytes.Replace(raw, []byte(`"requestSequence":1`), []byte(`"requestSequence":null`), 1),
	} {
		if originalDecode(bad, &evidence) == nil {
			t.Fatal("open root request schema")
		}
	}
}

func TestOriginalConsumerSameEReleaseCancelsActualRequestAndJoins(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile")
	}
	s, arm, f, client, requests, _ := sameEClientSession(t, cc.SameE, true)
	armSameE(t, s, arm)
	<-requests
	raw, _ := json.Marshal(OriginalConsumerProbe{Arm: arm, Scope: arm.Scope, Peer: s.peer})
	result := make(chan error, 1)
	go func() { _, err := s.originalConsumerControl("original-consumer-probe", raw); result <- err }()
	<-requests // cancellation follows actual dispatch, not a fabricated attempt
	release, _ := json.Marshal(arm)
	if _, err := s.originalConsumerControl("original-consumer-release", release); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("cancellation published negative evidence")
	}
	if f.observer.file != nil || !f.observer.stopped || client.Err() == nil {
		t.Fatal("release did not join/clear")
	}
	select {
	case <-f.observer.done:
	default:
		t.Fatal("release skipped operation join")
	}
}

func TestOriginalConsumerSameETimeoutIsNotNegative(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile")
	}
	s, arm, f, _, requests, _ := sameEClientSession(t, cc.SameE, true)
	armSameE(t, s, arm)
	<-requests
	raw, _ := json.Marshal(OriginalConsumerProbe{Arm: arm, Scope: arm.Scope, Peer: s.peer})
	if _, err := s.originalConsumerControl("original-consumer-probe", raw); err == nil {
		t.Fatal("transport timeout became negative evidence")
	}
	<-requests
	if !f.observer.stopped || f.observer.file != nil {
		t.Fatal("timeout failed to release")
	}
}

func TestOriginalConsumerSameERequiresActualPositive(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile")
	}
	for _, name := range []string{cc.SameE, cc.SameEReconnect} {
		s, arm, f := originalInstalledSession(t)
		arm.Version = 4
		arm.CaseName = name
		raw, _ := json.Marshal(arm)
		if _, err := s.originalConsumerControl("original-consumer-arm", raw); err == nil || !f.observer.stopped {
			t.Fatal("FD/mock positive substituted for actual root", name)
		}
	}
}
