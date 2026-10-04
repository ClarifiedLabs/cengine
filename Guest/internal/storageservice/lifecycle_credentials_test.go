package storageservice

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

func lifecycleAttachmentFixture(t *testing.T) (*lifecycleFixture, p.Identity, Ready, a.DataHello, p.Key, []byte) {
	t.Helper()
	f := newLifecycleServiceFixture(t)
	identity := lifecycleCredential(t, f)
	ready, err := f.s.Ready()
	must(t, err)
	client, join := lifecycleWorkload(t, f.s, identity)
	volume := id(t)
	call(t, client, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: ready.Store.ID, Volume: volume, Name: "credential"}})
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	h := a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: id(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(t), Key: fingerprint(t, key), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	call(t, client, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: h.Binding}})
	client.Close()
	join()
	return f, identity, ready, h, key, lifecycleAttachmentCSR(t, key, h)
}
func lifecycleAttachmentCSR(t *testing.T, key p.Key, h a.DataHello) []byte {
	t.Helper()
	b, err := d.AttachmentBinding(h)
	must(t, err)
	csr, err := key.CSR(b)
	must(t, err)
	return csr
}
func lifecycleCredentialConn(t *testing.T, f *lifecycleFixture, identity p.Identity, ready Ready) (*tls.Conn, func() error) {
	t.Helper()
	raw, join := serve(t, f.s.ServeAttachmentCSR)
	root, err := p.ParseRootDER(ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	must(t, err)
	conn, err := p.NewControllerTLSClient(raw, identity, root, server, ready.ServerKey)
	must(t, err)
	must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	must(t, conn.HandshakeContext(t.Context()))
	return conn, join
}

func TestLifecycleAttachmentCSRActiveReservedAndStrictEnvelope(t *testing.T) {
	f, identity, ready, h, key, csr := lifecycleAttachmentFixture(t)
	request := lifecycleAttachmentCSRRequest{3, lifecycleCredentialHello(f.initial.Grant.Identity, ready.ServiceEpoch, 1), h, csr}
	for name, mutate := range map[string]func(*lifecycleAttachmentCSRRequest){
		"v1-envelope":      func(r *lifecycleAttachmentCSRRequest) { r.Version = 1 },
		"v2-control":       func(r *lifecycleAttachmentCSRRequest) { r.Controller.Version = 2 },
		"missing-identity": func(r *lifecycleAttachmentCSRRequest) { r.Controller.LifecycleIdentity = nil },
		"wrong-S":          func(r *lifecycleAttachmentCSRRequest) { r.Controller.LifecycleIdentity.Store = id(t) },
		"wrong-G":          func(r *lifecycleAttachmentCSRRequest) { r.Controller.LifecycleIdentity.Generation++ },
		"wrong-binding": func(r *lifecycleAttachmentCSRRequest) {
			r.Controller.LifecycleIdentity.Binding = f.initial.Grant.NewKey
		},
		"wrong-E":            func(r *lifecycleAttachmentCSRRequest) { r.Controller.ServiceEpoch = id(t) },
		"wrong-C":            func(r *lifecycleAttachmentCSRRequest) { r.Controller.ControllerEpoch++ },
		"successor-role":     func(r *lifecycleAttachmentCSRRequest) { r.Controller.Role = c.Successor },
		"wrong-attachment-E": func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Epoch = id(t) },
		"missing-binding":    func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Binding = a.Binding{} },
		"wrong-attachment-S": func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Binding.Store = id(t) },
		"wrong-container": func(r *lifecycleAttachmentCSRRequest) {
			r.Attachment.Binding.Container = a.ContainerID(strings.Repeat("b", 64))
		},
		"wrong-role": func(r *lifecycleAttachmentCSRRequest) {
			r.Attachment.Binding.Role = a.PrepareRole
			r.Attachment.Binding.Prepare = id(t)
		},
		"unregistered": func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Binding.Attachment = id(t) },
		"wrong-volume": func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Binding.Volume = id(t) },
		"wrong-launch": func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Binding.Launch = id(t) },
		"wrong-mode":   func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Binding.Mode = a.ReadOnly },
		"wrong-key":    func(r *lifecycleAttachmentCSRRequest) { r.Attachment.Binding.Key = f.initial.Grant.NewKey },
		"wrong-CSR-key": func(r *lifecycleAttachmentCSRRequest) {
			other, err := p.NewAttachmentKey(p.RuntimeRole)
			must(t, err)
			r.CSR = lifecycleAttachmentCSR(t, other, h)
		},
		"wrong-CSR-URI": func(r *lifecycleAttachmentCSRRequest) {
			other := h
			other.Binding.Launch = id(t)
			r.CSR = lifecycleAttachmentCSR(t, key, other)
		},
		"malformed-CSR": func(r *lifecycleAttachmentCSRRequest) { r.CSR = []byte("not DER") },
	} {
		t.Run(name, func(t *testing.T) {
			q := request
			scope := *request.Controller.LifecycleIdentity
			q.Controller.LifecycleIdentity = &scope
			mutate(&q)
			conn, join := lifecycleCredentialConn(t, f, identity, ready)
			must(t, writeCredential(conn, q))
			var reply lifecycleAttachmentCSRReply
			if readCredential(conn, &reply) == nil || len(reply.Certificate) != 0 {
				t.Fatal("issued rejected request")
			}
			conn.Close()
			if join() == nil {
				t.Fatal("server admitted bad request")
			}
		})
	}
	for _, malformed := range []string{`{"version":3,"version":3}`, `{"version":3,"authority":{}}`, `null`} {
		conn, join := lifecycleCredentialConn(t, f, identity, ready)
		must(t, writeCredential(conn, json.RawMessage(malformed)))
		var reply lifecycleAttachmentCSRReply
		if readCredential(conn, &reply) == nil {
			t.Fatal("malformed envelope admitted")
		}
		conn.Close()
		join()
	}
	issue := func(h a.DataHello, key p.Key) {
		raw, join := serve(t, f.s.ServeAttachmentCSR)
		cert, err := RequestLifecycleAttachmentCertificate(t.Context(), raw, identity, ready, f.initial.Grant.Identity, h, lifecycleAttachmentCSR(t, key, h))
		must(t, err)
		must(t, join())
		_, err = cert.WithKey(key)
		must(t, err)
	}
	issue(h, key)
	prepareKey, err := p.NewAttachmentKey(p.PrepareRole)
	must(t, err)
	prepare := h
	prepare.Binding.Role, prepare.Binding.Prepare, prepare.Binding.Attachment, prepare.Binding.Key = a.PrepareRole, id(t), id(t), fingerprint(t, prepareKey)
	client, join := lifecycleWorkload(t, f.s, identity)
	call(t, client, c.Request{ReservePrepare: &a.ReserveRequest{Operation: id(t), Prepare: prepare.Binding.Prepare, Attachments: []a.Binding{prepare.Binding}}})
	client.Close()
	join()
	issue(prepare, prepareKey)
}

func TestLifecycleAttachmentCSRCurrentControllerTLSOnly(t *testing.T) {
	f, identity, ready, h, _, csr := lifecycleAttachmentFixture(t)
	// Real legacy client is not negotiated/upgraded by the lifecycle endpoint.
	raw, join := serve(t, f.s.ServeAttachmentCSR)
	if cert, err := requestLegacyAttachmentCertificate(t.Context(), raw, identity, ready, h, csr); err == nil || len(cert.DER()) != 0 {
		t.Fatal("accepted legacy client")
	}
	if join() == nil {
		t.Fatal("server accepted v1")
	}
	for _, wrongEpoch := range []bool{false, true} {
		key, err := p.NewControllerKey()
		must(t, err)
		epoch := uint64(1)
		if wrongEpoch {
			epoch = 2
			key = f.key
		}
		binding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(epoch))
		must(t, err)
		cert, err := f.s.owner.issuer.IssueController(lifecycleCSR(t, key, ready.Store.ID, epoch), binding, f.cfg.Now, f.cfg.Lifetime)
		must(t, err)
		rogue, err := cert.WithKey(key)
		must(t, err)
		conn, join := lifecycleCredentialConn(t, f, rogue, ready)
		must(t, writeCredential(conn, lifecycleAttachmentCSRRequest{3, lifecycleCredentialHello(f.initial.Grant.Identity, ready.ServiceEpoch, 1), h, csr}))
		var reply lifecycleAttachmentCSRReply
		if readCredential(conn, &reply) == nil || len(reply.Certificate) != 0 {
			t.Fatal("CA-valid noncurrent controller issued certificate")
		}
		conn.Close()
		if join() == nil {
			t.Fatal("server admitted noncurrent key/C")
		}
	}
}

func TestLifecycleAttachmentCSRRejectsPendingAndSealed(t *testing.T) {
	for _, state := range []string{"takeover", "retirement", "sealed", "retired-or-draining"} {
		t.Run(state, func(t *testing.T) {
			f, identity, ready, h, _, csr := lifecycleAttachmentFixture(t)
			if state == "retired-or-draining" {
				client, join := lifecycleWorkload(t, f.s, identity)
				_, _ = client.Call(t.Context(), c.Request{Retire: &a.RetireRequest{Operation: id(t), Store: h.Binding.Store, Volume: h.Binding.Volume, Attachment: h.Binding.Attachment, Launch: h.Binding.Launch}})
				client.Close()
				join() // Darwin's real barrier remains blocked, never faked.
			} else if state == "takeover" {
				key, err := p.NewControllerKey()
				must(t, err)
				grant := a.LifecycleGrant{Operation: a.LifecycleTakeover, ID: id(t), Identity: f.initial.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: fingerprint(t, key)}
				_, err = f.s.AuthorizeSuccessor(lifecycleSign(t, f.root, grant), lifecycleCSR(t, key, ready.Store.ID, 2))
				must(t, err)
			} else {
				if state == "sealed" {
					// Empty store can seal on Darwin without pretending native drain succeeded.
					f = newLifecycleServiceFixture(t)
					identity = lifecycleCredential(t, f)
					var err error
					ready, err = f.s.Ready()
					must(t, err)
					h.Binding.Store, h.Epoch = ready.Store.ID, ready.ServiceEpoch
				}
				g := a.LifecycleGrant{Operation: a.LifecycleRetire, ID: id(t), Identity: f.initial.Grant.Identity, Serial: 2, ExpectedEpoch: 1, NewKey: f.initial.Grant.NewKey}
				signed := lifecycleSign(t, f.root, g)
				must(t, f.s.AuthorizeRetirement(signed))
				if state == "sealed" {
					client, join := lifecycleConnect(t, f.s, identity, 1)
					must(t, client.Retire(t.Context(), signed))
					client.Close()
					join()
				}
			}
			raw, join := serve(t, f.s.ServeAttachmentCSR)
			cert, err := RequestLifecycleAttachmentCertificate(t.Context(), raw, identity, ready, f.initial.Grant.Identity, h, csr)
			if err == nil || len(cert.DER()) != 0 {
				t.Fatal("issued nonlive state")
			}
			if join() == nil {
				t.Fatal("server allowed nonlive state")
			}
		})
	}
}

func TestLifecycleAttachmentCSRClientReplyAndTrust(t *testing.T) {
	f, identity, ready, h, key, csr := lifecycleAttachmentFixture(t)
	binding, err := d.AttachmentBinding(h)
	must(t, err)
	cert, err := f.s.owner.issuer.IssueAttachment(csr, binding, f.cfg.Now, f.cfg.Lifetime)
	must(t, err)
	for _, kind := range []string{"v1", "unknown", "duplicate", "truncated", "wrong-key", "wrong-binding", "wrong-pin", "wrong-root", "wrong-controller-key"} {
		t.Run(kind, func(t *testing.T) {
			r := ready
			if kind == "wrong-pin" {
				r.ServerKey[0] ^= 1
			}
			if kind == "wrong-root" {
				other := newLifecycleServiceFixture(t)
				otherReady, err := other.s.Ready()
				must(t, err)
				r.TLSRootDER = otherReady.TLSRootDER
			}
			if kind == "wrong-controller-key" {
				r.Controller.Key = h.Binding.Key
			}
			raw, join := serve(t, func(ctx context.Context, raw net.Conn) error {
				defer raw.Close()
				conn := tls.Server(raw, f.s.owner.credentialTLS)
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if err := conn.HandshakeContext(ctx); err != nil {
					return err
				}
				var request lifecycleAttachmentCSRRequest
				if err := readCredential(conn, &request); err != nil {
					return err
				}
				reply := lifecycleAttachmentCSRReply{Version: 3, Certificate: cert.DER()}
				switch kind {
				case "v1":
					reply.Version = 1
				case "unknown":
					return writeCredential(conn, json.RawMessage(`{"version":3,"certificate":"","error":"rejected"}`))
				case "duplicate":
					return writeCredential(conn, json.RawMessage(`{"version":3,"version":3,"certificate":""}`))
				case "truncated":
					var head [4]byte
					binary.BigEndian.PutUint32(head[:], 5)
					_, err := conn.Write(append(head[:], '{'))
					return err
				case "wrong-key":
					other, err := p.NewAttachmentKey(p.RuntimeRole)
					must(t, err)
					cert, err := f.s.owner.issuer.IssueAttachment(lifecycleAttachmentCSR(t, other, h), binding, f.cfg.Now, f.cfg.Lifetime)
					must(t, err)
					reply.Certificate = cert.DER()
				case "wrong-binding":
					other := h
					other.Binding.Launch = id(t)
					b, err := d.AttachmentBinding(other)
					must(t, err)
					cert, err := f.s.owner.issuer.IssueAttachment(lifecycleAttachmentCSR(t, key, other), b, f.cfg.Now, f.cfg.Lifetime)
					must(t, err)
					reply.Certificate = cert.DER()
				}
				return writeCredential(conn, reply)
			})
			got, err := RequestLifecycleAttachmentCertificate(t.Context(), raw, identity, r, f.initial.Grant.Identity, h, csr)
			if err == nil || len(got.DER()) != 0 {
				t.Fatal("accepted bad reply/trust")
			}
			join()
		})
	}
}

func TestLifecycleAttachmentCSRCancellationOwnsStream(t *testing.T) {
	f, identity, ready, h, _, csr := lifecycleAttachmentFixture(t)
	for _, server := range []bool{false, true} {
		left, right := net.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			if server {
				done <- f.s.ServeAttachmentCSR(ctx, right)
			} else {
				_, err := RequestLifecycleAttachmentCertificate(ctx, right, identity, ready, f.initial.Grant.Identity, h, csr)
				done <- err
			}
		}()
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancelled issuance")
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation hung")
		}
		left.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := left.Read(make([]byte, 1)); err == nil {
			t.Fatal("stream leaked")
		}
		left.Close()
	}
}
