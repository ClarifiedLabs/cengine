package storagebootstrap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	service "dev.cengine/guest/internal/storageservice"
)

func lifecycleAttachmentChild(t *testing.T) (*lifecycleSessionFixture, *service.LifecycleService, LifecycleAttachmentCertificateRequest, p.Key) {
	t.Helper()
	f := newLifecycleSessionIntent(t, false)
	lifecycleSessionProof(t, f, f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant))
	f.owner = lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)
	check(t, f.s.bindGrant(f.owner))
	dir := t.TempDir()
	check(t, os.Mkdir(filepath.Join(dir, "volumes"), 0700))
	held, err := os.Open(dir)
	check(t, err)
	defer held.Close()
	svc, err := service.InitializeLifecycle(service.Config{Root: held, DeviceUUID: "lifecycle-attachment-child", Store: f.cfg.store, Bootstrap: f.cfg.root, Now: f.now, Lifetime: time.Hour}, f.owner)
	check(t, err)
	ready, err := svc.Ready()
	check(t, err)
	csr, err := f.s.controllerCSR()
	check(t, err)
	cert, err := svc.IssueController(csr)
	check(t, err)
	root, err := p.ParseRootDER(ready.TLSRootDER)
	check(t, err)
	f.boot = lifecycleBoot{identity: f.owner.Grant.Identity, signed: f.owner, serviceEpoch: ready.ServiceEpoch, root: root, serverPin: ready.ServerKey, certificate: cert}
	raw, join := credentialStream(t, svc.ServeLifecycle)
	check(t, f.s.connectTrustedBoot(t.Context(), raw, f.boot))
	lifecycleSessionProof(t, f, f.challenge(t, 2, p.LifecycleChildResult, f.owner.Grant))
	raw, workJoin := credentialStream(t, svc.ServeControl)
	check(t, f.s.connectWorkload(t.Context(), raw))
	t.Cleanup(func() { f.s.close(); workJoin(); join(); check(t, svc.Close()) })
	call := func(request c.Request) {
		body, err := f.s.workloadCommand(t.Context(), request)
		check(t, err)
		var reply c.Response
		check(t, json.Unmarshal(body, &reply))
		if reply.Error != "" {
			t.Fatal(reply.Error)
		}
	}
	volume := lifecycleSessionID(t)
	call(c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: lifecycleSessionID(t), Store: ready.Store.ID, Volume: volume, Name: "child-credential"}})
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	check(t, err)
	pin, err := key.Fingerprint()
	check(t, err)
	h := a.DataHello{Epoch: ready.ServiceEpoch, Binding: a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: lifecycleSessionID(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: lifecycleSessionID(t), Key: a.Fingerprint(pin.String()), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	call(c.Request{RegisterAttachment: &a.RegisterRequest{Operation: lifecycleSessionID(t), Binding: h.Binding}})
	binding, err := d.AttachmentBinding(h)
	check(t, err)
	csr, err = key.CSR(binding)
	check(t, err)
	return f, svc, LifecycleAttachmentCertificateRequest{Attachment: h, ControllerEpoch: ready.Controller.Epoch, CSR: csr, Identity: f.owner.Grant.Identity}, key
}

func lifecycleAttachmentExchange(t *testing.T, f *lifecycleSessionFixture, svc *service.LifecycleService, request LifecycleAttachmentCertificateRequest) AttachmentCertificateReply {
	t.Helper()
	raw, join := credentialStream(t, svc.ServeAttachmentCSR)
	body, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("attachment-certificate", lifecyclePrivateBody(t, request)), raw)
	check(t, err)
	join()
	var reply AttachmentCertificateReply
	check(t, lifecycleCanonical(body, &reply, MaximumPayload))
	if (len(reply.Certificate) != 0) == (reply.Error != "") || (reply.Error != "" && reply.Error != "rejected" && reply.Error != "unavailable") {
		t.Fatal("not closed reply union", string(body))
	}
	return reply
}

func TestLifecycleAttachmentPrivateCurrentOwnerAndExactBinding(t *testing.T) {
	f, svc, request, key := lifecycleAttachmentChild(t)
	reply := lifecycleAttachmentExchange(t, f, svc, request)
	if reply.Error != "" {
		t.Fatal(reply.Error)
	}
	binding, err := d.AttachmentBinding(request.Attachment)
	check(t, err)
	cert, err := p.ParseCertificateDER(reply.Certificate, binding)
	check(t, err)
	_, err = cert.WithKey(key)
	check(t, err)
	for name, mutate := range map[string]func(*LifecycleAttachmentCertificateRequest){
		"wrong-S":       func(r *LifecycleAttachmentCertificateRequest) { r.Identity.Store = lifecycleSessionID(t) },
		"wrong-G":       func(r *LifecycleAttachmentCertificateRequest) { r.Identity.Generation++ },
		"wrong-binding": func(r *LifecycleAttachmentCertificateRequest) { r.Identity.Binding = f.owner.Grant.NewKey },
		"wrong-E":       func(r *LifecycleAttachmentCertificateRequest) { r.Attachment.Epoch = lifecycleSessionID(t) },
		"wrong-C":       func(r *LifecycleAttachmentCertificateRequest) { r.ControllerEpoch++ },
		"unregistered": func(r *LifecycleAttachmentCertificateRequest) {
			r.Attachment.Binding.Attachment = lifecycleSessionID(t)
		},
		"wrong-launch": func(r *LifecycleAttachmentCertificateRequest) { r.Attachment.Binding.Launch = lifecycleSessionID(t) },
		"wrong-volume": func(r *LifecycleAttachmentCertificateRequest) { r.Attachment.Binding.Volume = lifecycleSessionID(t) },
		"wrong-container": func(r *LifecycleAttachmentCertificateRequest) {
			r.Attachment.Binding.Container = a.ContainerID(strings.Repeat("b", 64))
		},
		"wrong-mode": func(r *LifecycleAttachmentCertificateRequest) { r.Attachment.Binding.Mode = a.ReadOnly },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := request
			mutate(&wrong)
			reply := lifecycleAttachmentExchange(t, f, svc, wrong)
			if len(reply.Certificate) != 0 || reply.Error == "" {
				t.Fatal("issued wrong tuple")
			}
		})
	}
	f.s.mu.Lock()
	f.s.rootBootSeen = false
	f.s.mu.Unlock()
	if reply := lifecycleAttachmentExchange(t, f, svc, request); reply.Error != "rejected" {
		t.Fatal("boot inputs alone established trust")
	}
	lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
	if reply := lifecycleAttachmentExchange(t, f, svc, request); reply.Error != "" {
		t.Fatal("rejected request destroyed current key")
	}
}

func TestLifecycleAttachmentPrivateClosedBodyAndStreams(t *testing.T) {
	f, _, request, _ := lifecycleAttachmentChild(t)
	body := lifecyclePrivateBody(t, request)
	var fields map[string]json.RawMessage
	check(t, json.Unmarshal(body, &fields))
	badBodies := [][]byte{[]byte("null"), []byte(`{}`), append([]byte(`{"attachment":{},`), body[1:]...)}
	for _, extra := range []string{"tls_root", "key", "authority", "controller_identity", "receipt"} {
		fields[extra] = json.RawMessage(`{}`)
		badBodies = append(badBodies, lifecyclePrivateBody(t, fields))
		delete(fields, extra)
	}
	delete(fields, "identity")
	badBodies = append(badBodies, lifecyclePrivateBody(t, fields))
	wrong := request
	wrong.CSR = []byte("malformed")
	badBodies = append(badBodies, lifecyclePrivateBody(t, wrong))
	wrong = request
	wrong.Attachment.Binding.Key = f.owner.Grant.NewKey
	badBodies = append(badBodies, lifecyclePrivateBody(t, wrong))
	for _, body := range badBodies {
		left, right := net.Pipe()
		if data, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("attachment-certificate", body), right); err == nil || len(data) != 0 {
			t.Fatal("malformed body accepted", string(body))
		}
		left.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := left.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatal("rejected stream leaked", err)
		}
		left.Close()
	}
	if _, err := f.s.privateLifecycleRequest(t.Context(), lifecyclePrivateCommand("attachment-certificate", body), nil); err == nil {
		t.Fatal("missing stream accepted")
	}
	// The private body is sorted recursively, not Go service-envelope declaration order.
	if !bytes.HasPrefix(body, []byte(`{"attachment":`)) || !bytes.Contains(body, []byte(`"generation":9007199254740993`)) {
		t.Fatal("lost canonical order or UInt64 precision", string(body))
	}
	wrong = request
	wrong.ControllerEpoch = ^uint64(0)
	var decoded LifecycleAttachmentCertificateRequest
	check(t, lifecycleCanonical(lifecyclePrivateBody(t, wrong), &decoded, MaximumPayload))
	if decoded.ControllerEpoch != ^uint64(0) {
		t.Fatal("rounded C")
	}
}

func TestLifecycleAttachmentPrivateCancellationAndRevocation(t *testing.T) {
	for _, kind := range []string{"queued-cancel", "handshake-cancel", "close", "owner-generation", "retirement"} {
		t.Run(kind, func(t *testing.T) {
			f, _, request, _ := lifecycleAttachmentChild(t)
			left, right := net.Pipe()
			defer left.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "queued-cancel" {
				f.s.op <- struct{}{}
			}
			done := make(chan error, 1)
			go func() {
				reply, err := f.s.attachmentCertificate(ctx, right, request)
				if len(reply.Certificate) != 0 {
					done <- errors.New("certificate escaped")
					return
				}
				done <- err
			}()
			if kind == "queued-cancel" {
				cancel()
				<-f.s.op
			} else {
				left.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := left.Read(make([]byte, 1)); err != nil {
					t.Fatal("no TLS handshake", err)
				}
				switch kind {
				case "handshake-cancel":
					cancel()
				case "close":
					f.s.close()
				case "owner-generation":
					f.s.mu.Lock()
					f.s.owner.Grant.Serial++
					f.s.mu.Unlock()
					left.Close()
				case "retirement":
					f.s.mu.Lock()
					f.s.retirement.Grant = f.retirement.Grant
					f.s.mu.Unlock()
					left.Close()
				}
			}
			select {
			case err := <-done:
				if kind != "handshake-cancel" && err == nil {
					t.Fatal("revoked/changed owner not fenced")
				}
			case <-time.After(time.Second):
				t.Fatal("operation hung")
			}
		})
	}
}

func TestLifecycleAttachmentPrivateFailureClassification(t *testing.T) {
	for _, err := range []error{io.EOF, context.Canceled, context.DeadlineExceeded, a.ErrUnauthorized} {
		reply, fatal := lifecycleAttachmentFailure(err)
		if fatal != nil || reply.Error == "" || len(reply.Certificate) != 0 {
			t.Fatal("bad ordinary failure")
		}
	}
	for _, err := range []error{io.ErrUnexpectedEOF, p.ErrInvalid, service.ErrConfiguration} {
		if reply, fatal := lifecycleAttachmentFailure(err); fatal == nil || len(reply.Certificate) != 0 || reply.Error != "" {
			t.Fatal("malformed/trust failure not fatal")
		}
	}
}

// Preserve the shared credential transport boundary coverage on the lifecycle
// owner rather than keeping a legacy controller alive just for this fixture.
func TestLifecycleAttachmentTLSRecordLoss(t *testing.T) {
	f, svc, request, _ := lifecycleAttachmentChild(t)
	for _, prefix := range [][]byte{nil, {0x16, 0x03}} {
		raw, join := credentialStream(t, func(_ context.Context, peer net.Conn) error {
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return err
			}
			var header [5]byte
			if _, err := io.ReadFull(peer, header[:]); err != nil {
				return err
			}
			n := int64(binary.BigEndian.Uint16(header[3:]))
			if header[0] != 0x16 || n == 0 || n > 16384 {
				return ErrProtocol
			}
			if _, err := io.CopyN(io.Discard, peer, n); err != nil {
				return err
			}
			if len(prefix) != 0 {
				_, err := peer.Write(prefix)
				return err
			}
			return nil
		})
		pin := lifecycleSessionPin(t, f.s)
		reply, err := f.s.attachmentCertificate(t.Context(), raw, request)
		check(t, join())
		if len(prefix) != 0 {
			if !errors.Is(err, io.ErrUnexpectedEOF) || reply.Error != "" || len(reply.Certificate) != 0 {
				t.Fatal("truncated TLS not fatal", reply, err)
			}
			continue
		}
		check(t, err)
		if reply.Error != "unavailable" || len(reply.Certificate) != 0 || pin != lifecycleSessionPin(t, f.s) {
			t.Fatal("EOF changed owner", reply)
		}
		if reply := lifecycleAttachmentExchange(t, f, svc, request); reply.Error != "" {
			t.Fatal("EOF prevented same-key retry", reply)
		}
	}
}

func TestLifecycleAttachmentRegisteredPrepareScope(t *testing.T) {
	f, svc, request, _ := lifecycleAttachmentChild(t)
	key, err := p.NewAttachmentKey(p.PrepareRole)
	check(t, err)
	pin, err := key.Fingerprint()
	check(t, err)
	request.Attachment.Binding.Role = a.PrepareRole
	request.Attachment.Binding.Prepare = lifecycleSessionID(t)
	request.Attachment.Binding.Attachment = lifecycleSessionID(t)
	request.Attachment.Binding.Key = a.Fingerprint(pin.String())
	body, err := f.s.workloadCommand(t.Context(), c.Request{ReservePrepare: &a.ReserveRequest{Operation: lifecycleSessionID(t), Prepare: request.Attachment.Binding.Prepare, Attachments: []a.Binding{request.Attachment.Binding}}})
	check(t, err)
	var response c.Response
	check(t, json.Unmarshal(body, &response))
	if response.Error != "" {
		t.Fatal(response.Error)
	}
	issue := func(r LifecycleAttachmentCertificateRequest) AttachmentCertificateReply {
		binding, err := d.AttachmentBinding(r.Attachment)
		check(t, err)
		r.CSR, err = key.CSR(binding)
		check(t, err)
		return lifecycleAttachmentExchange(t, f, svc, r)
	}
	if reply := issue(request); reply.Error != "" {
		t.Fatal("registered prepare rejected", reply)
	}
	wrong := request
	wrong.Attachment.Binding.Prepare = lifecycleSessionID(t)
	if reply := issue(wrong); reply.Error == "" {
		t.Fatal("wrong prepare certified")
	}
}
