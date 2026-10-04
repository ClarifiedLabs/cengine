package workloadstorage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dev.cengine/guest/internal/storagepki"
)

// These fakes exercise control ownership only. They do not assert that a kernel
// mount, copy-up, durability barrier or supervisor operation actually occurred.
type sessionWorkloadFake struct {
	configured, prepared, started, stopped atomic.Int32
	done                                   chan struct{}
	once                                   sync.Once
	raw                                    []byte
	claim                                  string
	mounts                                 []MountBinding
	prepareError                           error
	prepareEntered                         chan struct{}
	completeOnStart                        bool // workload completes before the start reply
	waitExited                             chan struct{}
	stopError                              error
	stopLeavesRunning                      bool
	stopEntered                            chan struct{}
	stopGate                               chan struct{}
}

func (w *sessionWorkloadFake) Configure() error { w.configured.Add(1); return nil }
func (w *sessionWorkloadFake) Prepare(ctx context.Context, raw []byte, claim string, _ Scope, mounts []MountBinding, _ []Slot) error {
	w.prepared.Add(1)
	w.raw, w.claim, w.mounts = bytes.Clone(raw), claim, mounts
	if w.prepareEntered != nil {
		close(w.prepareEntered)
		<-ctx.Done()
		return ctx.Err()
	}
	return w.prepareError
}
func (w *sessionWorkloadFake) Start(context.Context, Scope, []MountBinding, []Slot) (uint32, error) {
	w.started.Add(1)
	if w.completeOnStart {
		w.once.Do(func() { close(w.done) })
	}
	return 42, nil
}
func (w *sessionWorkloadFake) Stop(context.Context) error {
	w.stopped.Add(1)
	if w.stopEntered != nil {
		close(w.stopEntered)
	}
	if w.stopGate != nil {
		<-w.stopGate
	}
	if !w.stopLeavesRunning {
		w.once.Do(func() { close(w.done) })
	}
	return w.stopError
}
func (w *sessionWorkloadFake) Wait() {
	<-w.done
	if w.waitExited != nil {
		close(w.waitExited)
	}
}

type sessionAttachmentFake struct {
	path              string
	done              chan struct{}
	once              sync.Once
	graceful, aborted atomic.Int32
	closeError        error
	blockGraceful     bool
	callback          func(error)
	abortError        error
	gracefulDeadline  chan time.Time
}

func (a *sessionAttachmentFake) CloseGracefully(ctx context.Context) error {
	a.graceful.Add(1)
	if a.gracefulDeadline != nil {
		deadline, _ := ctx.Deadline()
		a.gracefulDeadline <- deadline
	}
	if a.blockGraceful {
		<-ctx.Done()
		return ctx.Err()
	}
	if a.closeError != nil {
		return a.closeError
	}
	a.once.Do(func() { close(a.done) })
	if a.callback != nil {
		a.callback(nil)
	}
	return nil
}
func (a *sessionAttachmentFake) Close() error {
	a.aborted.Add(1)
	a.once.Do(func() { close(a.done) })
	return a.abortError
}
func (a *sessionAttachmentFake) Done() <-chan struct{} { return a.done }
func (a *sessionAttachmentFake) Err() error            { return nil }
func (a *sessionAttachmentFake) Mountpoint() string    { return a.path }

type sessionFactoryFake struct {
	mu          sync.Mutex
	attachments []*sessionAttachmentFake
	wrongPath   bool
	closeError  bool
	blockSecond bool
}

func (f *sessionFactoryFake) Mount(_ context.Context, scope Scope, _ Peer, slot Slot, identity storagepki.Identity, callback func(error)) (Attachment, error) {
	expected, err := sessionBinding(scope, slot)
	if err != nil || identity.Certificate().Binding() != expected {
		return nil, errors.New("wrong identity")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a := &sessionAttachmentFake{path: "/run/cengine/managed/" + slot.Attachment + "/root", done: make(chan struct{}), callback: callback}
	if f.wrongPath {
		a.path = "/untrusted"
	}
	if f.closeError && len(f.attachments) == 0 {
		a.closeError = errors.New("secret backend diagnostic")
	}
	if f.blockSecond && len(f.attachments) == 1 {
		a.blockGraceful = true
	}
	f.attachments = append(f.attachments, a)
	return a, nil
}
func (f *sessionFactoryFake) all() []*sessionAttachmentFake {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*sessionAttachmentFake{}, f.attachments...)
}

type sessionHarness struct {
	t       *testing.T
	s       *Session
	w       *sessionWorkloadFake
	factory *sessionFactoryFake
	config  *Frame
	issuer  storagepki.Issuer
	now     time.Time
	client  net.Conn
	result  chan error
	seq     uint64
	raw     []byte
	ctx     context.Context
	wrap    func(net.Conn) net.Conn
}

func sessionUUID(t *testing.T) string {
	t.Helper()
	id, err := storagepki.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func newSessionHarness(t *testing.T, volumes int) *sessionHarness {
	t.Helper()
	h := &sessionHarness{t: t, w: &sessionWorkloadFake{done: make(chan struct{})}, factory: &sessionFactoryFake{}, now: time.Now().Add(-time.Minute).Truncate(time.Second), raw: []byte("{ \"ioClaim\": \"\", \"mounts\": [] }\n")}
	scope := Scope{Intent: sessionUUID(t), Store: sessionUUID(t), ServiceEpoch: sessionUUID(t), ControllerEpoch: 1, ControllerKey: strings.Repeat("a", 64), Container: strings.Repeat("b", 64), ContainerInstance: sessionUUID(t), Launch: sessionUUID(t), Prepare: sessionUUID(t), SpecificationDigest: SpecificationDigest(h.raw)}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := storagepki.NewBootstrapPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	h.issuer, err = storagepki.NewIssuer(h.now, 2*time.Hour, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	key, err := storagepki.NewServerKey()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := storagepki.NewServerBinding(storagepki.StoreID(scope.Store), storagepki.ServiceEpoch(scope.ServiceEpoch))
	if err != nil {
		t.Fatal(err)
	}
	csr, err := key.CSR(binding)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.issuer.IssueServer(csr, binding, h.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := key.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{TLSRootDER: h.issuer.Root().DER(), ServerDER: cert.DER(), ServerKey: fingerprint.String(), DataAddress: "192.0.2.1"}
	mounts, slots := []MountBinding{}, []Slot{}
	for i := 0; i < volumes; i++ {
		volume := sessionUUID(t)
		mounts = append(mounts, MountBinding{Index: uint32(i), Volume: volume, Destination: "/data", Mode: "read-write", NoCopy: true})
		for _, role := range []string{"prepare", "runtime"} {
			slots = append(slots, Slot{Volume: volume, Attachment: sessionUUID(t), Role: role, Mode: "read-write"})
		}
	}
	boot := BootBinding{ShimLaunchUUID: scope.Launch, GuestBootNonce: sessionUUID(t)}
	h.config = NewFrame("configure", boot, scope, Payload{Peer: &peer, Mounts: &mounts, Slots: &slots})
	h.s, err = newSession(boot, h.w, h.factory)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func (h *sessionHarness) connect() {
	h.t.Helper()
	server, client := net.Pipe()
	if h.wrap != nil {
		server = h.wrap(server)
	}
	h.client = client
	h.result = make(chan error, 1)
	ctx := h.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go func() { h.result <- h.s.Serve(ctx, server) }()
	h.t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-h.result:
		case <-time.After(3 * time.Second):
			h.t.Error("session failed to join")
		}
	})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	hello, err := ReadFrame(client)
	if err != nil || hello.Operation != "hello" || hello.Binding != h.config.Binding {
		h.t.Fatal("hello", err)
	}
}
func (h *sessionHarness) configure() {
	h.t.Helper()
	h.connect()
	if err := WriteFrame(h.client, h.config); err != nil {
		h.t.Fatal(err)
	}
	frame, err := ReadFrame(h.client)
	if err != nil || frame.Operation != "configured" {
		h.t.Fatal("configure", err)
	}
}
func (h *sessionHarness) exchange(kind string, data Payload) *Frame {
	h.t.Helper()
	h.seq++
	frame := NewFrame("command", h.config.Binding, *h.config.Scope, data)
	frame.Kind, frame.Sequence = kind, &h.seq
	if err := WriteFrame(h.client, frame); err != nil {
		h.t.Fatal("write", err)
	}
	reply, err := ReadFrame(h.client)
	if err != nil {
		h.t.Fatal("read", err)
	}
	if reply.Kind != kind || reply.Sequence == nil || *reply.Sequence != h.seq || reply.Binding != h.config.Binding || *reply.Scope != *h.config.Scope {
		h.t.Fatal("reply correlation")
	}
	return reply
}
func (h *sessionHarness) success(kind string, data Payload) *Frame {
	h.t.Helper()
	reply := h.exchange(kind, data)
	if reply.Data.Code != nil {
		h.t.Fatal("command failed", kind, *reply.Data.Code)
	}
	return reply
}
func (h *sessionHarness) offer(role string) []Offer {
	h.t.Helper()
	return *h.success("offer-keys", Payload{Role: &role}).Data.Offers
}
func (h *sessionHarness) certificate(offer Offer, issuer storagepki.Issuer) []byte {
	h.t.Helper()
	var slot Slot
	for _, candidate := range *h.config.Data.Slots {
		if candidate.Attachment == offer.Attachment {
			slot = candidate
		}
	}
	binding, err := sessionBinding(*h.config.Scope, slot)
	if err != nil {
		h.t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(offer.CSRDER)
	if err != nil || csr.CheckSignature() != nil {
		h.t.Fatal("invalid CSR")
	}
	pin, err := storagepki.PublicKeyFingerprint(csr.PublicKey.(ed25519.PublicKey))
	if err != nil || pin.String() != offer.Key {
		h.t.Fatal("CSR key mismatch")
	}
	cert, err := issuer.IssueAttachment(offer.CSRDER, binding, h.now, time.Hour)
	if err != nil {
		h.t.Fatal(err)
	}
	return cert.DER()
}
func (h *sessionHarness) mount(role string) []Offer {
	h.t.Helper()
	offers := h.offer(role)
	for _, offer := range offers {
		cert := h.certificate(offer, h.issuer)
		h.success("install-certificate", Payload{Attachment: &offer.Attachment, CertificateDER: &cert})
	}
	h.success("mount-phase", Payload{Role: &role})
	return offers
}
func (h *sessionHarness) prepare() *Frame {
	h.t.Helper()
	return h.success("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("separate-secret")})
}
func (h *sessionHarness) finish() error {
	h.t.Helper()
	select {
	case err := <-h.result:
		h.result <- err
		return err
	case <-time.After(3 * time.Second):
		h.t.Fatal("session did not terminate")
		return nil
	}
}

func TestSessionLifecycle(t *testing.T) {
	h := newSessionHarness(t, 1)
	h.configure()
	prepare := h.mount("prepare")
	reply := h.prepare()
	if !*reply.Data.Succeeded || !*reply.Data.CleanCopyUp || !pin(*reply.Data.EvidenceDigest) {
		t.Fatal("prepare evidence")
	}
	closed := h.success("close-phase", Payload{Role: ptr("prepare")})
	if !*closed.Data.Clean || len(*closed.Data.AttachmentIDs) != 1 {
		t.Fatal("unclean")
	}
	runtime := h.mount("runtime")
	if prepare[0].Key == runtime[0].Key || prepare[0].Attachment == runtime[0].Attachment {
		t.Fatal("keys reused")
	}
	h.success("start", Payload{})
	status := h.success("status", Payload{})
	if *status.Data.Phase != "running" || !reflect.DeepEqual(*status.Data.MountedIDs, []string{runtime[0].Attachment}) {
		t.Fatal("status")
	}
	h.success("abort", Payload{})
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
	if h.w.configured.Load() != 1 || h.w.prepared.Load() != 1 || h.w.started.Load() != 1 || h.w.stopped.Load() != 1 {
		t.Fatal("workload invocation counts")
	}
	if !bytes.Equal(h.w.raw, h.raw) || h.w.claim != "separate-secret" || !reflect.DeepEqual(h.w.mounts, *h.config.Data.Mounts) || !h.w.mounts[0].NoCopy {
		t.Fatal("opaque bytes, separate claim or noCopy plan changed")
	}
	for _, a := range h.factory.all() {
		if a.aborted.Load() == 0 {
			t.Fatal("unowned mount")
		}
	}
	if err := h.s.Serve(context.Background(), h.client); err == nil {
		t.Fatal("session reused")
	}
}

func TestSessionRejectsReversedPhaseAndReplay(t *testing.T) {
	for _, test := range []string{"runtime-first", "start-first", "close-before-prepare", "offer-twice", "sequence", "scope", "binding"} {
		t.Run(test, func(t *testing.T) {
			h := newSessionHarness(t, 1)
			h.configure()
			kind, payload, want := "start", Payload{}, "phase"
			switch test {
			case "runtime-first":
				kind, payload = "offer-keys", Payload{Role: ptr("runtime")}
			case "close-before-prepare":
				kind, payload = "close-phase", Payload{Role: ptr("prepare")}
			case "offer-twice":
				h.offer("prepare")
				kind, payload = "offer-keys", Payload{Role: ptr("prepare")}
			case "sequence":
				h.success("status", Payload{})
				h.seq--
				kind, want = "status", "sequence"
			case "scope", "binding":
				frame := NewFrame("command", h.config.Binding, *h.config.Scope, Payload{})
				frame.Kind, frame.Sequence = "status", ptr(uint64(1))
				if test == "scope" {
					frame.Scope.Intent = sessionUUID(t)
					want = "scope-mismatch"
				} else {
					frame.Binding.GuestBootNonce = sessionUUID(t)
					want = "binding-mismatch"
				}
				if err := WriteFrame(h.client, frame); err != nil {
					t.Fatal(err)
				}
				reply, err := ReadFrame(h.client)
				if err != nil || reply.Data.Code == nil || *reply.Data.Code != want {
					t.Fatal("mismatch not rejected", err)
				}
				if h.finish() == nil {
					t.Fatal("not terminal")
				}
				return
			}
			reply := h.exchange(kind, payload)
			if reply.Data.Code == nil || *reply.Data.Code != want {
				t.Fatal("expected fixed error", want)
			}
			if h.finish() == nil || h.w.started.Load() != 0 {
				t.Fatal("not terminal")
			}
		})
	}
}

func TestSessionRejectsWrongCertificateAndReplay(t *testing.T) {
	for _, variant := range []string{"wrong-key", "wrong-root", "replay", "mount-before-certificate"} {
		t.Run(variant, func(t *testing.T) {
			h := newSessionHarness(t, 1)
			h.configure()
			offer := h.offer("prepare")[0]
			if variant == "mount-before-certificate" {
				if h.exchange("mount-phase", Payload{Role: ptr("prepare")}).Data.Code == nil {
					t.Fatal("mounted without certificate")
				}
				h.finish()
				return
			}
			issuer := h.issuer
			if variant == "wrong-root" {
				other := newSessionHarness(t, 0)
				issuer = other.issuer
			}
			if variant == "wrong-key" {
				slot := (*h.config.Data.Slots)[0]
				b, _ := sessionBinding(*h.config.Scope, slot)
				key, _ := storagepki.NewAttachmentKey(storagepki.PrepareRole)
				offer.CSRDER, _ = key.CSR(b)
				fingerprint, _ := key.Fingerprint()
				offer.Key = fingerprint.String()
			}
			cert := h.certificate(offer, issuer)
			payload := Payload{Attachment: &offer.Attachment, CertificateDER: &cert}
			if variant == "replay" {
				h.success("install-certificate", payload)
			}
			if h.exchange("install-certificate", payload).Data.Code == nil {
				t.Fatal("invalid certificate accepted")
			}
			h.finish()
			if len(h.factory.all()) != 0 {
				t.Fatal("certificate failure mounted")
			}
		})
	}
}

func TestSessionCloseFailureNeverReportsClean(t *testing.T) {
	h := newSessionHarness(t, 2)
	h.factory.closeError, h.factory.blockSecond = true, true
	h.configure()
	h.mount("prepare")
	h.prepare()
	reply := h.exchange("close-phase", Payload{Role: ptr("prepare")})
	if reply.Data.Code == nil || *reply.Data.Code != "mount" || reply.Data.Clean != nil {
		t.Fatal("false clean")
	}
	err := h.finish()
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("diagnostic leaked")
	}
	for _, a := range h.factory.all() {
		if a.graceful.Load() != 1 || a.aborted.Load() == 0 {
			t.Fatal("not every owned mount was closed")
		}
	}
}

func TestSessionConnectionLossUnblocksPrepare(t *testing.T) {
	h := newSessionHarness(t, 1)
	h.w.prepareEntered = make(chan struct{})
	h.configure()
	h.mount("prepare")
	h.seq++
	frame := NewFrame("command", h.config.Binding, *h.config.Scope, Payload{WorkloadJSON: &h.raw, IOClaim: ptr("secret")})
	frame.Kind, frame.Sequence = "prepare", &h.seq
	if err := WriteFrame(h.client, frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.w.prepareEntered:
	case <-time.After(time.Second):
		t.Fatal("prepare not entered")
	}
	_ = h.client.Close()
	h.finish()
	if h.w.stopped.Load() != 1 || h.factory.all()[0].aborted.Load() == 0 {
		t.Fatal("disconnect did not clean up")
	}
}

func TestSessionCallbackFloodIsNonblockingAndTerminal(t *testing.T) {
	h := newSessionHarness(t, 1)
	h.configure()
	h.mount("prepare")
	callback := h.factory.all()[0].callback
	done := make(chan struct{})
	go func() {
		for range 10000 {
			callback(errors.New("secret native error"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("native callback blocked")
	}
	if h.finish() == nil || h.w.stopped.Load() != 1 {
		t.Fatal("retirement not terminal")
	}
}

func TestSessionEmbeddedClaimAndAdapterFailure(t *testing.T) {
	for _, raw := range []string{`{"ioClaim":"secret"}`, `{"ioClaim":"","ioClaim":""}`, `{"ioClaim":"","IOClaim":""}`, `{"ioClaim":null}`, `{}`, `[]`} {
		if emptyEmbeddedClaim([]byte(raw)) {
			t.Fatal("accepted embedded claim")
		}
	}
	h := newSessionHarness(t, 1)
	h.w.prepareError = errors.New("adapter rejected noCopy mismatch: secret")
	h.configure()
	h.mount("prepare")
	reply := h.exchange("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("secret")})
	if reply.Data.Code == nil || *reply.Data.Code != "prepare" {
		t.Fatal("adapter validation ignored")
	}
	if err := h.finish(); err == nil || err.Error() != "prepare" {
		t.Fatal("unsanitized error")
	}
}

func TestSessionEmptyPlanAndSequenceCeiling(t *testing.T) {
	h := newSessionHarness(t, 0)
	h.configure()
	h.mount("prepare")
	h.prepare()
	h.success("close-phase", Payload{Role: ptr("prepare")})
	h.mount("runtime")
	h.success("start", Payload{})
	h.seq = ^uint64(0) - 1
	h.success("status", Payload{})
	h.seq = 0
	reply := h.exchange("status", Payload{})
	if reply.Data.Code == nil || *reply.Data.Code != "sequence" {
		t.Fatal("sequence wrapped")
	}
	h.finish()
}

func TestSessionRejectsEmbeddedClaimBeforeBackend(t *testing.T) {
	for _, raw := range []string{`{"ioClaim":"secret"}`, `{"ioClaim":"","ioClaim":""}`, `{"ioClaim":"","IOClaim":""}`} {
		h := newSessionHarness(t, 1)
		h.raw = []byte(raw)
		h.config.Scope.SpecificationDigest = SpecificationDigest(h.raw)
		h.configure()
		h.mount("prepare")
		reply := h.exchange("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("separate-secret")})
		if reply.Data.Code == nil || *reply.Data.Code != "prepare" {
			t.Fatal("embedded claim accepted")
		}
		h.finish()
		if h.w.prepared.Load() != 0 {
			t.Fatal("backend saw embedded secret")
		}
	}
}

func TestSessionParentCancellationJoinsRunningWorkload(t *testing.T) {
	h := newSessionHarness(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.ctx = ctx
	h.configure()
	h.mount("prepare")
	h.prepare()
	h.success("close-phase", Payload{Role: ptr("prepare")})
	h.mount("runtime")
	h.success("start", Payload{})
	cancel()
	h.finish()
	if h.w.stopped.Load() != 1 {
		t.Fatal("cancel did not stop workload")
	}
}

type sessionDeadlineConn struct {
	net.Conn
	deadlines chan time.Time
}

func (c sessionDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.deadlines <- deadline
	return c.Conn.SetReadDeadline(deadline)
}

func TestSessionTransportIdleThenAbsoluteDeadlineAndLengthBound(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	deadlines := make(chan time.Time, 2)
	result := make(chan error, 1)
	go func() { _, err := sessionRead(sessionDeadlineConn{server, deadlines}); result <- err }()
	if deadline := <-deadlines; !deadline.IsZero() {
		t.Fatal("idle connection has a deadline")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], MaximumFrameBytes+1)
	if _, err := client.Write(prefix[:1]); err != nil {
		t.Fatal(err)
	}
	deadline := <-deadlines
	if remaining := time.Until(deadline); remaining < 119*time.Second || remaining > 120*time.Second {
		t.Fatal("wrong absolute frame deadline")
	}
	if _, err := client.Write(prefix[1:]); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrInvalidFrame) {
		t.Fatal("oversized frame accepted")
	}
	select {
	case <-deadlines:
		t.Fatal("deadline rolled while reading frame")
	default:
	}
}

func TestSessionRejectsInvalidPeerAndMountpoint(t *testing.T) {
	t.Run("server-key", func(t *testing.T) {
		h := newSessionHarness(t, 1)
		h.config.Data.Peer.ServerKey = strings.Repeat("e", 64)
		h.connect()
		if err := WriteFrame(h.client, h.config); err != nil {
			t.Fatal(err)
		}
		if err := h.finish(); err == nil || h.w.configured.Load() != 0 {
			t.Fatal("invalid peer configured")
		}
	})
	t.Run("mountpoint", func(t *testing.T) {
		h := newSessionHarness(t, 1)
		h.factory.wrongPath = true
		h.configure()
		offer := h.offer("prepare")[0]
		cert := h.certificate(offer, h.issuer)
		h.success("install-certificate", Payload{Attachment: &offer.Attachment, CertificateDER: &cert})
		if h.exchange("mount-phase", Payload{Role: ptr("prepare")}).Data.Code == nil {
			t.Fatal("accepted arbitrary mountpoint")
		}
		h.finish()
		if h.factory.all()[0].aborted.Load() == 0 {
			t.Fatal("invalid mount leaked")
		}
	})
}

func (h *sessionHarness) terminal(ids []string) {
	h.t.Helper()
	frame, err := ReadFrame(h.client)
	if err != nil {
		h.t.Fatal("terminal event", err)
	}
	if frame.Operation != "terminal" || frame.Binding != h.config.Binding || frame.Scope == nil || *frame.Scope != *h.config.Scope || frame.Kind != "" || frame.Sequence != nil || frame.Data.Code == nil || *frame.Data.Code != "terminal" || frame.Data.AttachmentIDs == nil || !reflect.DeepEqual(*frame.Data.AttachmentIDs, ids) {
		h.t.Fatal("incorrect terminal event")
	}
	if _, err := ReadFrame(h.client); err == nil {
		h.t.Fatal("frame after terminal event")
	}
}

// A workload's natural exit is not a retirement source; only genuine mount
// failures (callback or attachment Done) publish the exact terminal event.
func TestSessionRetirementPublishesExactTerminalEvent(t *testing.T) {
	for _, source := range []string{"callback", "attachment-done"} {
		t.Run(source, func(t *testing.T) {
			h := newSessionHarness(t, 1)
			h.configure()
			offers := h.mount("prepare")
			a := h.factory.all()[0]
			if source == "callback" {
				a.callback(errors.New("secret native diagnostic"))
			} else {
				a.once.Do(func() { close(a.done) })
			}
			h.terminal([]string{offers[0].Attachment})
			if err := h.finish(); err == nil || err.Error() != "terminal" {
				t.Fatal("retirement not terminal", err)
			}
		})
	}
}

// Isolate the production start command's sole worker so joining workers also
// joins any action after Wait returns. This deterministically rejects the old
// Wait -> retire behavior without sleeps or a test-only production callback.
func TestSessionCompletedStartDoesNotRetireAuthority(t *testing.T) {
	for _, volumes := range []int{0, 2} {
		t.Run(map[int]string{0: "empty", 2: "mounted"}[volumes], func(t *testing.T) {
			h := newSessionHarness(t, volumes)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.s.cancel, h.s.phase = cancel, "runtime-mounted"
			h.s.scope, h.s.slots = *h.config.Scope, *h.config.Data.Slots
			h.w.completeOnStart = true
			reply, code := h.s.command(ctx, "start", Payload{})
			h.s.workers.Wait()
			if code != "" || reply.Status == nil || *reply.Status != "running" || reply.PID == nil || *reply.PID != 42 {
				t.Fatal("completed start lost its reply")
			}
			if ctx.Err() != nil || len(h.s.events) != 0 || h.w.stopped.Load() != 0 {
				t.Fatal("workload completion retired private authority")
			}
		})
	}
}

// Workload completion does not retire the session: mounts and private keys stay
// owned until explicit host retirement/teardown or a genuine failure.
func TestSessionNaturalWorkloadExitRetainsOwnership(t *testing.T) {
	names := map[int]string{0: "zero-attachments", 2: "nonzero-attachments"}
	for _, volumes := range []int{0, 2} {
		t.Run(names[volumes], func(t *testing.T) {
			for _, termination := range []string{"abort", "eof", "cancel"} {
				t.Run(termination, func(t *testing.T) {
					h := newSessionHarness(t, volumes)
					h.w.completeOnStart, h.w.waitExited = true, make(chan struct{})
					var cancel context.CancelFunc
					if termination == "cancel" {
						h.ctx, cancel = context.WithCancel(context.Background())
						defer cancel()
					}
					h.configure()
					h.mount("prepare")
					h.prepare()
					h.success("close-phase", Payload{Role: ptr("prepare")})
					runtime := h.mount("runtime")
					reply := h.success("start", Payload{})
					if reply.Data.Status == nil || *reply.Data.Status != "running" || reply.Data.PID == nil || *reply.Data.PID != 42 {
						t.Fatal("start reply changed by natural exit")
					}
					select {
					case <-h.w.waitExited:
					case <-time.After(time.Second):
						t.Fatal("workload wait never joined")
					}
					mounted := []string{}
					for _, offer := range runtime {
						mounted = append(mounted, offer.Attachment)
					}
					sort.Strings(mounted)
					status := h.success("status", Payload{})
					if status.Data.Phase == nil || *status.Data.Phase != "running" ||
						!reflect.DeepEqual(*status.Data.MountedIDs, mounted) || len(*status.Data.TerminalIDs) != 0 {
						t.Fatal("natural exit retired owned mounts")
					}
					if h.w.stopped.Load() != 0 {
						t.Fatal("natural exit stopped the workload")
					}
					switch termination {
					case "abort":
						h.success("abort", Payload{})
					case "eof":
						_ = h.client.Close()
					case "cancel":
						cancel()
					}
					if termination == "abort" {
						if err := h.finish(); err != nil {
							t.Fatal("clean abort after natural exit", err)
						}
					} else if err := h.finish(); err == nil || err.Error() != "terminal" {
						t.Fatal("loss after natural exit not terminal", err)
					}
					if h.w.stopped.Load() != 1 {
						t.Fatal("post-exit termination did not stop the workload exactly once")
					}
					for _, a := range h.factory.all() {
						if a.aborted.Load() != 1 {
							t.Fatal("post-exit termination did not clean each owned mount exactly once")
						}
					}
				})
			}
		})
	}
}

// A mount failure after the workload already completed is still terminal:
// completion changed nothing about attachment ownership.
func TestSessionAttachmentFailureAfterNaturalExitStillTerminal(t *testing.T) {
	for _, source := range []string{"callback", "attachment-done"} {
		t.Run(source, func(t *testing.T) {
			h := newSessionHarness(t, 1)
			h.w.completeOnStart, h.w.waitExited = true, make(chan struct{})
			h.configure()
			h.mount("prepare")
			h.prepare()
			h.success("close-phase", Payload{Role: ptr("prepare")})
			offers := h.mount("runtime")
			h.success("start", Payload{})
			<-h.w.waitExited
			runtime := h.factory.all()[1]
			if source == "callback" {
				runtime.callback(errors.New("secret native diagnostic"))
			} else {
				runtime.once.Do(func() { close(runtime.done) })
			}
			h.terminal([]string{offers[0].Attachment})
			if err := h.finish(); err == nil || err.Error() != "terminal" {
				t.Fatal("post-exit attachment failure not terminal", err)
			}
			if h.w.stopped.Load() != 1 {
				t.Fatal("post-exit attachment failure did not stop the workload")
			}
		})
	}
}

// Natural exit does not relax the one-shot command phase machine.
func TestSessionNaturalExitStillRefusesForbiddenCommands(t *testing.T) {
	for _, op := range []string{"start", "offer-keys", "configure"} {
		t.Run(op, func(t *testing.T) {
			h := newSessionHarness(t, 1)
			h.w.completeOnStart, h.w.waitExited = true, make(chan struct{})
			h.configure()
			h.mount("prepare")
			h.prepare()
			h.success("close-phase", Payload{Role: ptr("prepare")})
			h.mount("runtime")
			h.success("start", Payload{})
			<-h.w.waitExited
			var reply *Frame
			switch op {
			case "start":
				reply = h.exchange("start", Payload{})
			case "offer-keys":
				reply = h.exchange("offer-keys", Payload{Role: ptr("runtime")})
			case "configure":
				if err := WriteFrame(h.client, h.config); err != nil {
					t.Fatal(err)
				}
				if _, err := ReadFrame(h.client); err == nil {
					t.Fatal("reconfiguration returned a frame")
				}
			}
			if op != "configure" && (reply.Data.Code == nil || *reply.Data.Code != "phase") {
				t.Fatal("forbidden command admitted after natural exit", op)
			}
			if err := h.finish(); err == nil {
				t.Fatal("forbidden command not terminal", op)
			}
		})
	}
}

func TestSessionRetireQueueBoundAndOwnedIDs(t *testing.T) {
	h := newSessionHarness(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.s.cancel = cancel
	ids := make([]string, 64)
	for i := range ids {
		ids[i] = sessionUUID(t)
	}
	want := append([]string(nil), ids[:32]...)
	for range 10000 {
		h.s.retire(ids...)
	}
	ids[0] = "changed"
	if ctx.Err() == nil || len(h.s.events) != 32 {
		t.Fatal("unbounded retirement queue")
	}
	for range 32 {
		if got := <-h.s.events; !reflect.DeepEqual(got, want) {
			t.Fatal("unbounded or borrowed IDs")
		}
	}
	h.s.retire()
	if len(h.s.events) != 0 {
		t.Fatal("event without IDs")
	}
}

func TestSessionAbortCleanupFailuresAreTerminal(t *testing.T) {
	for _, failure := range []string{"stop", "attachment"} {
		t.Run(failure, func(t *testing.T) {
			h := newSessionHarness(t, 1)
			if failure == "stop" {
				h.w.stopError = errors.New("secret owned stop failure")
			}
			h.configure()
			h.mount("prepare")
			if failure == "attachment" {
				h.factory.all()[0].abortError = errors.New("secret attachment cleanup failure")
			}
			reply := h.exchange("abort", Payload{})
			if reply.Data.Code == nil || *reply.Data.Code != "terminal" || reply.Data.TerminalIDs != nil {
				t.Fatal("false successful abort")
			}
			if err := h.finish(); err == nil || err.Error() != "terminal" {
				t.Fatal("unsanitized shutdown failure", err)
			}
			if h.w.stopped.Load() != 1 || h.factory.all()[0].aborted.Load() != 1 {
				t.Fatal("cleanup not idempotent")
			}
		})
	}
}

func TestSessionShutdownWaitsForConcurrentCleanup(t *testing.T) {
	h := newSessionHarness(t, 0)
	h.w.stopEntered, h.w.stopGate = make(chan struct{}), make(chan struct{})
	h.w.stopError = errors.New("secret stop error")
	results := make(chan error, 2)
	go func() { results <- h.s.shutdown() }()
	<-h.w.stopEntered
	go func() { results <- h.s.shutdown() }()
	select {
	case <-results:
		t.Fatal("shutdown returned before cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	close(h.w.stopGate)
	for range 2 {
		if err := <-results; err == nil || err.Error() != "terminal" {
			t.Fatal("cleanup result lost", err)
		}
	}
	if h.w.stopped.Load() != 1 {
		t.Fatal("duplicate stop")
	}
}

func TestSessionFailedStopStillJoinsOwnedWorkload(t *testing.T) {
	h := newSessionHarness(t, 0)
	h.w.stopError, h.w.stopLeavesRunning = errors.New("secret stuck workload"), true
	h.configure()
	defer h.w.once.Do(func() { close(h.w.done) }) // simulated VM teardown
	h.mount("prepare")
	h.prepare()
	h.success("close-phase", Payload{Role: ptr("prepare")})
	h.mount("runtime")
	h.success("start", Payload{})
	reply := h.exchange("abort", Payload{})
	if reply.Data.Code == nil || *reply.Data.Code != "terminal" {
		t.Fatal("false abort acknowledgement")
	}
	select {
	case <-h.result:
		t.Fatal("abandoned owned workload")
	case <-time.After(20 * time.Millisecond):
	}
	h.w.once.Do(func() { close(h.w.done) })
	if err := h.finish(); err == nil || err.Error() != "terminal" {
		t.Fatal("stop failure lost")
	}
}

func TestSessionEOFWithCleanupFailureIsFixedTerminal(t *testing.T) {
	h := newSessionHarness(t, 0)
	h.w.stopError = errors.New("secret stop failure")
	h.configure()
	_ = h.client.Close()
	if err := h.finish(); err == nil || err.Error() != "terminal" {
		t.Fatal("EOF cleanup failure not sanitized", err)
	}
	if len(h.s.events) != 0 {
		t.Fatal("EOF generated event without IDs")
	}
}

func TestSessionClosePrepareSetsBoundedDeadline(t *testing.T) {
	h := newSessionHarness(t, 1)
	h.configure()
	h.mount("prepare")
	h.prepare()
	a := h.factory.all()[0]
	a.gracefulDeadline = make(chan time.Time, 1)
	h.success("close-phase", Payload{Role: ptr("prepare")})
	if remaining := time.Until(<-a.gracefulDeadline); remaining <= 0 || remaining > sessionIOTimeout {
		t.Fatal("unbounded graceful close")
	}
	// Fake graceful close invokes the native callback; it must not retire.
	h.success("status", Payload{})
	h.success("abort", Payload{})
	if err := h.finish(); err != nil {
		t.Fatal("graceful callback retired session", err)
	}
}

type sessionWriteObserver struct {
	net.Conn
	writes     chan struct{}
	deadlines  chan time.Time
	active     atomic.Int32
	concurrent atomic.Bool
}

func (c *sessionWriteObserver) Write(p []byte) (int, error) {
	if c.active.Add(1) != 1 {
		c.concurrent.Store(true)
	}
	defer c.active.Add(-1)
	c.writes <- struct{}{}
	return c.Conn.Write(p)
}
func (c *sessionWriteObserver) SetWriteDeadline(d time.Time) error {
	c.deadlines <- d
	return c.Conn.SetWriteDeadline(d)
}

func TestSessionTerminalEventSerializesWithReply(t *testing.T) {
	for _, readReply := range []bool{true, false} {
		t.Run(map[bool]string{true: "reader", false: "blocked-writer"}[readReply], func(t *testing.T) {
			h := newSessionHarness(t, 1)
			var observer *sessionWriteObserver
			h.wrap = func(c net.Conn) net.Conn {
				observer = &sessionWriteObserver{Conn: c, writes: make(chan struct{}, 32), deadlines: make(chan time.Time, 32)}
				return observer
			}
			h.configure()
			offers := h.mount("prepare")
			for len(observer.writes) > 0 {
				<-observer.writes
			}
			for len(observer.deadlines) > 0 {
				<-observer.deadlines
			}
			h.seq++
			frame := NewFrame("command", h.config.Binding, *h.config.Scope, Payload{})
			frame.Kind, frame.Sequence = "status", &h.seq
			if err := WriteFrame(h.client, frame); err != nil {
				t.Fatal(err)
			}
			<-observer.writes    // reply now owns writeMu and is blocked in net.Pipe
			<-observer.deadlines // normal 120-second deadline
			h.factory.all()[0].callback(errors.New("secret retirement"))
			deadline := <-observer.deadlines
			if remaining := time.Until(deadline); remaining <= 0 || remaining > 100*time.Millisecond {
				t.Fatal("wrong terminal deadline")
			}
			if readReply {
				reply, err := ReadFrame(h.client)
				if err != nil || reply.Operation != "reply" || reply.Kind != "status" {
					t.Fatal("interleaved reply", err)
				}
				h.terminal([]string{offers[0].Attachment})
			}
			if err := h.finish(); err == nil || err.Error() != "terminal" {
				t.Fatal("retirement did not return fixed terminal", err)
			}
			if observer.concurrent.Load() {
				t.Fatal("concurrent frame writers")
			}
			if err := h.s.write(observer, frame); err == nil {
				t.Fatal("write admitted after failure")
			}
			select {
			case <-observer.deadlines:
				t.Fatal("terminal deadline extended")
			default:
			}
		})
	}
}
