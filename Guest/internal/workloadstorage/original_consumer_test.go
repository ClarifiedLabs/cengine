package workloadstorage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	at "dev.cengine/guest/internal/storageauthoritytest"
	p "dev.cengine/guest/internal/storagepki"
	"dev.cengine/guest/internal/storageserver"
)

func originalTestArm() OriginalConsumerArm {
	const a = "11111111-1111-4111-8111-111111111111"
	const b = "22222222-2222-4222-8222-222222222222"
	return OriginalConsumerArm{Version: 1, Profile: preparecompat.FullProfile, RequestID: a, OperationUUID: b, CaseName: "cross-e-old-leaf-reconnect", Binding: BootBinding{a, b}, Scope: Scope{Intent: a, Store: a, ServiceEpoch: a, ControllerEpoch: 1, ControllerKey: strings.Repeat("a", 64), Container: strings.Repeat("b", 64), ContainerInstance: b, Launch: a, Prepare: b, SpecificationDigest: strings.Repeat("c", 64)}, TargetAttachment: b, LeafSHA256: strings.Repeat("d", 64)}
}
func TestOriginalConsumerClosedContract(t *testing.T) {
	arm := originalTestArm()
	if !arm.valid() {
		t.Fatal("valid arm rejected")
	}
	for _, name := range []string{"same-e-existing-data", "same-e-retained-fd", "same-e-old-leaf-reconnect", "wrong-volume", "wrong-key", "wrong-role", "wrong-mode", "wrong-epoch", "cross-mount-root-grant", "retired-root-grant-replay", "attachment-key-reuse", "delayed-registration", "replayed-takeover", "legacy-connection", "second-service-exclusivity", "normal"} {
		a := arm
		a.CaseName = name
		if a.valid() {
			t.Fatalf("unsupported case %s", name)
		}
	}
	raw, _ := json.Marshal(arm)
	var decoded OriginalConsumerArm
	if originalDecode(raw, &decoded) != nil || decoded != arm {
		t.Fatal("round trip")
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), raw...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version"`), []byte(`"Version"`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1), []byte(`{}`)} {
		if originalDecode(bad, &decoded) == nil {
			t.Fatal("open schema")
		}
	}
	want := preparecompat.FullEnabled() && !preparecompat.Enabled() && !preparecompat.EarlyEnabled()
	if originalConsumerEnabled() != want {
		t.Fatal("nonexclusive build profile")
	}
	s := &Session{factory: &sessionFactoryFake{}}
	if _, err := s.originalConsumerControl("original-consumer-arm", raw); err == nil {
		t.Fatal("ordinary factory armed")
	}
}
func originalIssuer(t *testing.T) p.Issuer {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := p.NewBootstrapPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := p.NewIssuer(time.Now().Add(-time.Minute), time.Hour, boot)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}
func originalIdentities(t *testing.T) (p.Identity, p.Identity, p.Issuer, Scope, Peer) {
	t.Helper()
	arm := originalTestArm()
	old, newIssuer := originalIssuer(t), originalIssuer(t)
	slot := Slot{Volume: arm.TargetAttachment, Attachment: arm.TargetAttachment, Role: "runtime", Mode: "read-write"}
	binding, err := sessionBinding(arm.Scope, slot)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := key.CSR(binding)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := old.IssueAttachment(csr, binding, time.Now().Add(-time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := cert.WithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	current := arm.Scope
	current.ServiceEpoch = arm.TargetAttachment
	current.ControllerEpoch++
	sb, err := p.NewServerBinding(p.StoreID(current.Store), p.ServiceEpoch(current.ServiceEpoch))
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
	sc, err := newIssuer.IssueServer(csr, sb, time.Now().Add(-time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server, err := sc.WithKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := sk.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return identity, server, newIssuer, current, Peer{TLSRootDER: newIssuer.Root().DER(), ServerDER: server.Certificate().DER(), ServerKey: pin.String(), DataAddress: "192.0.2.2"}
}

// Pair the actual DATA Serve observer with the original-owner TLS signer. No
// TLS-config callback, fake principal or alternate server acceptance is used.
func originalDataServer(t *testing.T) (p.Identity, *storageserver.Server, *a.Authority, Scope, Peer) {
	t.Helper()
	identity, _, issuer, scope, _ := originalIdentities(t)
	resources, err := storageserver.NewResources()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	if err = os.Mkdir(filepath.Join(path, "volumes"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	bootstrapKey, bootstrapPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPin, err := a.PublicKeyFingerprint(controllerKey)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := at.New(t, bootstrapPrivate, a.ID(scope.Store), controllerPin).Initialize(a.Config{Root: root, DeviceID: "original-consumer-tls-domain", BootstrapKey: bootstrapKey, Barrier: resources.Barrier})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	meta, err := authority.StartupMetadata()
	if err != nil {
		t.Fatal(err)
	}
	scope.ServiceEpoch = string(meta.Epoch)
	binding, err := p.NewServerBinding(p.StoreID(scope.Store), p.ServiceEpoch(scope.ServiceEpoch))
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.NewServerKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := key.CSR(binding)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := issuer.IssueServer(csr, binding, time.Now().Add(-time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	serverIdentity, err := cert.WithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	server, err := storageserver.NewPKIWithResources(resources, authority, storageserver.PKIConfig{Identity: serverIdentity, ClientRoot: issuer.Root(), Store: meta.Store.ID, ServiceEpoch: meta.Epoch, RequestRetirement: func(a.DataHello, error) { t.Error("unauthenticated retirement") }})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := key.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return identity, server, authority, scope, Peer{TLSRootDER: issuer.Root().DER(), ServerDER: cert.DER(), ServerKey: pin.String(), DataAddress: "192.0.2.2"}
}

type originalReadPrefix struct {
	net.Conn
	bytes    []byte
	fragment int
}

func (c *originalReadPrefix) Read(b []byte) (int, error) {
	if c.fragment > 0 && len(b) > c.fragment {
		b = b[:c.fragment]
	}
	n, err := c.Conn.Read(b)
	c.bytes = append(c.bytes, b[:n]...)
	return n, err
}
func TestOriginalConsumerRealTLSUnknownAuthorityPrefixAndSigner(t *testing.T) {
	for _, fragment := range []int{1, 7, 16384} {
		t.Run(string(rune('a'+fragment%26)), func(t *testing.T) {
			identity, server, authority, scope, peer := originalDataServer(t)
			cfg, witness, err := originalTLSConfig(identity, scope, peer)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			type observed struct {
				err   error
				bytes []byte
			}
			result := make(chan observed, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					result <- observed{err: err}
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				raw := &originalReadPrefix{Conn: conn, fragment: fragment}
				err = server.Serve(storageserver.WithTLSFailureObservation(context.Background()), authority, raw)
				result <- observed{err, bytes.Clone(raw.bytes)}
			}()
			raw, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			capture := &originalCapture{Conn: raw, signer: witness}
			client := tls.Client(capture, cfg)
			if err = client.Handshake(); err != nil {
				t.Fatal("client full handshake", err)
			}
			if !client.ConnectionState().HandshakeComplete || client.ConnectionState().DidResume {
				t.Fatal("not full handshake")
			}
			var one [1]byte
			if n, err := client.Read(one[:]); n != 0 || err == nil {
				t.Fatal("server accepted stale identity")
			}
			got := <-result
			var verification *tls.CertificateVerificationError
			var unknown x509.UnknownAuthorityError
			if !errors.As(got.err, &verification) || !errors.As(got.err, &unknown) || len(verification.UnverifiedCertificates) != 1 || !bytes.Equal(verification.UnverifiedCertificates[0].Raw, identity.Certificate().DER()) {
				t.Fatalf("unattributed rejection %T", got.err)
			}
			if witness.count != 1 || !pin(witness.digest) || capture.afterSign == 0 || capture.overflow {
				t.Fatal("missing original signer/write witness")
			}
			if len(got.bytes) == 0 || len(got.bytes) > len(capture.bytes) || !bytes.Equal(got.bytes, capture.bytes[:len(got.bytes)]) {
				t.Fatal("server read prefix mismatch")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			arm := originalTestArm()
			// Correlating the real TLS prefix must preserve, not overwrite or
			// manufacture, an independently obtained local-operation result.
			// This tests forwarding only; it is not native DATA/FD evidence.
			var operation OriginalOperation
			if fragment == 1 {
				arm.CaseName = "cross-e-existing-data"
				operation = OriginalOperation{Kind: "data-getattr-root", Sequence: 1, ErrorClass: "client-closed-joined"}
			} else if fragment == 7 {
				arm.CaseName = "cross-e-retained-fd"
				operation = OriginalOperation{Kind: "fsync-directory", Sequence: 2, ErrorClass: "enotconn"}
			}
			o := &originalConsumer{arm: arm, ctx: ctx, probed: true, capture: capture, evidence: OriginalConsumerEvidence{Stage: "original-owner-signed-flight", OriginalOperation: operation, LocalError: "tls-alert-or-transport"}}
			serverDigest := sha256.Sum256(append([]byte(storageserver.TLSFailurePrefixDomain), got.bytes...))
			prefix := OriginalConsumerPrefix{Arm: arm, ServerPrefixBytes: uint64(len(got.bytes)), ServerPrefixSHA256: hex.EncodeToString(serverDigest[:])}
			snapshot, hasEvidence := storageserver.TLSFailureEvidence(got.err)
			if hasEvidence != originalConsumerEnabled() {
				t.Fatal("unexpected production evidence availability")
			}
			if hasEvidence {
				if snapshot.Store != a.ID(scope.Store) || snapshot.ServiceEpoch != a.ID(scope.ServiceEpoch) || snapshot.RejectedCertificateSHA256 != sha256.Sum256(identity.Certificate().DER()) || snapshot.ByteCount != uint64(len(got.bytes)) || snapshot.PrefixSHA256 != serverDigest {
					t.Fatal("incorrect actual DATA Server.Serve evidence")
				}
				// Query the owner using the production server's receipt, not
				// a hash synthesized by this client-side test fixture.
				prefix.ServerPrefixBytes = snapshot.ByteCount
				prefix.ServerPrefixSHA256 = hex.EncodeToString(snapshot.PrefixSHA256[:])
			}
			evidence, err := o.prefix(prefix)
			if err != nil || evidence.ClientPrefixSHA256 != prefix.ServerPrefixSHA256 || evidence.OriginalOperation != operation || evidence.LocalError != "tls-alert-or-transport" {
				t.Fatal("prefix query", err)
			}
			if _, err := o.prefix(prefix); err == nil {
				t.Fatal("repeated query")
			}
			capture.clear()
		})
	}
}
func TestOriginalConsumerExactServerAndNoSignerOnMismatch(t *testing.T) {
	identity, _, _, scope, peer := originalIdentities(t)
	peer.ServerDER = []byte("wrong exact DER")
	cfg, witness, err := originalTLSConfig(identity, scope, peer)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyConnection(tls.ConnectionState{}) == nil || witness.count != 0 {
		t.Fatal("unverified server")
	}
	cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{AcceptableCAs: [][]byte{[]byte("other CA")}})
	if err != nil || !bytes.Equal(cert.Certificate[0], identity.Certificate().DER()) || cfg.ClientSessionCache != nil || !cfg.SessionTicketsDisabled {
		t.Fatal("old leaf not forced/no resume")
	}
}
func TestOriginalConsumerStopClosesSocketAndJoinsBeforeFDRelease(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "retained")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	o := &originalConsumer{file: file, conn: left, ctx: ctx, cancel: cancel, done: done}
	joined := make(chan struct{})
	go func() { o.stop(); close(joined) }()
	<-ctx.Done()
	select {
	case <-joined:
		t.Fatal("release skipped join")
	default:
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("released FD before join")
	}
	b := []byte{0}
	if _, err := right.Read(b); err == nil {
		t.Fatal("socket not closed")
	}
	close(done)
	<-joined
	if _, err := file.Stat(); err == nil {
		t.Fatal("FD not released")
	}
	o.stop()
}
func TestOriginalConsumerExpiryUsesFixedBudgetAndJoins(t *testing.T) {
	if originalConsumerBudget != 10*time.Second {
		t.Fatal("changed budget")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	o := &originalConsumer{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	o.timer = time.AfterFunc(20*time.Millisecond, func() { _ = o.stop() })
	<-ctx.Done()
	close(o.done)
	o.stop()
	if !o.stopped {
		t.Fatal("not stopped")
	}
}
func TestOriginalConsumerConcurrentStopAndCaptureOverflow(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &originalCapture{Conn: left, signer: &originalSigner{count: 1}}
	joined := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, right); close(joined) }()
	if _, err := c.Write(make([]byte, originalCiphertextLimit+1)); err != nil {
		t.Fatal(err)
	}
	if !c.overflow || len(c.bytes) > originalCiphertextLimit {
		t.Fatal("unbounded private capture")
	}
	o := &originalConsumer{conn: left, capture: c}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); o.stop() }()
	}
	wg.Wait()
	<-joined
	if c.bytes != nil {
		t.Fatal("ciphertext retained after release")
	}
}
func TestOriginalConsumerTrustRejectsAddressAndUnrelatedScope(t *testing.T) {
	_, _, _, scope, peer := originalIdentities(t)
	arm := originalTestArm()
	o := &originalConsumer{arm: arm, peer: peer}
	q := OriginalConsumerProbe{Arm: arm, Scope: scope, Peer: peer}
	if !o.validTrust(q) {
		t.Fatal("current adopted scope")
	}
	q.Peer.DataAddress = "192.0.2.3"
	if o.validTrust(q) {
		t.Fatal("alternate address")
	}
	q.Peer = peer
	q.Scope.ContainerInstance = arm.Scope.Store
	if o.validTrust(q) {
		t.Fatal("alternate owner")
	}
}

// This private fake exercises installed-session provenance only; it is never a
// native mount positive and is unreachable from the production constructor.
type originalFactoryFake struct {
	sessionFactoryFake
	observer *originalConsumer
	file     *os.File
}

func (f *originalFactoryFake) originalConsumerObserver() *originalConsumer { return f.observer }
func (f *originalFactoryFake) openOriginalMount(Attachment) (*os.File, string, error) {
	return f.file, strings.Repeat("e", 64), nil
}
func originalInstalledSession(t *testing.T) (*Session, OriginalConsumerArm, *originalFactoryFake) {
	t.Helper()
	arm := originalTestArm()
	issuer := originalIssuer(t)
	slot := Slot{Volume: arm.TargetAttachment, Attachment: arm.TargetAttachment, Role: "runtime", Mode: "read-write"}
	binding, err := sessionBinding(arm.Scope, slot)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := key.CSR(binding)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := issuer.IssueAttachment(csr, binding, time.Now().Add(-time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := cert.WithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	arm.LeafSHA256 = SpecificationDigest(cert.DER())
	file, err := os.CreateTemp(t.TempDir(), "control-only")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	f := &originalFactoryFake{observer: &originalConsumer{}, file: file}
	s := &Session{binding: arm.Binding, scope: arm.Scope, root: issuer.Root(), phase: "running", activeRole: "runtime", factory: f, entries: map[string]*sessionAttachment{slot.Attachment: {slot: slot, binding: binding, key: key, identity: identity, installed: true, mounted: true, attachment: &sessionAttachmentFake{done: make(chan struct{})}}}}
	t.Cleanup(func() { _ = f.observer.stop() })
	return s, arm, f
}
func TestOriginalConsumerArmChecksInstalledRunningRuntimeAndLeaf(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile only")
	}
	for _, name := range []string{"phase", "role", "leaf", "scope", "boot", "stopped", "unmounted", "uninstalled", "key", "valid"} {
		t.Run(name, func(t *testing.T) {
			s, arm, f := originalInstalledSession(t)
			entry := s.entries[arm.TargetAttachment]
			switch name {
			case "phase":
				s.phase = "runtime-mounted"
			case "role":
				entry.slot.Role = "prepare"
			case "leaf":
				arm.LeafSHA256 = strings.Repeat("f", 64)
			case "scope":
				arm.Scope.ControllerEpoch++
			case "boot":
				arm.Binding.GuestBootNonce = arm.Binding.ShimLaunchUUID
			case "stopped":
				s.stopped = true
			case "unmounted":
				entry.mounted = false
			case "uninstalled":
				entry.installed = false
			case "key":
				var err error
				entry.key, err = p.NewAttachmentKey(p.RuntimeRole)
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(arm)
			payload, err := s.originalConsumerControl("original-consumer-arm", raw)
			if name != "valid" {
				if err == nil {
					t.Fatal("bad installed provenance accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var evidence OriginalConsumerEvidence
			if json.Unmarshal(payload, &evidence) != nil || evidence.Stage != "armed-mounted-positive" || f.observer.file != f.file || f.observer.identity.Certificate().DER() == nil {
				t.Fatal("original state not retained")
			}
			if _, err = s.originalConsumerControl("original-consumer-begin", raw); err != nil {
				t.Fatal(err)
			}
			deadline, _ := f.observer.ctx.Deadline()
			if remaining := time.Until(deadline); remaining <= 9*time.Second || remaining > originalConsumerBudget {
				t.Fatal("budget not owner-fixed")
			}
			// Normal Session terminal key clearing does not replace the old owner.
			entry.key, entry.identity = p.Key{}, p.Identity{}
			if SpecificationDigest(f.observer.identity.Certificate().DER()) != arm.LeafSHA256 {
				t.Fatal("identity did not survive original session cleanup")
			}
			if _, err = s.originalConsumerControl("original-consumer-release", raw); err != nil {
				t.Fatal(err)
			}
			if _, err = f.file.Stat(); err == nil {
				t.Fatal("release failed to close original FD")
			}
			if _, err = s.originalConsumerControl("original-consumer-begin", raw); err == nil {
				t.Fatal("released observer reused")
			}
		})
	}
}
func TestOriginalConsumerBeginRefusesAlreadyRetiredOwner(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile only")
	}
	s, arm, f := originalInstalledSession(t)
	raw, _ := json.Marshal(arm)
	if _, err := s.originalConsumerControl("original-consumer-arm", raw); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	if _, err := s.originalConsumerControl("original-consumer-begin", raw); err == nil {
		t.Fatal("retired owner began lease")
	}
	if !f.observer.stopped || f.observer.file != nil {
		t.Fatal("failed begin retained resources")
	}
}

func TestOriginalConsumerBadPrefixAndMalformedRequestConsumeArm(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile only")
	}
	s, arm, f := originalInstalledSession(t)
	raw, _ := json.Marshal(arm)
	if _, err := s.originalConsumerControl("original-consumer-arm", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.originalConsumerControl("original-consumer-probe", []byte(`{}`)); err == nil {
		t.Fatal("malformed probe")
	}
	if !f.observer.stopped || f.observer.file != nil {
		t.Fatal("malformed observation failed to release")
	}
}

func TestOriginalConsumerPrefixRejectsWrongCountHashAndEOFOnly(t *testing.T) {
	for _, name := range []string{"zero", "too-long", "wrong-hash", "unseparated-hash", "eof-only", "overflow"} {
		t.Run(name, func(t *testing.T) {
			arm := originalTestArm()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c := &originalCapture{bytes: []byte("private transcript")}
			o := &originalConsumer{arm: arm, ctx: ctx, probed: true, capture: c, evidence: OriginalConsumerEvidence{Stage: "original-owner-signed-flight"}}
			digest := sha256.Sum256(append([]byte(storageserver.TLSFailurePrefixDomain), c.bytes[:3]...))
			q := OriginalConsumerPrefix{Arm: arm, ServerPrefixBytes: 3, ServerPrefixSHA256: hex.EncodeToString(digest[:])}
			switch name {
			case "zero":
				q.ServerPrefixBytes = 0
			case "too-long":
				q.ServerPrefixBytes = originalCiphertextLimit + 1
			case "wrong-hash":
				q.ServerPrefixSHA256 = strings.Repeat("f", 64)
			case "unseparated-hash":
				q.ServerPrefixSHA256 = SpecificationDigest(c.bytes[:3])
			case "eof-only":
				o.evidence.Stage = "eof"
			case "overflow":
				c.overflow = true
			}
			if _, err := o.prefix(q); err == nil {
				t.Fatal("invalid correlation accepted")
			}
		})
	}
}
